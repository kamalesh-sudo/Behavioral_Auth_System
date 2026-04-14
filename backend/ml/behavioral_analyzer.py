import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
from collections import defaultdict

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    TENSORFLOW_AVAILABLE = True
except Exception:  # pylint: disable=broad-except
    tf = None
    Sequential = None
    LSTM = None
    Dense = None
    Dropout = None
    TENSORFLOW_AVAILABLE = False

try:
    from ml.feature_extractor import BehavioralFeatureExtractor
except ImportError:
    from backend.ml.feature_extractor import BehavioralFeatureExtractor

class BehavioralAnalyzer:
    def __init__(self):
        self.feature_extractor = BehavioralFeatureExtractor()
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.lstm_model = None
        self.user_profiles = {}
        self.is_trained = False
        self.model_dir = Path(__file__).resolve().parents[1] / "models"
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.user_feature_history = defaultdict(list)
        self.user_risk_ema = {}
        # Presentation-tuned defaults for quicker confidence buildup.
        self.min_keystroke_events = 3
        self.min_mouse_events = 3
        self.min_eye_events = 3
        self.min_total_events = 6
        self.min_interaction_window_ms = 600
        self.profile_train_min_samples = 6
        self.profile_history_max = 80
        self.drift_window_size = 6
        self.cross_user_min_samples = 6
        self.identity_margin_target = 1.0
        self.user_context_history = defaultdict(lambda: defaultdict(int))
        self.last_explanations = {}
        self.last_debug_io = {}
        self.profile_update_risk_threshold = 0.45
        self.critical_risk_passthrough = 0.55
        self.pending_behavior_windows = defaultdict(lambda: {"keystrokeData": [], "mouseData": [], "eyeData": []})
        self.pending_behavior_max_events = 240
        self.pending_behavior_window_ms = 5000
    
    def create_user_profile(self, user_id, behavioral_data):
        """Create initial user profile from behavioral data"""
        features = self.extract_features(behavioral_data)
        if not self._has_signal(behavioral_data):
            return features
        
        # Store user profile
        self.user_profiles[user_id] = {
            'features': features,
            'training_data': behavioral_data,
            'model': IsolationForest(contamination=0.1, random_state=42),
            'is_model_trained': False,
            'feature_keys': sorted(features.keys()),
        }
        self.user_feature_history[user_id].append(features)
        self._refresh_user_profile_model(user_id)
        
        return features
    
    def extract_features(self, behavioral_data):
        """Extract features from behavioral data"""
        keystroke_data = behavioral_data.get('keystrokeData', [])
        mouse_data = behavioral_data.get('mouseData', [])
        eye_data = behavioral_data.get('eyeData', [])
        
        keystroke_features = self.feature_extractor.extract_keystroke_features(keystroke_data)
        mouse_features = self.feature_extractor.extract_mouse_features(mouse_data)
        eye_features = self.feature_extractor.extract_eye_features(eye_data)
        
        # Combine features
        combined_features = {**keystroke_features, **mouse_features, **eye_features}
        
        return combined_features
    
    def prepare_feature_matrix(self, feature_list):
        """Convert feature dictionaries to numpy matrix"""
        if not feature_list:
            return np.array([])
        
        # Get all possible feature names
        all_features = set()
        for features in feature_list:
            all_features.update(features.keys())
        
        # Create feature matrix
        feature_matrix = []
        for features in feature_list:
            feature_vector = []
            for feature_name in sorted(all_features):
                feature_vector.append(features.get(feature_name, 0))
            feature_matrix.append(feature_vector)
        
        return np.array(feature_matrix)
    
    def train_global_model(self, training_data):
        """Train global model with multiple users' data"""
        all_features = []
        all_labels = []
        
        for user_data in training_data:
            features = self.extract_features(user_data['behavioral_data'])
            all_features.append(features)
            all_labels.append(user_data['user_id'])
        
        # Prepare feature matrix
        feature_matrix = self.prepare_feature_matrix(all_features)
        
        # Scale features
        feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)
        
        # Train classifier
        self.classifier.fit(feature_matrix_scaled, all_labels)
        
        # Train LSTM for temporal analysis
        self.train_lstm_model(training_data)
        
        self.is_trained = True
        
        # Save models
        self.save_models()
    
    def train_lstm_model(self, training_data):
        """Train LSTM model for temporal behavioral analysis"""
        if not TENSORFLOW_AVAILABLE:
            print("TensorFlow not available; skipping LSTM training.")
            return

        sequences = []
        labels = []
        
        for user_data in training_data:
            # Create sequences of behavioral features
            behavioral_data = user_data['behavioral_data']
            user_id = user_data['user_id']
            
            # Extract features in time windows
            time_windows = self.create_time_windows(behavioral_data)
            
            for window in time_windows:
                features = self.extract_features(window)
                feature_vector = list(features.values())
                sequences.append(feature_vector)
                labels.append(user_id)
        
        if not sequences:
            return
        
        # Convert to numpy arrays
        X = np.array(sequences)
        y = np.array(labels)
        
        # Reshape for LSTM (samples, time_steps, features)
        X = X.reshape((X.shape[0], 1, X.shape[1]))
        
        # Build LSTM model
        self.lstm_model = Sequential([
            LSTM(50, return_sequences=True, input_shape=(1, X.shape[2])),
            Dropout(0.2),
            LSTM(50, return_sequences=False),
            Dropout(0.2),
            Dense(25, activation='relu'),
            Dense(len(set(labels)), activation='softmax')
        ])
        
        self.lstm_model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
        
        # Convert labels to numeric
        unique_labels = list(set(labels))
        y_numeric = np.array([unique_labels.index(label) for label in y])
        
        # Train model
        self.lstm_model.fit(X, y_numeric, epochs=20, batch_size=32, verbose=1)
    
    def create_time_windows(self, behavioral_data, window_size=5000):
        """Create time windows from behavioral data"""
        keystroke_data = behavioral_data.get('keystrokeData', [])
        mouse_data = behavioral_data.get('mouseData', [])
        eye_data = behavioral_data.get('eyeData', [])
        
        # Combine and sort by timestamp
        all_events = []
        for event in keystroke_data:
            all_events.append(('keystroke', event))
        for event in mouse_data:
            all_events.append(('mouse', event))
        for event in eye_data:
            all_events.append(('eye', event))
        
        all_events.sort(key=lambda x: x[1].get('timestamp', 0))
        
        # Create windows
        windows = []
        current_window = {'keystrokeData': [], 'mouseData': [], 'eyeData': []}
        
        for event_type, event in all_events:
            if event_type == 'keystroke':
                current_window['keystrokeData'].append(event)
            elif event_type == 'mouse':
                current_window['mouseData'].append(event)
            else:
                current_window['eyeData'].append(event)
            
            # Check if window is full
            total_events = len(current_window['keystrokeData']) + len(current_window['mouseData']) + len(current_window['eyeData'])
            if total_events >= window_size:
                windows.append(current_window)
                current_window = {'keystrokeData': [], 'mouseData': [], 'eyeData': []}
        
        # Add final window if not empty
        if current_window['keystrokeData'] or current_window['mouseData'] or current_window['eyeData']:
            windows.append(current_window)
        
        return windows
    
    def analyze_real_time(self, keystroke_data, mouse_data, eye_data=None, user_id=None, context=None):
        """Analyze behavioral data in real-time"""
        incoming_behavioral_data = {
            'keystrokeData': keystroke_data,
            'mouseData': mouse_data,
            'eyeData': eye_data or []
        }
        behavioral_data = incoming_behavioral_data
        if user_id:
            behavioral_data = self._merge_pending_behavior(user_id, behavioral_data)

        if not self._has_signal(behavioral_data):
            if user_id:
                self.last_explanations[user_id] = {
                    "reason": "insufficient_signal",
                    "components": {"fallback": 0.05},
                    "top_deviations": [],
                }
                self._store_debug_io(
                    user_id=user_id,
                    incoming_behavioral_data=incoming_behavioral_data,
                    analyzed_behavioral_data=behavioral_data,
                    features=None,
                    risk=0.05,
                    explanation=self.last_explanations[user_id],
                )
            return self._smoothed_risk(user_id, 0.05)
        
        features = self.extract_features(behavioral_data)
        if user_id:
            self._clear_pending_behavior(user_id)
        
        if not features:
            if user_id:
                self.last_explanations[user_id] = {
                    "reason": "empty_features",
                    "components": {"fallback": 0.05},
                    "top_deviations": [],
                }
                self._store_debug_io(
                    user_id=user_id,
                    incoming_behavioral_data=incoming_behavioral_data,
                    analyzed_behavioral_data=behavioral_data,
                    features=None,
                    risk=0.05,
                    explanation=self.last_explanations[user_id],
                )
            return self._smoothed_risk(user_id, 0.05)
        
        # If user-specific model exists, use it
        if user_id and user_id in self.user_profiles:
            risk, explanation = self.analyze_with_user_model(features, user_id, context=context)
            if self._should_update_profile(user_id, risk, explanation):
                self._append_user_history(user_id, features)
                self._update_context_history(user_id, context)
                explanation["profile_updated"] = True
            else:
                explanation["profile_updated"] = False
            self.last_explanations[user_id] = explanation
            self._store_debug_io(
                user_id=user_id,
                incoming_behavioral_data=incoming_behavioral_data,
                analyzed_behavioral_data=behavioral_data,
                features=features,
                risk=risk,
                explanation=explanation,
            )
            return self._smoothed_risk(user_id, risk)
        
        # Otherwise, use global model
        risk = self.analyze_with_global_model(features)
        if user_id:
            self._append_user_history(user_id, features)
            self._update_context_history(user_id, context)
            if user_id not in self.user_profiles:
                self.create_user_profile(user_id, behavioral_data)
            self.last_explanations[user_id] = {
                "reason": "global_model",
                "components": {"global": float(risk), "context": float(self._context_novelty_risk(user_id, context))},
                "top_deviations": [],
            }
            self._store_debug_io(
                user_id=user_id,
                incoming_behavioral_data=incoming_behavioral_data,
                analyzed_behavioral_data=behavioral_data,
                features=features,
                risk=risk,
                explanation=self.last_explanations[user_id],
            )
        return self._smoothed_risk(user_id, risk)
    
    def analyze_with_user_model(self, features, user_id, context=None):
        """Analyze using user-specific model"""
        user_profile = self.user_profiles[user_id]
        keys = user_profile.get("feature_keys") or sorted(features.keys())
        feature_vector = np.array([[features.get(k, 0.0) for k in keys]], dtype=float)

        model_risk = 0.5
        if user_profile.get("is_model_trained"):
            try:
                anomaly_score = user_profile['model'].decision_function(feature_vector)[0]
                model_risk = float(np.clip((0.5 - anomaly_score) / 1.2, 0.0, 1.0))
            except Exception:  # pylint: disable=broad-except
                model_risk = 0.5

        distance_risk, top_deviations = self._profile_distance_risk(user_id, features, keys)
        drift_risk = self._temporal_drift_risk(user_id, features, keys)
        profile_z_spike_risk, profile_z_spikes = self._profile_specific_spike_risk(user_id, features)
        context_risk = self._context_novelty_risk(user_id, context)
        global_risk = self.analyze_with_global_model(features)
        impostor_risk, impostor_hint = self._cross_user_impostor_risk(user_id, features, keys)
        separation_risk = self._identity_separation_risk(user_id, features, keys)
        combined = (
            (0.35 * model_risk)
            + (0.35 * distance_risk)
            + (0.08 * drift_risk)
            + (0.04 * global_risk)
            + (0.03 * context_risk)
            + (0.05 * impostor_risk)
            + (0.03 * separation_risk)
            + (0.07 * profile_z_spike_risk)
        )
        explanation = {
            "reason": "user_model",
            "components": {
                "model": float(model_risk),
                "distance": float(distance_risk),
                "drift": float(drift_risk),
                "global": float(global_risk),
                "context": float(context_risk),
                "impostor": float(impostor_risk),
                "separation": float(separation_risk),
                "profile_z_spike": float(profile_z_spike_risk),
            },
            "top_deviations": top_deviations,
        }
        if profile_z_spikes:
            explanation["profile_z_spikes"] = profile_z_spikes
        if impostor_hint:
            explanation["impostor_hint"] = impostor_hint
        return float(np.clip(combined, 0.0, 1.0)), explanation
    
    def analyze_with_global_model(self, features):
        """Analyze using global model"""
        if not self.is_trained:
            # Cold-start fallback: conservative non-zero uncertainty.
            return 0.25
        
        feature_matrix = self.prepare_feature_matrix([features])
        try:
            if hasattr(self.scaler, "n_features_in_") and feature_matrix.shape[1] != int(self.scaler.n_features_in_):
                return 0.35
            feature_matrix_scaled = self.scaler.transform(feature_matrix)
            probabilities = self.classifier.predict_proba(feature_matrix_scaled)[0]
            max_probability = np.max(probabilities)
            risk_score = 1.0 - max_probability
            return float(np.clip(risk_score, 0.0, 1.0))
        except Exception:  # pylint: disable=broad-except
            return 0.35
    
    def update_user_profile(self, user_id, behavioral_data, feedback=None):
        """Update user profile with new behavioral data"""
        if not self._has_signal(behavioral_data):
            return
        if user_id not in self.user_profiles:
            self.create_user_profile(user_id, behavioral_data)
            return
        
        new_features = self.extract_features(behavioral_data)
        
        # Update user profile
        self.user_profiles[user_id]['features'] = new_features
        self.user_profiles[user_id]['training_data'] = behavioral_data
        self._append_user_history(user_id, new_features)
    
    def save_models(self):
        """Save trained models to disk"""
        joblib.dump(self.scaler, self.model_dir / "scaler.pkl")
        joblib.dump(self.classifier, self.model_dir / "classifier.pkl")
        joblib.dump(self.anomaly_detector, self.model_dir / "anomaly_detector.pkl")
        
        if self.lstm_model and TENSORFLOW_AVAILABLE:
            self.lstm_model.save(self.model_dir / "lstm_model.h5")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            self.scaler = joblib.load(self.model_dir / "scaler.pkl")
            self.classifier = joblib.load(self.model_dir / "classifier.pkl")
            self.anomaly_detector = joblib.load(self.model_dir / "anomaly_detector.pkl")
            
            if TENSORFLOW_AVAILABLE:
                try:
                    self.lstm_model = tf.keras.models.load_model(self.model_dir / "lstm_model.h5")
                except Exception:  # pylint: disable=broad-except
                    print("LSTM model not found")
            else:
                self.lstm_model = None
            
            self.is_trained = True
            return True
        except Exception:  # pylint: disable=broad-except
            print("Models not found, please train first")
            return False

    def _has_signal(self, behavioral_data: dict) -> bool:
        keystrokes = behavioral_data.get("keystrokeData", []) or []
        mouse = behavioral_data.get("mouseData", []) or []
        eye = behavioral_data.get("eyeData", []) or []
        enough_events = (
            len(keystrokes) >= self.min_keystroke_events
            or len(mouse) >= self.min_mouse_events
            or len(eye) >= self.min_eye_events
            or (len(keystrokes) + len(mouse) + len(eye)) >= self.min_total_events
        )
        if not enough_events:
            return False
        return self._interaction_window_ms(keystrokes, mouse, eye) >= self.min_interaction_window_ms

    @staticmethod
    def _interaction_window_ms(keystrokes: list[dict], mouse: list[dict], eye: list[dict] = None) -> float:
        timestamps = []
        for event in keystrokes:
            ts = event.get("timestamp")
            if ts is not None:
                timestamps.append(float(ts))
        for event in mouse:
            ts = event.get("timestamp")
            if ts is not None:
                timestamps.append(float(ts))
        for event in (eye or []):
            ts = event.get("timestamp")
            if ts is not None:
                timestamps.append(float(ts))
        if len(timestamps) < 2:
            return 0.0
        return max(timestamps) - min(timestamps)

    @staticmethod
    def _max_timestamp(events: list[dict]) -> float | None:
        timestamps = [float(event.get("timestamp")) for event in events if event.get("timestamp") is not None]
        if not timestamps:
            return None
        return max(timestamps)

    def _trim_behavior_events(self, events: list[dict]) -> list[dict]:
        if not events:
            return []
        ordered = [event for event in events if event.get("timestamp") is not None]
        if not ordered:
            return []
        ordered.sort(key=lambda event: float(event.get("timestamp", 0)))
        latest_ts = float(ordered[-1].get("timestamp", 0))
        min_ts = latest_ts - float(self.pending_behavior_window_ms)
        trimmed = [event for event in ordered if float(event.get("timestamp", 0)) >= min_ts]
        if len(trimmed) > int(self.pending_behavior_max_events):
            trimmed = trimmed[-int(self.pending_behavior_max_events):]
        return trimmed

    def _merge_pending_behavior(self, user_id: str, behavioral_data: dict) -> dict:
        pending = self.pending_behavior_windows[user_id]
        pending_keystrokes = pending.get("keystrokeData", []) or []
        pending_mouse = pending.get("mouseData", []) or []
        pending_eye = pending.get("eyeData", []) or []
        incoming_keystrokes = behavioral_data.get("keystrokeData", []) or []
        incoming_mouse = behavioral_data.get("mouseData", []) or []
        incoming_eye = behavioral_data.get("eyeData", []) or []

        pending_latest = self._max_timestamp(pending_keystrokes + pending_mouse + pending_eye)
        incoming_latest = self._max_timestamp(incoming_keystrokes + incoming_mouse + incoming_eye)
        if (
            pending_latest is not None
            and incoming_latest is not None
            and (incoming_latest + 250.0) < pending_latest
        ):
            # Frontend timestamp counters can restart on a new page/session.
            pending_keystrokes = []
            pending_mouse = []
            pending_eye = []

        merged_keystrokes = self._trim_behavior_events(pending_keystrokes + incoming_keystrokes)
        merged_mouse = self._trim_behavior_events(pending_mouse + incoming_mouse)
        merged_eye = self._trim_behavior_events(pending_eye + incoming_eye)
        merged = {"keystrokeData": merged_keystrokes, "mouseData": merged_mouse, "eyeData": merged_eye}
        self.pending_behavior_windows[user_id] = merged
        return merged

    def _clear_pending_behavior(self, user_id: str) -> None:
        self.pending_behavior_windows[user_id] = {"keystrokeData": [], "mouseData": [], "eyeData": []}

    def _append_user_history(self, user_id: str, features: dict) -> None:
        history = self.user_feature_history[user_id]
        history.append(features)
        if len(history) > self.profile_history_max:
            del history[0 : len(history) - self.profile_history_max]
        self._refresh_user_profile_model(user_id)

    def _refresh_user_profile_model(self, user_id: str) -> None:
        profile = self.user_profiles.get(user_id)
        history = self.user_feature_history[user_id]
        if not profile or not history:
            return
        keys = profile.get("feature_keys") or sorted(history[-1].keys())
        profile["feature_keys"] = keys
        if len(history) < self.profile_train_min_samples:
            profile["is_model_trained"] = False
            return
        matrix = np.array([[sample.get(k, 0.0) for k in keys] for sample in history], dtype=float)
        try:
            profile["model"].fit(matrix)
            profile["is_model_trained"] = True
        except Exception:  # pylint: disable=broad-except
            profile["is_model_trained"] = False

    def _profile_distance_risk(self, user_id: str, features: dict, keys: list[str]) -> tuple[float, list[dict]]:
        history = self.user_feature_history[user_id]
        if len(history) < 3:
            return 0.35, []
        matrix = np.array([[sample.get(k, 0.0) for k in keys] for sample in history], dtype=float)
        baseline_mean = np.mean(matrix, axis=0)
        baseline_std = np.std(matrix, axis=0) + 1e-6
        current = np.array([features.get(k, 0.0) for k in keys], dtype=float)
        z = np.abs((current - baseline_mean) / baseline_std)
        # Robust aggregated shift from normal behavior.
        z_score = self._aggregate_shift(z)
        top_idx = np.argsort(z)[-5:][::-1]
        top_deviations = [
            {"feature": keys[int(i)], "z_score": float(z[int(i)]), "value": float(current[int(i)]), "baseline": float(baseline_mean[int(i)])}
            for i in top_idx
        ]
        return float(np.clip(z_score / 4.0, 0.0, 1.0)), top_deviations

    def _temporal_drift_risk(self, user_id: str, features: dict, keys: list[str]) -> float:
        history = self.user_feature_history[user_id]
        window = int(self.drift_window_size)
        if len(history) < max(2 * window, 6):
            return 0.2
        recent = history[-window:]
        previous = history[-(2 * window) : -window]
        recent_matrix = np.array([[sample.get(k, 0.0) for k in keys] for sample in recent], dtype=float)
        previous_matrix = np.array([[sample.get(k, 0.0) for k in keys] for sample in previous], dtype=float)
        recent_mean = np.mean(recent_matrix, axis=0)
        previous_mean = np.mean(previous_matrix, axis=0)
        reference_std = np.std(previous_matrix, axis=0) + 1e-6
        drift_z = np.abs((recent_mean - previous_mean) / reference_std)
        return float(np.clip(self._aggregate_shift(drift_z) / 4.0, 0.0, 1.0))

    def _profile_specific_spike_risk(self, user_id: str, features: dict) -> tuple[float, list[dict]]:
        """
        Profile-specific normalization gate:
        flag risk when jerk or dwell variability features are >2σ from user's own baseline.
        """
        history = self.user_feature_history[user_id]
        if len(history) < max(5, int(self.profile_train_min_samples)):
            return 0.0, []

        monitored_features = ("jerk_mean", "jerk_p95", "dwell_variance", "dwell_std")
        spikes = []
        severity = 0.0
        for feature_name in monitored_features:
            historical_values = []
            for sample in history:
                value = sample.get(feature_name)
                if value is None:
                    continue
                value = float(value)
                if np.isfinite(value):
                    historical_values.append(value)
            if len(historical_values) < 3:
                continue

            baseline_mean = float(np.mean(historical_values))
            baseline_std = float(np.std(historical_values))
            if baseline_std < 1e-6:
                continue

            current_value = float(features.get(feature_name, 0.0))
            if not np.isfinite(current_value):
                continue
            z_score = float(abs((current_value - baseline_mean) / baseline_std))
            if z_score > 2.0:
                spikes.append(
                    {
                        "feature": feature_name,
                        "z_score": z_score,
                        "value": current_value,
                        "baseline_mean": baseline_mean,
                        "baseline_std": baseline_std,
                    }
                )
                severity = max(severity, float(np.clip((z_score - 2.0) / 2.0, 0.0, 1.0)))

        return severity, spikes

    @staticmethod
    def _distance_to_profile(features: dict, keys: list[str], history: list[dict]) -> float:
        if len(history) < 3:
            return 3.0
        matrix = np.array([[sample.get(k, 0.0) for k in keys] for sample in history], dtype=float)
        baseline_mean = np.mean(matrix, axis=0)
        baseline_std = np.std(matrix, axis=0) + 1e-6
        current = np.array([features.get(k, 0.0) for k in keys], dtype=float)
        z = np.abs((current - baseline_mean) / baseline_std)
        return float(BehavioralAnalyzer._aggregate_shift(z))

    @staticmethod
    def _aggregate_shift(z_values: np.ndarray) -> float:
        """Aggregate per-feature z-shifts without losing sparse but important deviations."""
        if z_values.size == 0:
            return 0.0
        z = np.asarray(z_values, dtype=float)
        z = z[np.isfinite(z)]
        if z.size == 0:
            return 0.0
        capped = np.clip(z, 0.0, 12.0)
        p50 = float(np.percentile(capped, 50))
        p75 = float(np.percentile(capped, 75))
        top_k = max(1, int(np.ceil(capped.size * 0.10)))
        tail = float(np.mean(np.partition(capped, -top_k)[-top_k:]))
        active_ratio = float(np.mean(capped > 1.0))
        ratio_term = 4.0 * active_ratio
        return float((0.35 * p50) + (0.30 * p75) + (0.25 * tail) + (0.10 * ratio_term))

    def _cross_user_impostor_risk(self, user_id: str, features: dict, keys: list[str]) -> tuple[float, dict]:
        own_history = self.user_feature_history[user_id]
        if len(own_history) < self.cross_user_min_samples:
            return 0.0, {}

        own_distance = self._distance_to_profile(features, keys, own_history)
        best_other = None
        for other_user_id, other_history in self.user_feature_history.items():
            if other_user_id == user_id or len(other_history) < self.cross_user_min_samples:
                continue
            other_distance = self._distance_to_profile(features, keys, other_history)
            if best_other is None or other_distance < best_other["distance"]:
                best_other = {"user_id": other_user_id, "distance": other_distance}

        if not best_other:
            return 0.0, {}

        distance_gap = own_distance - best_other["distance"]
        ratio = own_distance / max(1e-6, best_other["distance"])
        # Positive gap means claimed user looks less like self than another known user.
        gap_component = np.clip(distance_gap / 1.8, 0.0, 1.0)
        ratio_component = np.clip((ratio - 1.0) / 0.8, 0.0, 1.0)
        impostor_risk = float(np.clip((0.70 * gap_component) + (0.30 * ratio_component), 0.0, 1.0))
        hint = {
            "closest_other_user": best_other["user_id"],
            "claimed_user_distance": float(own_distance),
            "closest_other_distance": float(best_other["distance"]),
            "distance_gap": float(distance_gap),
            "distance_ratio": float(ratio),
        }
        return impostor_risk, hint

    def _identity_separation_risk(self, user_id: str, features: dict, keys: list[str]) -> float:
        own_history = self.user_feature_history[user_id]
        if len(own_history) < self.cross_user_min_samples:
            return 0.3

        own_distance = self._distance_to_profile(features, keys, own_history)
        other_distances = [
            self._distance_to_profile(features, keys, history)
            for other_id, history in self.user_feature_history.items()
            if other_id != user_id and len(history) >= self.cross_user_min_samples
        ]
        if not other_distances:
            return 0.25
        nearest_other = min(other_distances)
        margin = nearest_other - own_distance
        # If margin is low/negative, sample is insufficiently separated from other users.
        return float(np.clip((self.identity_margin_target - margin) / (self.identity_margin_target + 1.0), 0.0, 1.0))

    def _context_novelty_risk(self, user_id: str, context: dict | None) -> float:
        if not context:
            return 0.0
        risk_values = []
        for key in ("device_class", "session_type"):
            value = context.get(key)
            if not value:
                continue
            bucket_key = f"{key}:{str(value).lower()}"
            counts = self.user_context_history[user_id]
            total_for_key = sum(v for k, v in counts.items() if k.startswith(f"{key}:"))
            seen = counts.get(bucket_key, 0)
            if total_for_key < 3:
                risk_values.append(0.15)
            elif seen == 0:
                risk_values.append(0.65)
            else:
                risk_values.append(float(np.clip(1.0 - (seen / max(1, total_for_key)), 0.0, 0.35)))
        if not risk_values:
            return 0.0
        return float(np.clip(np.mean(risk_values), 0.0, 1.0))

    def _update_context_history(self, user_id: str, context: dict | None) -> None:
        if not context:
            return
        for key in ("device_class", "session_type"):
            value = context.get(key)
            if value:
                bucket_key = f"{key}:{str(value).lower()}"
                self.user_context_history[user_id][bucket_key] += 1

    def _smoothed_risk(self, user_id: str | None, risk: float) -> float:
        risk = float(np.clip(risk, 0.0, 1.0))
        if not user_id:
            return risk
        previous = self.user_risk_ema.get(user_id)
        if previous is None:
            self.user_risk_ema[user_id] = risk
            return risk
        if risk >= float(self.critical_risk_passthrough):
            # Avoid hiding acute anomalies behind smoothing lag.
            self.user_risk_ema[user_id] = risk
            return risk
        ema = 0.65 * previous + 0.35 * risk
        self.user_risk_ema[user_id] = ema
        return float(np.clip(ema, 0.0, 1.0))

    def _should_update_profile(self, user_id: str, risk: float, explanation: dict | None = None) -> bool:
        profile = self.user_profiles.get(user_id)
        if not profile:
            return True
        if not profile.get("is_model_trained"):
            return True
        components = (explanation or {}).get("components", {}) if isinstance(explanation, dict) else {}
        model_risk = float(components.get("model", 0.0))
        distance_risk = float(components.get("distance", 0.0))
        impostor_risk = float(components.get("impostor", 0.0))
        separation_risk = float(components.get("separation", 0.0))
        profile_z_spike_risk = float(components.get("profile_z_spike", 0.0))
        if (
            distance_risk >= 0.75
            or model_risk >= 0.75
            or impostor_risk >= 0.45
            or separation_risk >= 0.55
            or profile_z_spike_risk >= 0.45
        ):
            return False
        return float(risk) <= float(self.profile_update_risk_threshold)

    def get_last_explanation(self, user_id: str | None) -> dict:
        if not user_id:
            return {"reason": "unknown", "components": {}, "top_deviations": []}
        return self.last_explanations.get(user_id, {"reason": "none", "components": {}, "top_deviations": []})

    def _store_debug_io(
        self,
        user_id: str,
        incoming_behavioral_data: dict,
        analyzed_behavioral_data: dict,
        features: dict | None,
        risk: float,
        explanation: dict,
    ) -> None:
        incoming_keystrokes = incoming_behavioral_data.get("keystrokeData", []) or []
        incoming_mouse = incoming_behavioral_data.get("mouseData", []) or []
        incoming_eye = incoming_behavioral_data.get("eyeData", []) or []
        analyzed_keystrokes = analyzed_behavioral_data.get("keystrokeData", []) or []
        analyzed_mouse = analyzed_behavioral_data.get("mouseData", []) or []
        analyzed_eye = analyzed_behavioral_data.get("eyeData", []) or []
        feature_map = features or {}
        feature_keys = sorted(feature_map.keys())
        self.last_debug_io[user_id] = {
            "input": {
                "incoming_behavioral_data": incoming_behavioral_data,
                "analyzed_behavioral_data": analyzed_behavioral_data,
                "incoming_event_counts": {
                    "keystrokes": int(len(incoming_keystrokes)),
                    "mouse": int(len(incoming_mouse)),
                    "eye": int(len(incoming_eye)),
                    "total": int(len(incoming_keystrokes) + len(incoming_mouse) + len(incoming_eye)),
                },
                "analyzed_event_counts": {
                    "keystrokes": int(len(analyzed_keystrokes)),
                    "mouse": int(len(analyzed_mouse)),
                    "eye": int(len(analyzed_eye)),
                    "total": int(len(analyzed_keystrokes) + len(analyzed_mouse) + len(analyzed_eye)),
                },
                "incoming_interaction_window_ms": float(self._interaction_window_ms(incoming_keystrokes, incoming_mouse, incoming_eye)),
                "analyzed_interaction_window_ms": float(self._interaction_window_ms(analyzed_keystrokes, analyzed_mouse, analyzed_eye)),
            },
            "model_input": {
                "feature_keys": feature_keys,
                "feature_vector": [float(feature_map.get(k, 0.0)) for k in feature_keys],
                "feature_map": {k: float(feature_map[k]) for k in feature_keys},
            },
            "model_output": {
                "risk_score": float(np.clip(risk, 0.0, 1.0)),
                "explanation": explanation,
            },
        }

    def get_last_debug_io(self, user_id: str | None) -> dict:
        if not user_id:
            return {}
        return self.last_debug_io.get(user_id, {})
