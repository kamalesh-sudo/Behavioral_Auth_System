import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path

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
    
    def create_user_profile(self, user_id, behavioral_data):
        """Create initial user profile from behavioral data"""
        features = self.extract_features(behavioral_data)
        
        # Store user profile
        self.user_profiles[user_id] = {
            'features': features,
            'training_data': behavioral_data,
            'model': IsolationForest(contamination=0.1, random_state=42)
        }
        
        # Train user-specific model
        feature_matrix = self.prepare_feature_matrix([features])
        self.user_profiles[user_id]['model'].fit(feature_matrix)
        
        return features
    
    def extract_features(self, behavioral_data):
        """Extract features from behavioral data"""
        keystroke_data = behavioral_data.get('keystrokeData', [])
        mouse_data = behavioral_data.get('mouseData', [])
        
        keystroke_features = self.feature_extractor.extract_keystroke_features(keystroke_data)
        mouse_features = self.feature_extractor.extract_mouse_features(mouse_data)
        
        # Combine features
        combined_features = {**keystroke_features, **mouse_features}
        
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
        
        # Combine and sort by timestamp
        all_events = []
        for event in keystroke_data:
            all_events.append(('keystroke', event))
        for event in mouse_data:
            all_events.append(('mouse', event))
        
        all_events.sort(key=lambda x: x[1].get('timestamp', 0))
        
        # Create windows
        windows = []
        current_window = {'keystrokeData': [], 'mouseData': []}
        
        for event_type, event in all_events:
            if event_type == 'keystroke':
                current_window['keystrokeData'].append(event)
            else:
                current_window['mouseData'].append(event)
            
            # Check if window is full
            total_events = len(current_window['keystrokeData']) + len(current_window['mouseData'])
            if total_events >= window_size:
                windows.append(current_window)
                current_window = {'keystrokeData': [], 'mouseData': []}
        
        # Add final window if not empty
        if current_window['keystrokeData'] or current_window['mouseData']:
            windows.append(current_window)
        
        return windows
    
    def analyze_real_time(self, keystroke_data, mouse_data, user_id=None):
        """Analyze behavioral data in real-time"""
        behavioral_data = {
            'keystrokeData': keystroke_data,
            'mouseData': mouse_data
        }
        
        features = self.extract_features(behavioral_data)
        
        if not features:
            return 0.0
        
        # If user-specific model exists, use it
        if user_id and user_id in self.user_profiles:
            return self.analyze_with_user_model(features, user_id)
        
        # Otherwise, use global model
        return self.analyze_with_global_model(features)
    
    def analyze_with_user_model(self, features, user_id):
        """Analyze using user-specific model"""
        user_profile = self.user_profiles[user_id]
        feature_matrix = self.prepare_feature_matrix([features])
        
        # Anomaly detection
        anomaly_score = user_profile['model'].decision_function(feature_matrix)[0]
        
        # Normalize to 0-1 range (higher = more anomalous)
        risk_score = max(0, min(1, (0.5 - anomaly_score) / 1.0))
        
        return risk_score
    
    def analyze_with_global_model(self, features):
        """Analyze using global model"""
        if not self.is_trained:
            return 0.0
        
        feature_matrix = self.prepare_feature_matrix([features])
        feature_matrix_scaled = self.scaler.transform(feature_matrix)
        
        # Get prediction probabilities
        probabilities = self.classifier.predict_proba(feature_matrix_scaled)[0]
        
        # Calculate risk score based on prediction confidence
        max_probability = np.max(probabilities)
        risk_score = 1.0 - max_probability
        
        return risk_score
    
    def update_user_profile(self, user_id, behavioral_data, feedback=None):
        """Update user profile with new behavioral data"""
        if user_id not in self.user_profiles:
            self.create_user_profile(user_id, behavioral_data)
            return
        
        new_features = self.extract_features(behavioral_data)
        
        # Update user profile
        self.user_profiles[user_id]['features'] = new_features
        self.user_profiles[user_id]['training_data'] = behavioral_data
        
        # Retrain user-specific model
        feature_matrix = self.prepare_feature_matrix([new_features])
        self.user_profiles[user_id]['model'].fit(feature_matrix)
    
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
