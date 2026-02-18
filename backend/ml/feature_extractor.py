# feature_extractor.py
import numpy as np
import pandas as pd

class BehavioralFeatureExtractor:
    def __init__(self):
        self.keystroke_features = {}
        self.mouse_features = {}
    
    def extract_keystroke_features(self, keystroke_data):
        """Extract advanced features from keystroke dynamics as requested"""
        features = {}
        
        # Convert to DataFrame for easier processing
        df = pd.DataFrame(keystroke_data)
        
        if df.empty or 'type' not in df.columns:
            return self.get_default_keystroke_features()
            
        # 1. Timing Features
        # Dwell Time = release_time - press_time
        # (Assuming 'dwellTime' is already calculated in the frontend/backend collector, 
        # but we can re-verify or calculate if raw events are provided)
        keyup_events = df[df['type'] == 'keyup'].copy()
        keydown_events = df[df['type'] == 'keydown'].copy()
        
        if len(keyup_events) < 5 or len(keydown_events) < 5:
            return self.get_default_keystroke_features()

        # Dwell times
        dwell_times = keyup_events['dwellTime'].values if 'dwellTime' in keyup_events else []
        if len(dwell_times) == 0:
            # Calculate if not present: find matching keydown for each keyup
            # Simple approximation if events are ordered
            dwell_times = []
            for i in range(min(len(keyup_events), len(keydown_events))):
                dwell_times.append(keyup_events.iloc[i]['timestamp'] - keydown_events.iloc[i]['timestamp'])
        
        # Flight Time = next_key_press_time - current_key_release_time
        # Inter-Key Latency = next_key_press_time - current_key_press_time
        flight_times = []
        ikl_latencies = []
        for i in range(len(keydown_events) - 1):
            current_release = keyup_events.iloc[i]['timestamp']
            current_press = keydown_events.iloc[i]['timestamp']
            next_press = keydown_events.iloc[i+1]['timestamp']
            
            flight_times.append(next_press - current_release)
            ikl_latencies.append(next_press - current_press)

        # 3. Statistical Features
        features['dwell_mean'] = np.mean(dwell_times) if len(dwell_times) > 0 else 0
        features['dwell_std'] = np.std(dwell_times) if len(dwell_times) > 0 else 0
        features['flight_mean'] = np.mean(flight_times) if len(flight_times) > 0 else 0
        features['flight_std'] = np.std(flight_times) if len(flight_times) > 0 else 0
        features['ikl_mean'] = np.mean(ikl_latencies) if len(ikl_latencies) > 0 else 0

        # 2. Typing Behavior Features
        # Average typing speed (keys per second)
        total_time = (df['timestamp'].max() - df['timestamp'].min()) / 1000.0 # seconds
        features['typing_speed'] = len(keydown_events) / total_time if total_time > 0 else 0
        
        # Typing rhythm consistency (std deviation of flight times)
        features['rhythm_consistency'] = features['flight_std']
        
        # Backspace usage frequency
        backspaces = len(df[df['key'] == 'Backspace'])
        features['backspace_frequency'] = backspaces / len(keydown_events) if len(keydown_events) > 0 else 0
        
        # Error rate (approximated by backspaces + deletions)
        corrections = len(df[df['key'].isin(['Backspace', 'Delete'])])
        features['error_rate'] = corrections / len(keydown_events) if len(keydown_events) > 0 else 0

        # Additional metrics from previous implementation
        features['unique_keys'] = df['key'].nunique()
        
        return features
    
    def get_feature_vector(self, keystroke_data, mouse_data=None):
        """Returns a numerical feature vector ready for ML models"""
        k_features = self.extract_keystroke_features(keystroke_data)
        
        # Basic mouse features if available, else defaults
        if mouse_data:
            m_features = self.extract_mouse_features(mouse_data)
        else:
            m_features = self.get_default_mouse_features()
            
        combined = {**k_features, **m_features}
        
        # Return sorted list of values for consistent vector shape
        keys = sorted(combined.keys())
        vector = [combined[k] for k in keys]
        
        # Normalize (Simple Min-Max or direct if values are already reasonable)
        # Note: In a production setting, we'd use a fitted StandardScaler or similar.
        # For this demonstration, we return the raw numerical vector as it's "ready" for scikit-learn.
        return np.array(vector), keys

    def extract_mouse_features(self, mouse_data):
        """Extract features from mouse dynamics"""
        features = {}
        
        if not mouse_data:
            return self.get_default_mouse_features()
        
        df = pd.DataFrame(mouse_data)
        
        if len(df) < 5:
            return self.get_default_mouse_features()
        
        # Mouse movement features
        move_events = df[df['type'] == 'mousemove'].copy()
        
        if len(move_events) > 1:
            # Calculate velocities
            move_events['velocity_x'] = np.gradient(move_events['x'])
            move_events['velocity_y'] = np.gradient(move_events['y'])
            move_events['velocity_magnitude'] = np.sqrt(
                move_events['velocity_x']**2 + move_events['velocity_y']**2
            )
            
            # Velocity features
            features['velocity_mean'] = np.mean(move_events['velocity_magnitude'])
            features['velocity_std'] = np.std(move_events['velocity_magnitude'])
            features['velocity_max'] = np.max(move_events['velocity_magnitude'])
            
            # Acceleration features
            accelerations = np.gradient(move_events['velocity_magnitude'])
            features['acceleration_mean'] = np.mean(accelerations)
            features['acceleration_std'] = np.std(accelerations)
            
            # Movement patterns
            features['movement_efficiency'] = self.calculate_movement_efficiency(move_events)
            features['direction_changes'] = self.count_direction_changes(move_events)
            
        else:
            features.update(self.get_default_mouse_features())
        
        # Click features
        click_events = df[df['type'].isin(['click', 'mousedown'])].copy()
        
        if len(click_events) > 1:
            click_intervals = np.diff(click_events['timestamp'])
            features['click_interval_mean'] = np.mean(click_intervals)
            features['click_interval_std'] = np.std(click_intervals)
            features['click_rate'] = len(click_events) / (df['timestamp'].iloc[-1] - df['timestamp'].iloc[0]) * 1000
        else:
            features['click_interval_mean'] = 0
            features['click_interval_std'] = 0
            features['click_rate'] = 0
        
        return features
    
    def calculate_movement_efficiency(self, move_events):
        """Calculate how efficiently the mouse moves (straight line vs actual path)"""
        if len(move_events) < 2:
            return 0
        
        start_x, start_y = move_events.iloc[0]['x'], move_events.iloc[0]['y']
        end_x, end_y = move_events.iloc[-1]['x'], move_events.iloc[-1]['y']
        
        # Straight line distance
        straight_distance = np.sqrt((end_x - start_x)**2 + (end_y - start_y)**2)
        
        # Actual path distance
        actual_distance = 0
        for i in range(1, len(move_events)):
            dx = move_events.iloc[i]['x'] - move_events.iloc[i-1]['x']
            dy = move_events.iloc[i]['y'] - move_events.iloc[i-1]['y']
            actual_distance += np.sqrt(dx**2 + dy**2)
        
        if actual_distance == 0:
            return 1 # If no movement, efficiency is 1 (stationary)
        
        return straight_distance / actual_distance
    
    def count_direction_changes(self, move_events):
        """Count how many times the mouse changes direction"""
        if len(move_events) < 3:
            return 0
        
        direction_changes = 0
        prev_dx = move_events.iloc[1]['x'] - move_events.iloc[0]['x']
        prev_dy = move_events.iloc[1]['y'] - move_events.iloc[0]['y']
        
        for i in range(2, len(move_events)):
            dx = move_events.iloc[i]['x'] - move_events.iloc[i-1]['x']
            dy = move_events.iloc[i]['y'] - move_events.iloc[i-1]['y']
            
            # Check if direction changed significantly
            if (dx * prev_dx < 0) or (dy * prev_dy < 0): # Direction sign change
                direction_changes += 1
            
            prev_dx, prev_dy = dx, dy
        
        return direction_changes
    
    def get_default_keystroke_features(self):
        """Return default keystroke features when insufficient data"""
        return {
            'dwell_mean': 0, 'dwell_std': 0, 'flight_mean': 0, 'flight_std': 0,
            'ikl_mean': 0, 'typing_speed': 0, 'rhythm_consistency': 0,
            'backspace_frequency': 0, 'error_rate': 0, 'unique_keys': 0
        }
    
    def get_default_mouse_features(self):
        """Return default mouse features when insufficient data"""
        return {
            'velocity_mean': 0, 'velocity_std': 0, 'velocity_max': 0,
            'acceleration_mean': 0, 'acceleration_std': 0,
            'movement_efficiency': 0, 'direction_changes': 0,
            'click_interval_mean': 0, 'click_interval_std': 0, 'click_rate': 0
        }
