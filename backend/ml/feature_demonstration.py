import json
import numpy as np
import os
import sys

# Add the backend directory to path so we can import ml.feature_extractor
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.feature_extractor import BehavioralFeatureExtractor

def demonstrate_extraction(json_path):
    print(f"Loading raw data from: {json_path}")
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    keystroke_data = data.get('keystroke_data', [])
    mouse_data = data.get('mouse_data', [])
    
    extractor = BehavioralFeatureExtractor()
    
    print("\n--- Raw Keystroke Input Snippet (First 2 events) ---")
    print(json.dumps(keystroke_data[:2], indent=2))
    
    print("\n--- Extracting Features ---")
    features = extractor.extract_keystroke_features(keystroke_data)
    
    print("\nExtracted Timing Features:")
    print(f"- Mean Dwell Time: {features['dwell_mean']:.2f} ms")
    print(f"- Mean Flight Time: {features['flight_mean']:.2f} ms")
    print(f"- Inter-Key Latency: {features['ikl_mean']:.2f} ms")
    
    print("\nExtracted Behavior Features:")
    print(f"- Typing Speed: {features['typing_speed']:.2f} keys/sec")
    print(f"- Rhythm Consistency (Flight Std): {features['rhythm_consistency']:.2f} ms")
    print(f"- Backspace Frequency: {features['backspace_frequency']:.2%}")
    print(f"- Error Rate (Corrections): {features['error_rate']:.2%}")
    
    print("\n--- Numerical Feature Vector (ML-Ready) ---")
    vector, keys = extractor.get_feature_vector(keystroke_data, mouse_data)
    
    print(f"Vector Length: {len(vector)}")
    print(f"Feature Names: {keys}")
    print("\nVector Output:")
    print(vector)
    
    # Save vector to file for user reference
    output_path = "extracted_feature_vector.txt"
    with open(output_path, "w") as f:
        f.write(f"Feature Names: {keys}\n")
        f.write(f"Vector: {vector.tolist()}\n")
    print(f"\nFull vector saved to: {output_path}")

if __name__ == "__main__":
    # Use the session data we extracted previously
    json_path = os.path.join(os.path.dirname(__file__), '../../behavior_session_1770884682591_qfh151all.json')
    if os.path.exists(json_path):
        demonstrate_extraction(json_path)
    else:
        print(f"Data file not found at {json_path}. Please ensure it exists.")
