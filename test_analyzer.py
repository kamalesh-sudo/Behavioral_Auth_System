import sys
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(ROOT_DIR)
sys.path.append(os.path.join(ROOT_DIR, "backend"))

from backend.ml.behavioral_analyzer import BehavioralAnalyzer

def create_event(etype, key, ts):
    return {"type": etype, "key": key, "timestamp": ts}

def simulate_user_data(start_ts, variation=0):
    keystrokes = []
    ts = start_ts
    for i, char in enumerate("hello world"):
        keystrokes.append(create_event("keydown", char, ts))
        ts += 50 + variation
        keystrokes.append(create_event("keyup", char, ts))
        ts += 200 + variation
    return {"keystrokeData": keystrokes, "mouseData": []}

analyzer = BehavioralAnalyzer()

print("Feeding user1 data to train profile")
for i in range(10):
    data = simulate_user_data(1000 * i, variation=10)
    risk = analyzer.analyze_real_time(data['keystrokeData'], data['mouseData'], user_id="user1")

print("Feeding user2 data to train profile")
for i in range(10):
    data = simulate_user_data(1000 * i, variation=150)
    risk = analyzer.analyze_real_time(data['keystrokeData'], data['mouseData'], user_id="user2")

print("Cross testing: UNKNOWN User 3 trying to be User 1")
data_u3 = simulate_user_data(100000, variation=800) # massive variation
risk_u3_impostor = analyzer.analyze_real_time(data_u3['keystrokeData'], data_u3['mouseData'], user_id="user1")
print("Risk:", risk_u3_impostor)
print("Explanation:", analyzer.get_last_explanation("user1"))
