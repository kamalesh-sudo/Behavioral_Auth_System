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

def simulate_eye_data(start_ts, blink_freq=0.1):
    eye_events = []
    ts = start_ts
    for i in range(10):
        is_blink = (i % 5 == 0)
        event = {
            "x": 100 + i * 5,
            "y": 200 + i * 2,
            "timestamp": ts,
            "isBlink": is_blink
        }
        if is_blink:
            event["blinkDuration"] = 150
        eye_events.append(event)
        ts += 100
    return eye_events

analyzer = BehavioralAnalyzer()

print("Feeding user1 data to train profile")
for i in range(10):
    data = simulate_user_data(1000 * i, variation=10)
    eye_data = simulate_eye_data(1000 * i)
    risk = analyzer.analyze_real_time(data['keystrokeData'], data['mouseData'], eye_data, user_id="user1")

print("Feeding user2 data to train profile")
for i in range(10):
    data = simulate_user_data(1000 * i, variation=150)
    eye_data = simulate_eye_data(1000 * i + 500)
    risk = analyzer.analyze_real_time(data['keystrokeData'], data['mouseData'], eye_data, user_id="user2")

print("Cross testing: UNKNOWN User 3 trying to be User 1 with anomalies")
data_u3 = simulate_user_data(100000, variation=800) # massive variation
eye_u3 = simulate_eye_data(100000, blink_freq=0.5) # more blinks
risk_u3_impostor = analyzer.analyze_real_time(data_u3['keystrokeData'], data_u3['mouseData'], eye_u3, user_id="user1")
print("Risk:", risk_u3_impostor)
print("Explanation:", analyzer.get_last_explanation("user1"))
