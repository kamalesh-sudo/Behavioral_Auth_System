import unittest

from backend.ml.behavioral_analyzer import BehavioralAnalyzer
from backend.ml.feature_extractor import BehavioralFeatureExtractor


def make_keystrokes(base_ts: int = 0, dwell: int = 90, interval: int = 220, count: int = 10) -> list[dict]:
    events = []
    ts = base_ts
    for i in range(count):
        key = chr(97 + (i % 5))
        events.append({"type": "keydown", "key": key, "keyCode": ord(key), "timestamp": ts})
        events.append(
            {"type": "keyup", "key": key, "keyCode": ord(key), "timestamp": ts + dwell, "dwellTime": dwell}
        )
        ts += interval
    return events


def make_mouse(base_ts: int = 0, step: int = 25, count: int = 20) -> list[dict]:
    events = []
    ts = base_ts
    x, y = 100, 100
    for i in range(count):
        x += 3
        y += 2
        events.append({"type": "mousemove", "x": x, "y": y, "timestamp": ts})
        ts += step
        if i % 6 == 0:
            events.append({"type": "click", "x": x, "y": y, "button": 0, "timestamp": ts})
    return events


class BehavioralMLTests(unittest.TestCase):
    def test_feature_extractor_outputs_finite_values(self) -> None:
        extractor = BehavioralFeatureExtractor()
        features = extractor.extract_keystroke_features(make_keystrokes())
        features.update(extractor.extract_mouse_features(make_mouse()))
        self.assertGreater(len(features), 10)
        for value in features.values():
            self.assertTrue(value == value)  # not NaN
            self.assertNotEqual(value, float("inf"))
            self.assertNotEqual(value, float("-inf"))

    def test_low_signal_returns_low_risk(self) -> None:
        analyzer = BehavioralAnalyzer()
        risk = analyzer.analyze_real_time(
            keystroke_data=[{"type": "keydown", "key": "a", "timestamp": 1}],
            mouse_data=[],
            user_id="u_low",
        )
        self.assertLessEqual(risk, 0.1)

    def test_anomalous_pattern_increases_user_risk(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_profile"

        normal_data = {"keystrokeData": make_keystrokes(dwell=85, interval=210), "mouseData": make_mouse(step=22)}
        analyzer.create_user_profile(user_id, normal_data)
        for _ in range(12):
            analyzer.update_user_profile(user_id, normal_data)

        normal_risk = analyzer.analyze_real_time(
            keystroke_data=normal_data["keystrokeData"],
            mouse_data=normal_data["mouseData"],
            user_id=user_id,
        )

        anomalous_data = {
            "keystrokeData": make_keystrokes(dwell=320, interval=640),
            "mouseData": make_mouse(step=180),
        }
        anomaly_risk = analyzer.analyze_real_time(
            keystroke_data=anomalous_data["keystrokeData"],
            mouse_data=anomalous_data["mouseData"],
            user_id=user_id,
        )

        self.assertGreaterEqual(anomaly_risk, normal_risk)
        self.assertGreater(anomaly_risk, 0.2)


if __name__ == "__main__":
    unittest.main()
