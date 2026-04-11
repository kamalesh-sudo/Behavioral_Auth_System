import unittest
import os
import sys


sys.path.append(os.path.dirname(os.path.dirname(__file__)))
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


def make_irregular_keystrokes(base_ts: int = 0, count: int = 12) -> list[dict]:
    events = []
    ts = base_ts
    dwell_pattern = [35, 280, 55, 340, 45, 260]
    interval_pattern = [120, 520, 140, 620, 110, 560]
    keys = ["t", "h", "e", "i", "n", "v"]
    for i in range(count):
        key = keys[i % len(keys)]
        dwell = dwell_pattern[i % len(dwell_pattern)]
        interval = interval_pattern[i % len(interval_pattern)]
        key_code = ord(key.upper())
        events.append({"type": "keydown", "key": key, "keyCode": key_code, "timestamp": ts})
        events.append(
            {"type": "keyup", "key": key, "keyCode": key_code, "timestamp": ts + dwell, "dwellTime": dwell}
        )
        ts += interval
    return events


class BehavioralMLTests(unittest.TestCase):
    def test_feature_extractor_outputs_finite_values(self) -> None:
        extractor = BehavioralFeatureExtractor()
        features = extractor.extract_keystroke_features(make_keystrokes())
        features.update(extractor.extract_mouse_features(make_mouse()))
        self.assertGreater(len(features), 10)
        self.assertIn("curvature_mean", features)
        self.assertIn("tangential_acceleration_mean", features)
        self.assertIn("path_curvature_deviation_mean", features)
        self.assertIn("shortcut_ctrl_v_latency_mean", features)
        self.assertIn("digraph_th_latency_mean", features)
        self.assertIn("deletion_selection_ratio", features)
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

    def test_short_burst_window_returns_low_risk(self) -> None:
        analyzer = BehavioralAnalyzer()
        burst = []
        ts = 0
        for _ in range(8):
            burst.append({"type": "keydown", "key": "a", "keyCode": 65, "timestamp": ts})
            burst.append({"type": "keyup", "key": "a", "keyCode": 65, "timestamp": ts + 5, "dwellTime": 5})
            ts += 10
        risk = analyzer.analyze_real_time(keystroke_data=burst, mouse_data=[], user_id="u_burst")
        self.assertLessEqual(risk, 0.1)

    def test_short_windows_accumulate_before_scoring(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_accum"

        chunk_one = make_keystrokes(base_ts=0, dwell=80, interval=220, count=3)
        chunk_two = make_keystrokes(base_ts=700, dwell=80, interval=220, count=3)
        mouse_one = make_mouse(base_ts=0, step=80, count=6)
        mouse_two = make_mouse(base_ts=700, step=80, count=6)

        risk_first = analyzer.analyze_real_time(
            keystroke_data=chunk_one,
            mouse_data=mouse_one,
            user_id=user_id,
        )
        risk_second = analyzer.analyze_real_time(
            keystroke_data=chunk_two,
            mouse_data=mouse_two,
            user_id=user_id,
        )
        explanation = analyzer.get_last_explanation(user_id)

        self.assertLessEqual(risk_first, 0.1)
        self.assertGreater(risk_second, risk_first)
        self.assertGreater(risk_second, 0.1)
        self.assertNotEqual(explanation.get("reason"), "insufficient_signal")

    def test_critical_risk_bypasses_smoothing_lag(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_smooth"
        baseline = analyzer._smoothed_risk(user_id, 0.2)
        critical = analyzer._smoothed_risk(user_id, 0.72)
        self.assertAlmostEqual(baseline, 0.2, places=6)
        self.assertAlmostEqual(critical, 0.72, places=6)

    def test_debug_io_captures_raw_model_input_and_output(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_debug"
        keystrokes = make_keystrokes(dwell=85, interval=210)
        mouse = make_mouse(step=22)

        risk = analyzer.analyze_real_time(
            keystroke_data=keystrokes,
            mouse_data=mouse,
            user_id=user_id,
        )
        debug_io = analyzer.get_last_debug_io(user_id)

        self.assertIn("input", debug_io)
        self.assertIn("model_input", debug_io)
        self.assertIn("model_output", debug_io)
        self.assertEqual(int(debug_io["input"]["incoming_event_counts"]["keystrokes"]), len(keystrokes))
        self.assertEqual(int(debug_io["input"]["incoming_event_counts"]["mouse"]), len(mouse))
        self.assertAlmostEqual(float(debug_io["model_output"]["risk_score"]), float(risk), places=6)
        self.assertGreater(len(debug_io["model_input"]["feature_keys"]), 10)
        self.assertEqual(
            len(debug_io["model_input"]["feature_keys"]),
            len(debug_io["model_input"]["feature_vector"]),
        )

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
        self.assertGreater(anomaly_risk, 0.15)

    def test_unseen_context_increases_context_component(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_context"
        normal_data = {"keystrokeData": make_keystrokes(dwell=85, interval=210), "mouseData": make_mouse(step=22)}
        analyzer.create_user_profile(user_id, normal_data)
        for _ in range(12):
            analyzer.update_user_profile(user_id, normal_data)
            analyzer.analyze_real_time(
                keystroke_data=normal_data["keystrokeData"],
                mouse_data=normal_data["mouseData"],
                user_id=user_id,
                context={"device_class": "desktop", "session_type": "typing_heavy"},
            )

        features = analyzer.extract_features(normal_data)
        _, known_expl = analyzer.analyze_with_user_model(
            features,
            user_id,
            context={"device_class": "desktop", "session_type": "typing_heavy"},
        )
        _, unknown_expl = analyzer.analyze_with_user_model(
            features,
            user_id,
            context={"device_class": "mobile", "session_type": "mouse_heavy"},
        )
        self.assertGreater(
            float(unknown_expl["components"]["context"]),
            float(known_expl["components"]["context"]),
        )

    def test_cross_user_impostor_signal_increases_for_wrong_user(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_a = "user_a"
        user_b = "user_b"

        data_a = {"keystrokeData": make_keystrokes(dwell=80, interval=200), "mouseData": make_mouse(step=20)}
        data_b = {"keystrokeData": make_keystrokes(dwell=240, interval=520), "mouseData": make_mouse(step=85)}

        analyzer.create_user_profile(user_a, data_a)
        analyzer.create_user_profile(user_b, data_b)
        for _ in range(12):
            analyzer.update_user_profile(user_a, data_a)
            analyzer.update_user_profile(user_b, data_b)

        a_features = analyzer.extract_features(data_a)
        b_features = analyzer.extract_features(data_b)
        same_user_risk, same_user_expl = analyzer.analyze_with_user_model(a_features, user_a)
        impostor_risk, impostor_expl = analyzer.analyze_with_user_model(b_features, user_a)

        self.assertGreater(float(impostor_expl["components"]["impostor"]), float(same_user_expl["components"]["impostor"]))
        self.assertGreater(impostor_risk, same_user_risk)
        self.assertIn("impostor_hint", impostor_expl)
        self.assertIn("separation", impostor_expl["components"])
        self.assertIn("separation", same_user_expl["components"])
        self.assertGreater(
            float(impostor_expl["components"]["separation"]),
            float(same_user_expl["components"]["separation"]),
        )

    def test_cross_user_impostor_can_reach_alert_threshold(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_a = "user_a_alert"
        user_b = "user_b_alert"
        data_a = {
            "keystrokeData": make_keystrokes(dwell=80, interval=140, count=14),
            "mouseData": make_mouse(step=20, count=30),
        }
        data_b = {
            "keystrokeData": make_keystrokes(dwell=260, interval=320, count=14),
            "mouseData": make_mouse(step=90, count=30),
        }

        analyzer.create_user_profile(user_a, data_a)
        analyzer.create_user_profile(user_b, data_b)
        for _ in range(14):
            analyzer.update_user_profile(user_a, data_a)
            analyzer.update_user_profile(user_b, data_b)

        impostor_risk = analyzer.analyze_real_time(
            keystroke_data=data_b["keystrokeData"],
            mouse_data=data_b["mouseData"],
            user_id=user_a,
        )
        explanation = analyzer.get_last_explanation(user_a)

        self.assertGreaterEqual(impostor_risk, 0.6)
        self.assertGreater(float(explanation["components"]["impostor"]), 0.5)
        self.assertFalse(bool(explanation.get("profile_updated", True)))

    def test_suspicious_sample_does_not_update_trained_profile(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_guardrail"
        normal_data = {
            "keystrokeData": make_keystrokes(dwell=85, interval=210, count=14),
            "mouseData": make_mouse(step=22, count=28),
        }
        analyzer.create_user_profile(user_id, normal_data)
        for _ in range(14):
            analyzer.update_user_profile(user_id, normal_data)

        history_before = len(analyzer.user_feature_history[user_id])
        suspicious = {
            "keystrokeData": make_keystrokes(dwell=900, interval=1800, count=14),
            "mouseData": make_mouse(step=220, count=28),
        }
        analyzer.analyze_real_time(
            keystroke_data=suspicious["keystrokeData"],
            mouse_data=suspicious["mouseData"],
            user_id=user_id,
        )
        history_after = len(analyzer.user_feature_history[user_id])
        explanation = analyzer.get_last_explanation(user_id)

        self.assertEqual(history_after, history_before)
        self.assertFalse(bool(explanation.get("profile_updated", True)))
        self.assertGreater(float(explanation["components"]["distance"]), 0.75)

    def test_profile_specific_zscore_spike_flags_dwell_variance_or_jerk(self) -> None:
        analyzer = BehavioralAnalyzer()
        user_id = "u_profile_spike"
        baseline = {
            "keystrokeData": make_keystrokes(dwell=85, interval=210, count=14),
            "mouseData": make_mouse(step=22, count=28),
        }
        analyzer.create_user_profile(user_id, baseline)
        for _ in range(12):
            analyzer.update_user_profile(user_id, baseline)

        suspicious = {
            "keystrokeData": make_irregular_keystrokes(count=14),
            "mouseData": make_mouse(step=160, count=28),
        }
        analyzer.analyze_real_time(
            keystroke_data=suspicious["keystrokeData"],
            mouse_data=suspicious["mouseData"],
            user_id=user_id,
        )
        explanation = analyzer.get_last_explanation(user_id)
        components = explanation.get("components", {})

        self.assertIn("profile_z_spike", components)
        self.assertGreaterEqual(float(components.get("profile_z_spike", 0.0)), 0.0)
        spikes = explanation.get("profile_z_spikes", [])
        if spikes:
            monitored = {entry.get("feature") for entry in spikes}
            self.assertTrue({"jerk_mean", "jerk_p95", "dwell_variance", "dwell_std"} & monitored)


if __name__ == "__main__":
    unittest.main()
