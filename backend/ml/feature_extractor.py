import numpy as np


class BehavioralFeatureExtractor:
    def __init__(self):
        self.keystroke_features = {}
        self.mouse_features = {}

    @staticmethod
    def _safe_stats(values: list[float], prefix: str) -> dict:
        if not values:
            return {
                f"{prefix}_mean": 0.0,
                f"{prefix}_std": 0.0,
                f"{prefix}_median": 0.0,
                f"{prefix}_p95": 0.0,
            }
        arr = np.asarray(values, dtype=float)
        arr = arr[np.isfinite(arr)]
        if arr.size == 0:
            return {
                f"{prefix}_mean": 0.0,
                f"{prefix}_std": 0.0,
                f"{prefix}_median": 0.0,
                f"{prefix}_p95": 0.0,
            }
        return {
            f"{prefix}_mean": float(np.mean(arr)),
            f"{prefix}_std": float(np.std(arr)),
            f"{prefix}_median": float(np.median(arr)),
            f"{prefix}_p95": float(np.percentile(arr, 95)),
        }

    def extract_keystroke_features(self, keystroke_data):
        """Extract robust keystroke timing and typing-consistency features."""
        if not keystroke_data:
            return self.get_default_keystroke_features()

        ordered = sorted(
            [e for e in keystroke_data if "timestamp" in e],
            key=lambda e: e.get("timestamp", 0),
        )
        if len(ordered) < 6:
            return self.get_default_keystroke_features()

        keydown_events = [e for e in ordered if e.get("type") == "keydown"]
        keyup_events = [e for e in ordered if e.get("type") == "keyup"]
        if len(keydown_events) < 3 or len(keyup_events) < 3:
            return self.get_default_keystroke_features()

        # Match keydown -> keyup by key and order to calculate dwell robustly.
        open_presses: dict[str, list[float]] = {}
        dwell_times: list[float] = []
        for event in ordered:
            event_type = event.get("type")
            key = str(event.get("key", ""))
            ts = float(event.get("timestamp", 0))
            if event_type == "keydown":
                open_presses.setdefault(key, []).append(ts)
            elif event_type == "keyup":
                if "dwellTime" in event and np.isfinite(event.get("dwellTime")):
                    dwell = float(event["dwellTime"])
                else:
                    queue = open_presses.get(key) or []
                    if not queue:
                        continue
                    start = queue.pop(0)
                    dwell = ts - start
                if 0 <= dwell <= 3000:
                    dwell_times.append(dwell)

        down_ts = [float(e.get("timestamp", 0)) for e in keydown_events]
        up_ts = [float(e.get("timestamp", 0)) for e in keyup_events]
        down_ts.sort()
        up_ts.sort()

        flight_times = []
        ikl_latencies = []
        for i in range(min(len(down_ts) - 1, len(up_ts))):
            flight = down_ts[i + 1] - up_ts[i]
            if -500 <= flight <= 3000:
                flight_times.append(flight)
            ikl = down_ts[i + 1] - down_ts[i]
            if 0 <= ikl <= 3000:
                ikl_latencies.append(ikl)

        total_ms = max(1.0, float(ordered[-1]["timestamp"]) - float(ordered[0]["timestamp"]))
        total_s = total_ms / 1000.0
        key_count = max(1, len(keydown_events))

        features = {}
        features.update(self._safe_stats(dwell_times, "dwell"))
        features.update(self._safe_stats(flight_times, "flight"))
        features.update(self._safe_stats(ikl_latencies, "ikl"))
        features["typing_speed"] = float(key_count / total_s)
        features["keys_count"] = float(key_count)
        features["active_duration_ms"] = float(total_ms)
        features["unique_keys"] = float(len({str(e.get("key", "")) for e in keydown_events}))

        corrections = sum(1 for e in keydown_events if str(e.get("key", "")) in {"Backspace", "Delete"})
        features["backspace_frequency"] = float(corrections / key_count)
        features["error_rate"] = float(corrections / key_count)

        # Rhythmic variability and pause behavior.
        pauses = [v for v in ikl_latencies if v > 700]
        features["pause_ratio"] = float(len(pauses) / max(1, len(ikl_latencies)))
        features["rhythm_consistency"] = float(np.std(ikl_latencies)) if ikl_latencies else 0.0

        # Dwell outlier rate via robust MAD.
        if dwell_times:
            dwell_arr = np.asarray(dwell_times, dtype=float)
            med = np.median(dwell_arr)
            mad = np.median(np.abs(dwell_arr - med)) + 1e-6
            robust_z = np.abs(dwell_arr - med) / (1.4826 * mad)
            features["dwell_outlier_rate"] = float(np.mean(robust_z > 3.5))
        else:
            features["dwell_outlier_rate"] = 0.0

        return features

    def get_feature_vector(self, keystroke_data, mouse_data=None):
        k_features = self.extract_keystroke_features(keystroke_data)
        m_features = self.extract_mouse_features(mouse_data or [])
        combined = {**k_features, **m_features}
        keys = sorted(combined.keys())
        vector = [combined[k] for k in keys]
        return np.array(vector, dtype=float), keys

    def extract_mouse_features(self, mouse_data):
        """Extract movement smoothness, speed, acceleration and click dynamics."""
        if not mouse_data:
            return self.get_default_mouse_features()

        ordered = sorted(
            [e for e in mouse_data if "timestamp" in e],
            key=lambda e: e.get("timestamp", 0),
        )
        if len(ordered) < 5:
            return self.get_default_mouse_features()

        move_events = [e for e in ordered if e.get("type") == "mousemove" and "x" in e and "y" in e]
        click_events = [e for e in ordered if e.get("type") in {"click", "mousedown"}]

        features = {}
        velocities = []
        accelerations = []
        direction_angles = []
        path_distance = 0.0

        if len(move_events) > 1:
            prev_v = None
            for i in range(1, len(move_events)):
                prev = move_events[i - 1]
                cur = move_events[i]
                dt = float(cur["timestamp"]) - float(prev["timestamp"])
                if dt <= 0:
                    continue
                dx = float(cur["x"]) - float(prev["x"])
                dy = float(cur["y"]) - float(prev["y"])
                dist = np.hypot(dx, dy)
                path_distance += dist
                v = dist / dt
                if np.isfinite(v):
                    velocities.append(v)
                    direction_angles.append(float(np.arctan2(dy, dx)))
                if prev_v is not None:
                    a = (v - prev_v) / dt
                    if np.isfinite(a):
                        accelerations.append(a)
                prev_v = v

            start = move_events[0]
            end = move_events[-1]
            straight_distance = float(np.hypot(float(end["x"]) - float(start["x"]), float(end["y"]) - float(start["y"])))
            movement_eff = straight_distance / path_distance if path_distance > 0 else 1.0
            features["movement_efficiency"] = float(np.clip(movement_eff, 0.0, 1.0))

            direction_changes = 0
            for i in range(1, len(direction_angles)):
                delta = abs(direction_angles[i] - direction_angles[i - 1])
                if delta > np.pi:
                    delta = 2 * np.pi - delta
                if delta > (np.pi / 2):
                    direction_changes += 1
            features["direction_changes"] = float(direction_changes)
        else:
            features["movement_efficiency"] = 0.0
            features["direction_changes"] = 0.0

        features.update(self._safe_stats(velocities, "velocity"))
        features.update(self._safe_stats(accelerations, "acceleration"))

        if len(click_events) > 1:
            click_ts = [float(e["timestamp"]) for e in click_events]
            click_ts.sort()
            intervals = [click_ts[i] - click_ts[i - 1] for i in range(1, len(click_ts)) if click_ts[i] >= click_ts[i - 1]]
            features.update(self._safe_stats(intervals, "click_interval"))
            duration_ms = max(1.0, float(ordered[-1]["timestamp"]) - float(ordered[0]["timestamp"]))
            features["click_rate"] = float(len(click_events) * 1000.0 / duration_ms)
        else:
            features["click_interval_mean"] = 0.0
            features["click_interval_std"] = 0.0
            features["click_interval_median"] = 0.0
            features["click_interval_p95"] = 0.0
            features["click_rate"] = 0.0

        features["mouse_events_count"] = float(len(ordered))
        return features

    def get_default_keystroke_features(self):
        return {
            "dwell_mean": 0.0,
            "dwell_std": 0.0,
            "dwell_median": 0.0,
            "dwell_p95": 0.0,
            "flight_mean": 0.0,
            "flight_std": 0.0,
            "flight_median": 0.0,
            "flight_p95": 0.0,
            "ikl_mean": 0.0,
            "ikl_std": 0.0,
            "ikl_median": 0.0,
            "ikl_p95": 0.0,
            "typing_speed": 0.0,
            "keys_count": 0.0,
            "active_duration_ms": 0.0,
            "unique_keys": 0.0,
            "backspace_frequency": 0.0,
            "error_rate": 0.0,
            "pause_ratio": 0.0,
            "rhythm_consistency": 0.0,
            "dwell_outlier_rate": 0.0,
        }

    def get_default_mouse_features(self):
        return {
            "velocity_mean": 0.0,
            "velocity_std": 0.0,
            "velocity_median": 0.0,
            "velocity_p95": 0.0,
            "acceleration_mean": 0.0,
            "acceleration_std": 0.0,
            "acceleration_median": 0.0,
            "acceleration_p95": 0.0,
            "movement_efficiency": 0.0,
            "direction_changes": 0.0,
            "click_interval_mean": 0.0,
            "click_interval_std": 0.0,
            "click_interval_median": 0.0,
            "click_interval_p95": 0.0,
            "click_rate": 0.0,
            "mouse_events_count": 0.0,
        }
