import numpy as np


def calculate_keystroke_dynamics(keystroke_data: list[dict]) -> dict:
    """
    Build per-window keystroke timing dynamics for identity discrimination.
    Returns dwell, flight and inter-key latency series used to form a rhythm profile.
    """
    if not keystroke_data:
        return {
            "ordered_events": [],
            "keydown_events": [],
            "keyup_events": [],
            "dwell_times": [],
            "flight_times": [],
            "inter_key_latencies": [],
            "rhythm_profile": {},
        }

    ordered = sorted(
        [event for event in keystroke_data if event.get("timestamp") is not None],
        key=lambda event: float(event.get("timestamp", 0.0)),
    )
    keydown_events = [event for event in ordered if event.get("type") == "keydown"]
    keyup_events = [event for event in ordered if event.get("type") == "keyup"]

    open_presses: dict[str, list[float]] = {}
    dwell_times: list[float] = []
    for event in ordered:
        event_type = event.get("type")
        key = str(event.get("key", ""))
        ts = float(event.get("timestamp", 0.0))
        if event_type == "keydown":
            open_presses.setdefault(key, []).append(ts)
        elif event_type == "keyup":
            dwell = None
            raw_dwell = event.get("dwellTime")
            if raw_dwell is not None and np.isfinite(raw_dwell):
                dwell = float(raw_dwell)
            else:
                queue = open_presses.get(key) or []
                if queue:
                    dwell = ts - float(queue.pop(0))
            if dwell is not None and 0.0 <= dwell <= 3000.0:
                dwell_times.append(float(dwell))

    down_ts = sorted(float(event.get("timestamp", 0.0)) for event in keydown_events)
    up_ts = sorted(float(event.get("timestamp", 0.0)) for event in keyup_events)

    flight_times: list[float] = []
    inter_key_latencies: list[float] = []
    for i in range(min(len(down_ts) - 1, len(up_ts))):
        flight = down_ts[i + 1] - up_ts[i]
        if -500.0 <= flight <= 3000.0:
            flight_times.append(float(flight))
        ikl = down_ts[i + 1] - down_ts[i]
        if 0.0 <= ikl <= 3000.0:
            inter_key_latencies.append(float(ikl))

    rhythm_profile = {
        "dwell_median": float(np.median(dwell_times)) if dwell_times else 0.0,
        "flight_median": float(np.median(flight_times)) if flight_times else 0.0,
        "ikl_median": float(np.median(inter_key_latencies)) if inter_key_latencies else 0.0,
        "ikl_std": float(np.std(inter_key_latencies)) if inter_key_latencies else 0.0,
    }

    return {
        "ordered_events": ordered,
        "keydown_events": keydown_events,
        "keyup_events": keyup_events,
        "dwell_times": dwell_times,
        "flight_times": flight_times,
        "inter_key_latencies": inter_key_latencies,
        "rhythm_profile": rhythm_profile,
    }


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

        dynamics = calculate_keystroke_dynamics(keystroke_data)
        ordered = dynamics["ordered_events"]
        if len(ordered) < 6:
            return self.get_default_keystroke_features()

        keydown_events = dynamics["keydown_events"]
        keyup_events = dynamics["keyup_events"]
        if len(keydown_events) < 3 or len(keyup_events) < 3:
            return self.get_default_keystroke_features()

        dwell_times = dynamics["dwell_times"]
        flight_times = dynamics["flight_times"]
        ikl_latencies = dynamics["inter_key_latencies"]
        rhythm_profile = dynamics["rhythm_profile"]

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
        features["rhythm_profile_ikl_std"] = float(rhythm_profile.get("ikl_std", 0.0))
        features["rhythm_profile_dwell_median"] = float(rhythm_profile.get("dwell_median", 0.0))
        features["rhythm_profile_flight_median"] = float(rhythm_profile.get("flight_median", 0.0))
        features["rhythm_profile_ikl_median"] = float(rhythm_profile.get("ikl_median", 0.0))

        # Identity-sensitive typing structure features.
        key_sequence = [str(e.get("key", "")) for e in keydown_events]
        transitions = [f"{key_sequence[i]}->{key_sequence[i + 1]}" for i in range(len(key_sequence) - 1)]
        if transitions:
            counts = {}
            for transition in transitions:
                counts[transition] = counts.get(transition, 0) + 1
            probs = np.array([c / len(transitions) for c in counts.values()], dtype=float)
            features["transition_entropy"] = float(-np.sum(probs * np.log2(np.clip(probs, 1e-12, 1.0))))
        else:
            features["transition_entropy"] = 0.0

        repeats = sum(1 for i in range(1, len(key_sequence)) if key_sequence[i] == key_sequence[i - 1])
        features["repeat_key_ratio"] = float(repeats / max(1, len(key_sequence) - 1))
        modifier_keys = {"Shift", "Control", "Alt", "Meta", "CapsLock"}
        modifiers = sum(1 for key in key_sequence if key in modifier_keys)
        features["modifier_key_ratio"] = float(modifiers / key_count)

        if dwell_times:
            dwell_arr = np.asarray(dwell_times, dtype=float)
            dwell_mean = float(np.mean(dwell_arr))
            features["dwell_cv"] = float((np.std(dwell_arr) / max(1e-6, dwell_mean)))
        else:
            features["dwell_cv"] = 0.0

        if ikl_latencies:
            ikl_arr = np.asarray(ikl_latencies, dtype=float)
            ikl_mean = float(np.mean(ikl_arr))
            features["ikl_burstiness"] = float(np.var(ikl_arr) / max(1e-6, ikl_mean))
        else:
            features["ikl_burstiness"] = 0.0

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
        jerks = []
        direction_angles = []
        path_distance = 0.0
        pause_count = 0

        if len(move_events) > 1:
            prev_v = None
            prev_a = None
            for i in range(1, len(move_events)):
                prev = move_events[i - 1]
                cur = move_events[i]
                dt = float(cur["timestamp"]) - float(prev["timestamp"])
                if dt <= 0:
                    continue
                if dt > 120:
                    pause_count += 1
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
                        if prev_a is not None:
                            jerk = (a - prev_a) / dt
                            if np.isfinite(jerk):
                                jerks.append(float(jerk))
                        prev_a = a
                prev_v = v

            start = move_events[0]
            end = move_events[-1]
            straight_distance = float(np.hypot(float(end["x"]) - float(start["x"]), float(end["y"]) - float(start["y"])))
            movement_eff = straight_distance / path_distance if path_distance > 0 else 1.0
            features["movement_efficiency"] = float(np.clip(movement_eff, 0.0, 1.0))
            features["path_length"] = float(path_distance)

            direction_changes = 0
            turn_angles = []
            for i in range(1, len(direction_angles)):
                delta = abs(direction_angles[i] - direction_angles[i - 1])
                if delta > np.pi:
                    delta = 2 * np.pi - delta
                if delta > (np.pi / 2):
                    direction_changes += 1
                turn_angles.append(delta)
            features["direction_changes"] = float(direction_changes)
            if turn_angles:
                features["turn_angle_mean"] = float(np.mean(turn_angles))
                features["turn_angle_std"] = float(np.std(turn_angles))
            else:
                features["turn_angle_mean"] = 0.0
                features["turn_angle_std"] = 0.0
            features["move_pause_ratio"] = float(pause_count / max(1, len(move_events) - 1))
        else:
            features["movement_efficiency"] = 0.0
            features["direction_changes"] = 0.0
            features["path_length"] = 0.0
            features["turn_angle_mean"] = 0.0
            features["turn_angle_std"] = 0.0
            features["move_pause_ratio"] = 0.0

        features.update(self._safe_stats(velocities, "velocity"))
        features.update(self._safe_stats(accelerations, "acceleration"))
        features.update(self._safe_stats(jerks, "jerk"))

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

        features["click_to_move_ratio"] = float(len(click_events) / max(1, len(move_events)))
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
            "rhythm_profile_ikl_std": 0.0,
            "rhythm_profile_dwell_median": 0.0,
            "rhythm_profile_flight_median": 0.0,
            "rhythm_profile_ikl_median": 0.0,
            "dwell_outlier_rate": 0.0,
            "transition_entropy": 0.0,
            "repeat_key_ratio": 0.0,
            "modifier_key_ratio": 0.0,
            "dwell_cv": 0.0,
            "ikl_burstiness": 0.0,
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
            "jerk_mean": 0.0,
            "jerk_std": 0.0,
            "jerk_median": 0.0,
            "jerk_p95": 0.0,
            "movement_efficiency": 0.0,
            "path_length": 0.0,
            "direction_changes": 0.0,
            "turn_angle_mean": 0.0,
            "turn_angle_std": 0.0,
            "move_pause_ratio": 0.0,
            "click_interval_mean": 0.0,
            "click_interval_std": 0.0,
            "click_interval_median": 0.0,
            "click_interval_p95": 0.0,
            "click_rate": 0.0,
            "click_to_move_ratio": 0.0,
            "mouse_events_count": 0.0,
        }
