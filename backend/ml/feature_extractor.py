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

    @staticmethod
    def _normalize_key(key: str | None) -> str:
        if key is None:
            return ""
        normalized = str(key).strip()
        aliases = {
            "ctrl": "control",
            "ctl": "control",
            "del": "delete",
            "cmd": "meta",
        }
        lowered = normalized.lower()
        lowered = aliases.get(lowered, lowered)
        return lowered

    def _extract_rhythm_buffer_features(self, ordered_events: list[dict]) -> dict:
        """
        Build cognitive signature metrics:
        - Common digraph latency profile (TH/HE/IN)
        - Shortcut latency for Ctrl/Cmd + V
        - Deletion strategy mix (Backspace/Delete/Selection)
        """
        features: dict[str, float] = {}
        digraph_targets = ("th", "he", "in")
        digraph_latencies = {digraph: [] for digraph in digraph_targets}

        keydown_events = [
            event for event in ordered_events
            if event.get("type") == "keydown" and event.get("timestamp") is not None
        ]
        letter_downs: list[tuple[str, float]] = []
        for event in keydown_events:
            key = self._normalize_key(event.get("key"))
            if len(key) == 1 and key.isalpha():
                letter_downs.append((key, float(event.get("timestamp", 0.0))))

        for i in range(1, len(letter_downs)):
            prev_key, prev_ts = letter_downs[i - 1]
            cur_key, cur_ts = letter_downs[i]
            latency = cur_ts - prev_ts
            digraph = f"{prev_key}{cur_key}"
            if digraph in digraph_latencies and 0.0 <= latency <= 1500.0:
                digraph_latencies[digraph].append(float(latency))

        all_digraph_samples: list[float] = []
        for digraph in digraph_targets:
            samples = digraph_latencies[digraph]
            features.update(self._safe_stats(samples, f"digraph_{digraph}_latency"))
            features[f"digraph_{digraph}_samples"] = float(len(samples))
            all_digraph_samples.extend(samples)
        features.update(self._safe_stats(all_digraph_samples, "digraph_latency"))

        control_active = False
        shift_active = False
        control_down_ts: float | None = None
        selection_timestamps: list[float] = []
        shortcut_latencies: list[float] = []
        backspace_count = 0
        delete_count = 0
        selection_count = 0
        selection_then_delete_count = 0
        keydown_count = 0

        for event in ordered_events:
            event_type = event.get("type")
            key = self._normalize_key(event.get("key"))
            ts = float(event.get("timestamp", 0.0))

            if event_type == "keydown":
                keydown_count += 1
                if key in {"control", "meta"}:
                    control_active = True
                    control_down_ts = ts
                elif key == "shift":
                    shift_active = True

                if key == "v" and control_active and control_down_ts is not None:
                    latency = ts - control_down_ts
                    if 0.0 <= latency <= 1500.0:
                        shortcut_latencies.append(float(latency))

                selection_detected = ((key == "a" and control_active) or (key.startswith("arrow") and shift_active))
                if selection_detected:
                    selection_count += 1
                    selection_timestamps.append(ts)

                if key == "backspace":
                    backspace_count += 1
                    if selection_timestamps and (ts - selection_timestamps[-1]) <= 1600.0:
                        selection_then_delete_count += 1
                elif key == "delete":
                    delete_count += 1
                    if selection_timestamps and (ts - selection_timestamps[-1]) <= 1600.0:
                        selection_then_delete_count += 1

            elif event_type == "keyup":
                if key in {"control", "meta"}:
                    control_active = False
                    control_down_ts = None
                elif key == "shift":
                    shift_active = False

        features.update(self._safe_stats(shortcut_latencies, "shortcut_ctrl_v_latency"))
        features["shortcut_ctrl_v_count"] = float(len(shortcut_latencies))

        ratio_den = max(1, keydown_count)
        deletion_total = backspace_count + delete_count + selection_count
        deletion_den = max(1, deletion_total)
        features["deletion_backspace_ratio"] = float(backspace_count / ratio_den)
        features["deletion_delete_ratio"] = float(delete_count / ratio_den)
        features["deletion_selection_ratio"] = float(selection_count / ratio_den)
        features["selection_then_delete_ratio"] = float(selection_then_delete_count / max(1, backspace_count + delete_count))
        features["backspace_delete_ratio"] = float(backspace_count / max(1, delete_count))
        probs = np.array(
            [
                backspace_count / deletion_den,
                delete_count / deletion_den,
                selection_count / deletion_den,
            ],
            dtype=float,
        )
        probs = probs[probs > 0.0]
        if probs.size:
            features["deletion_strategy_entropy"] = float(-np.sum(probs * np.log2(probs)))
        else:
            features["deletion_strategy_entropy"] = 0.0
        return features

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
            features["dwell_variance"] = float(np.var(dwell_arr))
        else:
            features["dwell_cv"] = 0.0
            features["dwell_variance"] = 0.0

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

        features.update(self._extract_rhythm_buffer_features(ordered))
        return features

    def get_feature_vector(self, keystroke_data, mouse_data=None, eye_data=None):
        k_features = self.extract_keystroke_features(keystroke_data)
        m_features = self.extract_mouse_features(mouse_data or [])
        e_features = self.extract_eye_features(eye_data or [])
        combined = {**k_features, **m_features, **e_features}
        keys = sorted(combined.keys())
        vector = [combined[k] for k in keys]
        return np.array(vector, dtype=float), keys

    def get_feature_vector_structure(self) -> dict[str, list[str]]:
        """Expose grouped feature names used by the ML feature vector."""
        keystroke_keys = sorted(self.get_default_keystroke_features().keys())
        mouse_keys = sorted(self.get_default_mouse_features().keys())
        eye_keys = sorted(self.get_default_eye_features().keys())
        return {
            "keystroke": keystroke_keys,
            "mouse": mouse_keys,
            "eye": eye_keys,
            "combined_sorted": sorted(set(keystroke_keys + mouse_keys + eye_keys)),
        }

    def extract_mouse_features(self, mouse_data):
        """Extract movement kinematics, smoothness, curvature and click dynamics."""
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
        velocities: list[float] = []
        accelerations: list[float] = []
        tangential_accelerations: list[float] = []
        curvatures: list[float] = []
        jerks: list[float] = []
        direction_angles: list[float] = []
        path_distance = 0.0
        pause_count = 0

        if len(move_events) > 1:
            segments = []
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
                vx = dx / dt
                vy = dy / dt
                speed = float(np.hypot(vx, vy))
                if np.isfinite(speed):
                    velocities.append(speed)
                    direction_angles.append(float(np.arctan2(dy, dx)))
                segments.append(
                    {
                        "dt": dt,
                        "vx": vx,
                        "vy": vy,
                        "speed": speed,
                    }
                )

            acceleration_vectors = []
            for i in range(1, len(segments)):
                prev = segments[i - 1]
                cur = segments[i]
                dt = max(float(cur["dt"]), 1e-6)
                ax = (float(cur["vx"]) - float(prev["vx"])) / dt
                ay = (float(cur["vy"]) - float(prev["vy"])) / dt
                acceleration_magnitude = float(np.hypot(ax, ay))
                if np.isfinite(acceleration_magnitude):
                    accelerations.append(acceleration_magnitude)

                speed = max(float(cur["speed"]), 1e-6)
                tangential = float(((ax * float(cur["vx"])) + (ay * float(cur["vy"]))) / speed)
                if np.isfinite(tangential):
                    tangential_accelerations.append(float(np.clip(tangential, -5000.0, 5000.0)))

                curvature = float(abs((float(cur["vx"]) * ay) - (float(cur["vy"]) * ax)) / max(speed**3, 1e-6))
                if np.isfinite(curvature):
                    curvatures.append(float(np.clip(curvature, 0.0, 5000.0)))

                acceleration_vectors.append({"dt": dt, "ax": ax, "ay": ay})

            for i in range(1, len(acceleration_vectors)):
                prev = acceleration_vectors[i - 1]
                cur = acceleration_vectors[i]
                dt = max(float(cur["dt"]), 1e-6)
                jx = (float(cur["ax"]) - float(prev["ax"])) / dt
                jy = (float(cur["ay"]) - float(prev["ay"])) / dt
                jerk_magnitude = float(np.hypot(jx, jy))
                if np.isfinite(jerk_magnitude):
                    jerks.append(float(np.clip(jerk_magnitude, 0.0, 5000.0)))

            start = move_events[0]
            end = move_events[-1]
            straight_distance = float(np.hypot(float(end["x"]) - float(start["x"]), float(end["y"]) - float(start["y"])))
            movement_eff = straight_distance / path_distance if path_distance > 0 else 1.0
            features["movement_efficiency"] = float(np.clip(movement_eff, 0.0, 1.0))
            features["path_length"] = float(path_distance)
            features["path_directness_ratio"] = float(np.clip(path_distance / max(1e-6, straight_distance), 0.0, 50.0))

            if straight_distance > 1e-6 and len(move_events) > 2:
                x1 = float(start["x"])
                y1 = float(start["y"])
                x2 = float(end["x"])
                y2 = float(end["y"])
                deviations = []
                for point in move_events[1:-1]:
                    x0 = float(point["x"])
                    y0 = float(point["y"])
                    numerator = abs(((y2 - y1) * x0) - ((x2 - x1) * y0) + (x2 * y1) - (y2 * x1))
                    deviations.append(float(numerator / straight_distance))
                normalized_deviations = [value / max(1e-6, straight_distance) for value in deviations]
                features.update(self._safe_stats(normalized_deviations, "path_curvature_deviation"))
            else:
                features.update(self._safe_stats([], "path_curvature_deviation"))

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
            features["path_directness_ratio"] = 0.0
            features["turn_angle_mean"] = 0.0
            features["turn_angle_std"] = 0.0
            features["move_pause_ratio"] = 0.0
            features.update(self._safe_stats([], "path_curvature_deviation"))

        features.update(self._safe_stats(velocities, "velocity"))
        features.update(self._safe_stats(accelerations, "acceleration"))
        features.update(self._safe_stats(tangential_accelerations, "tangential_acceleration"))
        features.update(self._safe_stats(curvatures, "curvature"))
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
            "dwell_variance": 0.0,
            "ikl_burstiness": 0.0,
            "digraph_th_latency_mean": 0.0,
            "digraph_th_latency_std": 0.0,
            "digraph_th_latency_median": 0.0,
            "digraph_th_latency_p95": 0.0,
            "digraph_th_samples": 0.0,
            "digraph_he_latency_mean": 0.0,
            "digraph_he_latency_std": 0.0,
            "digraph_he_latency_median": 0.0,
            "digraph_he_latency_p95": 0.0,
            "digraph_he_samples": 0.0,
            "digraph_in_latency_mean": 0.0,
            "digraph_in_latency_std": 0.0,
            "digraph_in_latency_median": 0.0,
            "digraph_in_latency_p95": 0.0,
            "digraph_in_samples": 0.0,
            "digraph_latency_mean": 0.0,
            "digraph_latency_std": 0.0,
            "digraph_latency_median": 0.0,
            "digraph_latency_p95": 0.0,
            "shortcut_ctrl_v_latency_mean": 0.0,
            "shortcut_ctrl_v_latency_std": 0.0,
            "shortcut_ctrl_v_latency_median": 0.0,
            "shortcut_ctrl_v_latency_p95": 0.0,
            "shortcut_ctrl_v_count": 0.0,
            "deletion_backspace_ratio": 0.0,
            "deletion_delete_ratio": 0.0,
            "deletion_selection_ratio": 0.0,
            "selection_then_delete_ratio": 0.0,
            "backspace_delete_ratio": 0.0,
            "deletion_strategy_entropy": 0.0,
        }

    def extract_eye_features(self, eye_data):
        """Extract gaze kinematics, saccade dynamics, and blinking patterns."""
        if not eye_data:
            return self.get_default_eye_features()

        ordered = sorted(
            [e for e in eye_data if "timestamp" in e],
            key=lambda e: e.get("timestamp", 0),
        )
        if len(ordered) < 5:
            return self.get_default_eye_features()

        features = {}
        
        # Movement Kinematics (similar to mouse but specific to gaze)
        gaze_events = [e for e in ordered if "x" in e and "y" in e and not e.get("isBlink")]
        blink_events = [e for e in ordered if e.get("isBlink")]

        velocities = []
        accelerations = []
        jerks = []
        path_distance = 0.0

        if len(gaze_events) > 1:
            segments = []
            for i in range(1, len(gaze_events)):
                prev = gaze_events[i-1]
                cur = gaze_events[i]
                dt = float(cur["timestamp"]) - float(prev["timestamp"])
                if dt <= 0: continue
                
                dx = float(cur["x"]) - float(prev["x"])
                dy = float(cur["y"]) - float(prev["y"])
                dist = np.hypot(dx, dy)
                path_distance += dist
                
                speed = dist / dt
                if np.isfinite(speed):
                    velocities.append(float(speed))
                    segments.append({"dt": dt, "speed": speed, "vx": dx/dt, "vy": dy/dt})

            acceleration_vectors = []
            for i in range(1, len(segments)):
                prev = segments[i-1]
                cur = segments[i]
                dt = max(float(cur["dt"]), 1e-6)
                ax = (cur["vx"] - prev["vx"]) / dt
                ay = (cur["vy"] - prev["vy"]) / dt
                accel = np.hypot(ax, ay)
                if np.isfinite(accel):
                    accelerations.append(float(accel))
                    acceleration_vectors.append({"dt": dt, "ax": ax, "ay": ay})

            for i in range(1, len(acceleration_vectors)):
                prev = acceleration_vectors[i-1]
                cur = acceleration_vectors[i]
                dt = max(float(cur["dt"]), 1e-6)
                jx = (cur["ax"] - prev["ax"]) / dt
                jy = (cur["ay"] - prev["ay"]) / dt
                jerk = np.hypot(jx, jy)
                if np.isfinite(jerk):
                    jerks.append(float(jerk))

        features.update(self._safe_stats(velocities, "gaze_velocity"))
        features.update(self._safe_stats(accelerations, "gaze_acceleration"))
        features.update(self._safe_stats(jerks, "gaze_jerk"))
        
        # Blink Dynamics
        duration_ms = max(1.0, float(ordered[-1]["timestamp"]) - float(ordered[0]["timestamp"]))
        features["blink_rate"] = float(len(blink_events) * 60000.0 / duration_ms) # blinks per minute
        
        blink_durations = [float(e.get("blinkDuration", 0)) for e in blink_events if e.get("blinkDuration") is not None]
        features.update(self._safe_stats(blink_durations, "blink_duration"))
        
        # Gaze Stability (Fixation)
        if gaze_events:
            x_coords = [float(e["x"]) for e in gaze_events]
            y_coords = [float(e["y"]) for e in gaze_events]
            features["gaze_stability_x"] = float(np.std(x_coords))
            features["gaze_stability_y"] = float(np.std(y_coords))
            features["gaze_dispersion"] = float(np.sqrt(np.var(x_coords) + np.var(y_coords)))
        else:
            features["gaze_stability_x"] = 0.0
            features["gaze_stability_y"] = 0.0
            features["gaze_dispersion"] = 0.0

        features["eye_events_count"] = float(len(ordered))
        features["gaze_path_length"] = float(path_distance)
        
        return features

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
            "tangential_acceleration_mean": 0.0,
            "tangential_acceleration_std": 0.0,
            "tangential_acceleration_median": 0.0,
            "tangential_acceleration_p95": 0.0,
            "curvature_mean": 0.0,
            "curvature_std": 0.0,
            "curvature_median": 0.0,
            "curvature_p95": 0.0,
            "jerk_mean": 0.0,
            "jerk_std": 0.0,
            "jerk_median": 0.0,
            "jerk_p95": 0.0,
            "movement_efficiency": 0.0,
            "path_length": 0.0,
            "path_directness_ratio": 0.0,
            "path_curvature_deviation_mean": 0.0,
            "path_curvature_deviation_std": 0.0,
            "path_curvature_deviation_median": 0.0,
            "path_curvature_deviation_p95": 0.0,
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

    def get_default_eye_features(self):
        return {
            "gaze_velocity_mean": 0.0,
            "gaze_velocity_std": 0.0,
            "gaze_velocity_median": 0.0,
            "gaze_velocity_p95": 0.0,
            "gaze_acceleration_mean": 0.0,
            "gaze_acceleration_std": 0.0,
            "gaze_acceleration_median": 0.0,
            "gaze_acceleration_p95": 0.0,
            "gaze_jerk_mean": 0.0,
            "gaze_jerk_std": 0.0,
            "gaze_jerk_median": 0.0,
            "gaze_jerk_p95": 0.0,
            "blink_rate": 0.0,
            "blink_duration_mean": 0.0,
            "blink_duration_std": 0.0,
            "blink_duration_median": 0.0,
            "blink_duration_p95": 0.0,
            "gaze_stability_x": 0.0,
            "gaze_stability_y": 0.0,
            "gaze_dispersion": 0.0,
            "eye_events_count": 0.0,
            "gaze_path_length": 0.0,
        }
