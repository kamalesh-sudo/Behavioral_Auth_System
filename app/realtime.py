import json
import logging
import os
import asyncio
from collections import deque
from datetime import datetime, timezone

import anyio
from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from app.alerts import send_security_alert
from app.config import Settings
from app.database import AuthDatabase
from app.security import verify_access_token
from backend.ml.behavioral_analyzer import BehavioralAnalyzer


AUTH_TOKEN = os.environ.get("AUTH_TOKEN")


class RealtimeBehaviorService:
    def __init__(self, settings: Settings, db: AuthDatabase):
        self.settings = settings
        self.db = db
        self.analyzer = BehavioralAnalyzer()
        self.analyzer.load_models()
        self.user_sessions: dict[str, dict] = {}
        self.connection_auth: dict[WebSocket, dict] = {}
        self.logger = logging.getLogger("behavioral.realtime")
        self.metrics = {
            "connections_total": 0,
            "connections_active": 0,
            "auth_success": 0,
            "auth_failed": 0,
            "messages_total": 0,
            "messages_behavioral": 0,
            "messages_feedback": 0,
            "messages_user_auth": 0,
            "anomalies_blocked": 0,
        }
        self.recent_events: deque[dict] = deque(maxlen=200)
        self.last_global_train_at: datetime | None = None
        self.last_global_train_count: int = 0
        self._analyzer_lock = asyncio.Lock()

    @staticmethod
    def _extract_ws_ip(websocket: WebSocket) -> str | None:
        forwarded_for = websocket.headers.get("x-forwarded-for")
        if forwarded_for:
            first = forwarded_for.split(",")[0].strip()
            if first:
                return first
        client = websocket.client
        return client.host if client else None

    @staticmethod
    def _extract_device_fingerprint(data: dict) -> str | None:
        context = data.get("context") if isinstance(data.get("context"), dict) else {}
        fingerprint = (
            context.get("device_fingerprint")
            or context.get("deviceFingerprint")
            or data.get("device_fingerprint")
            or data.get("deviceFingerprint")
        )
        if not fingerprint:
            return None
        value = str(fingerprint).strip()
        return value or None

    async def handle_client(self, websocket: WebSocket) -> None:
        await websocket.accept()
        client = websocket.client
        remote = f"{client.host}:{client.port}" if client else "unknown"
        client_ip = self._extract_ws_ip(websocket)
        if self.db.is_ip_blocked(client_ip):
            self._record_event("ws_rejected_ip_blocked", ip_address=client_ip, remote=remote)
            await websocket.close(code=1008, reason="IP blocked")
            return
        self.metrics["connections_total"] += 1
        self.metrics["connections_active"] += 1
        self._record_event("ws_connected", remote=remote)
        try:
            claims = await self._authenticate_connection(websocket)
            self.connection_auth[websocket] = claims
            self.metrics["auth_success"] += 1
            self._record_event(
                "ws_authenticated",
                username=claims.get("sub"),
                user_id=claims.get("user_id"),
                remote=remote,
            )
            while True:
                message = await websocket.receive_text()
                await self._process_message(websocket, message)
        except WebSocketDisconnect:
            self._record_event("ws_disconnected", remote=remote)
        finally:
            self.connection_auth.pop(websocket, None)
            self.metrics["connections_active"] = max(0, self.metrics["connections_active"] - 1)

    async def _authenticate_connection(self, websocket: WebSocket) -> dict:
        auth_message = await websocket.receive_text()
        try:
            auth_data = json.loads(auth_message)
        except json.JSONDecodeError:
            self.metrics["auth_failed"] += 1
            self._record_event("ws_auth_failed", reason="invalid_json")
            await websocket.close(code=1008, reason="Authentication failed")
            raise WebSocketDisconnect

        token = (auth_data.get("token") or "").strip()
        if not token:
            self.metrics["auth_failed"] += 1
            self._record_event("ws_auth_failed", reason="missing_token")
            await websocket.close(code=1008, reason="Authentication token missing")
            raise WebSocketDisconnect
        try:
            claims = verify_access_token(token, self.settings)
        except (ValueError, RuntimeError):
            if not AUTH_TOKEN or token != AUTH_TOKEN:
                self.metrics["auth_failed"] += 1
                self._record_event("ws_auth_failed", reason="invalid_token")
                await websocket.close(code=1008, reason="Invalid authentication token")
                raise WebSocketDisconnect
            claims = {"sub": None, "user_id": None}
        return claims

    async def _process_message(self, websocket: WebSocket, message: str) -> None:
        self.metrics["messages_total"] += 1
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            self._record_event("ws_message_invalid", reason="invalid_json")
            await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON format"}))
            return

        message_type = data.get("type")
        claimed_user = data.get("userId")
        auth_user = self.connection_auth.get(websocket, {}).get("sub")
        if auth_user and claimed_user and auth_user != claimed_user:
            self._record_event("ws_user_mismatch", auth_user=auth_user, claimed_user=claimed_user)
            await websocket.close(code=1008, reason="User mismatch for authenticated token")
            return

        if message_type == "behavioral_data":
            self.metrics["messages_behavioral"] += 1
            await self._handle_behavioral_data(websocket, data)
        elif message_type == "user_authentication":
            self.metrics["messages_user_auth"] += 1
            await self._handle_user_authentication(websocket, data)
        elif message_type == "feedback":
            self.metrics["messages_feedback"] += 1
            await self._handle_feedback(websocket, data)
        else:
            self._record_event("ws_message_unknown", message_type=message_type)

    async def _handle_behavioral_data(self, websocket: WebSocket, data: dict) -> None:
        username = data.get("userId") or self.connection_auth.get(websocket, {}).get("sub")
        session_id = data.get("sessionId")
        keystroke_data = data.get("keystrokeData", [])
        mouse_data = data.get("mouseData", [])
        eye_data = data.get("eyeData", [])
        context = data.get("context") if isinstance(data.get("context"), dict) else None
        client_ip = self._extract_ws_ip(websocket)
        device_fingerprint = self._extract_device_fingerprint(data)
        if not username or not session_id:
            self._record_event(
                "behavioral_rejected",
                reason="missing_identity_or_session",
                username=username,
                session_id=session_id,
            )
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "error",
                        "message": "Missing required fields: userId/sessionId",
                    }
                )
            )
            return

        if self.db.is_ip_blocked(client_ip):
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="IP address is blocked by security policy",
            )
            return
        if self.db.is_device_fingerprint_blocked(device_fingerprint):
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="Device is blocked by security policy",
            )
            return
        self._record_event(
            "behavioral_received",
            username=username,
            session_id=session_id,
            ip_address=client_ip,
            keystrokes=len(keystroke_data),
            mouse=len(mouse_data),
            eye=len(eye_data),
        )

        if self.db.is_user_blocked(username):
            self.db.log_security_event(
                username=username,
                event_type="BLOCKED_USER_ACTIVITY",
                reason="Blocked user attempted behavioral_data",
                session_id=session_id,
                risk_score=1.0,
            )
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="User account is blocked due to behavioral anomaly detection",
            )
            return

        debug_requested = bool(
            self.settings.debug_model_io
            or (isinstance(context, dict) and bool(context.get("debug_model_io")))
        )
        async with self._analyzer_lock:
            risk_score, risk_explanation, model_io = await anyio.to_thread.run_sync(
                self._analyze_behavior_window_sync,
                keystroke_data,
                mouse_data,
                eye_data,
                username,
                context,
                debug_requested,
            )
        self._record_event(
            "behavioral_scored",
            username=username,
            session_id=session_id,
            risk_score=round(float(risk_score), 4),
            reason=risk_explanation.get("reason"),
        )
        self.user_sessions[session_id] = {
            "username": username,
            "websocket": websocket,
            "last_activity": datetime.now(timezone.utc),
            "risk_score": risk_score,
        }

        user_info = self.db.get_user(username)
        if user_info.get("success"):
            self.db.save_behavioral_profile(
                user_info["user"]["id"], session_id, keystroke_data, mouse_data, eye_data, risk_score
            )

        if risk_score >= self.settings.anomaly_block_threshold:
            reason = "Behavioral anomaly detected in real-time monitoring"
            self.metrics["anomalies_blocked"] += 1
            self._record_event(
                "behavioral_blocked",
                username=username,
                session_id=session_id,
                risk_score=round(float(risk_score), 4),
                threshold=self.settings.anomaly_block_threshold,
            )
            self.db.block_user(username, session_id, risk_score, reason)
            if client_ip:
                self.db.block_ip(
                    client_ip,
                    reason=f"Realtime anomaly block for user {username}",
                    blocked_by="system",
                    duration_minutes=120,
                )
            if device_fingerprint:
                self.db.block_device_fingerprint(
                    device_fingerprint,
                    reason=f"Realtime anomaly block for user {username}",
                    blocked_by="system",
                )
            self.db.log_security_event(
                username=username,
                event_type="REALTIME_ANOMALY_BLOCK",
                reason=reason,
                session_id=session_id,
                risk_score=risk_score,
            )
            send_security_alert(
                {
                    "event_type": "REALTIME_ANOMALY_BLOCK",
                    "username": username,
                    "session_id": session_id,
                    "risk_score": risk_score,
                    "reason": reason,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            await self._terminate_session(session_id, username, risk_score, reason)
            return

        response = {
            "type": "analysis_result",
            "sessionId": session_id,
            "effectiveUser": username,
            "riskScore": risk_score,
            "riskExplanation": risk_explanation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if debug_requested:
            response["modelIO"] = model_io
        if risk_score > self.settings.high_risk_threshold:
            response["alert"] = {
                "level": "HIGH",
                "message": "Unusual behavioral patterns detected",
                "recommended_action": "Require additional authentication",
            }
        elif risk_score > 0.5:
            response["alert"] = {"level": "MEDIUM", "message": "Behavioral patterns slightly deviate from norm"}

        await websocket.send_text(json.dumps(response))

    async def _handle_user_authentication(self, websocket: WebSocket, data: dict) -> None:
        username = data.get("userId") or self.connection_auth.get(websocket, {}).get("sub")
        session_id = data.get("sessionId")
        client_ip = self._extract_ws_ip(websocket)
        device_fingerprint = self._extract_device_fingerprint(data)
        if not username or not session_id:
            self._record_event(
                "user_auth_rejected",
                reason="missing_identity_or_session",
                username=username,
                session_id=session_id,
            )
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "error",
                        "message": "Missing required fields: userId/sessionId",
                    }
                )
            )
            return
        self._record_event("user_auth_message", username=username, session_id=session_id)

        if self.db.is_ip_blocked(client_ip):
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="IP address is blocked by security policy",
            )
            return
        if self.db.is_device_fingerprint_blocked(device_fingerprint):
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="Device is blocked by security policy",
            )
            return

        if self.db.is_user_blocked(username):
            self.db.log_security_event(
                username=username,
                event_type="BLOCKED_USER_AUTH_ATTEMPT",
                reason="Blocked user attempted user_authentication",
                session_id=session_id,
                risk_score=1.0,
            )
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="User account is blocked due to behavioral anomaly detection",
            )
            return

        profile_created = False
        async with self._analyzer_lock:
            if username not in self.analyzer.user_profiles:
                self.analyzer.create_user_profile(username, {"keystrokeData": [], "mouseData": [], "eyeData": []})
                profile_created = True
            profile = self.analyzer.user_profiles.get(username, {})
            profile_model_trained = bool(profile.get("is_model_trained"))
            profile_samples = len(self.analyzer.user_feature_history.get(username, []))
        user_info = self.db.get_user(username)
        if user_info.get("success") and device_fingerprint:
            user_id = user_info["user"]["id"]
            known_device = self.db.is_known_user_device(user_id, device_fingerprint)
            self.db.register_user_device(user_id, device_fingerprint, client_ip)
            if not known_device:
                self.db.log_security_event(
                    username=username,
                    event_type="NEW_DEVICE_WEBSOCKET",
                    reason=f"New websocket device seen (ip={client_ip or 'unknown'})",
                    session_id=session_id,
                )
        self._record_event(
            "profile_state",
            username=username,
            session_id=session_id,
            created=profile_created,
            model_trained=profile_model_trained,
            samples=profile_samples,
        )

        await websocket.send_text(json.dumps({"type": "authentication_success", "userId": username}))

    async def _handle_feedback(self, websocket: WebSocket, data: dict) -> None:
        username = data.get("userId") or self.connection_auth.get(websocket, {}).get("sub")
        session_id = data.get("sessionId")
        feedback = data.get("feedback")
        behavioral_data = data.get("behavioralData")
        if not username or not session_id:
            self._record_event(
                "feedback_rejected",
                reason="missing_identity_or_session",
                username=username,
                session_id=session_id,
            )
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "error",
                        "message": "Missing required fields: userId/sessionId",
                    }
                )
            )
            return

        if self.db.is_user_blocked(username):
            self.db.log_security_event(
                username=username,
                event_type="BLOCKED_USER_FEEDBACK",
                reason="Blocked user attempted feedback",
                session_id=session_id,
                risk_score=1.0,
            )
            await self._terminate_session(
                session_id=session_id,
                username=username,
                risk_score=1.0,
                reason="User account is blocked due to behavioral anomaly detection",
            )
            return

        async with self._analyzer_lock:
            await anyio.to_thread.run_sync(self.analyzer.update_user_profile, username, behavioral_data, feedback)
            profile = self.analyzer.user_profiles.get(username, {})
            profile_model_trained = bool(profile.get("is_model_trained"))
            profile_samples = len(self.analyzer.user_feature_history.get(username, []))
        self._record_event(
            "profile_updated",
            username=username,
            session_id=session_id,
            feedback=feedback,
            model_trained=profile_model_trained,
            samples=profile_samples,
        )
        await websocket.send_text(json.dumps({"type": "feedback_received", "message": "User profile updated"}))

    def _analyze_behavior_window_sync(
        self,
        keystroke_data: list[dict],
        mouse_data: list[dict],
        eye_data: list[dict],
        username: str,
        context: dict | None,
        debug_requested: bool,
    ) -> tuple[float, dict, dict]:
        risk_score = self.analyzer.analyze_real_time(keystroke_data, mouse_data, eye_data, username, context=context)
        risk_explanation = self.analyzer.get_last_explanation(username)
        model_io = self.analyzer.get_last_debug_io(username) if debug_requested else {}
        return risk_score, risk_explanation, model_io

    async def _terminate_session(self, session_id: str, username: str, risk_score: float, reason: str) -> None:
        payload = {
            "type": "session_terminated",
            "sessionId": session_id,
            "userId": username,
            "riskScore": risk_score,
            "reason": reason,
            "blocked": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        ws = self.user_sessions.get(session_id, {}).get("websocket")
        if ws:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                await ws.close(code=1008, reason="Session terminated due to behavioral anomaly")
            except Exception:  # pylint: disable=broad-except
                pass
        self._record_event(
            "session_terminated",
            username=username,
            session_id=session_id,
            risk_score=round(float(risk_score), 4),
            reason=reason,
        )
        self.user_sessions.pop(session_id, None)

    async def train_global_from_db(self) -> None:
        limit = max(1, int(self.settings.global_train_max_samples))
        result = self.db.get_behavioral_training_data(limit=limit)
        if not result.get("success"):
            self._record_event("global_train_failed", reason=result.get("error", "db_error"))
            return
        dataset = result.get("dataset") or []
        if len(dataset) < int(self.settings.global_train_min_samples):
            self._record_event(
                "global_train_skipped",
                reason="insufficient_samples",
                samples=len(dataset),
                min_samples=int(self.settings.global_train_min_samples),
            )
            return
        if len(dataset) == self.last_global_train_count:
            self._record_event("global_train_skipped", reason="no_new_data", samples=len(dataset))
            return
        try:
            await asyncio.to_thread(self.analyzer.train_global_model, dataset)
            self.last_global_train_at = datetime.now(timezone.utc)
            self.last_global_train_count = len(dataset)
            self._record_event(
                "global_train_completed",
                samples=len(dataset),
                trained_at=self.last_global_train_at.isoformat(),
            )
        except Exception as exc:  # pylint: disable=broad-except
            self._record_event("global_train_failed", reason=str(exc))

    async def auto_train_loop(self) -> None:
        interval = max(30, int(self.settings.global_train_interval_seconds))
        while True:
            await self.train_global_from_db()
            await asyncio.sleep(interval)

    def _record_event(self, event_type: str, **fields) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **fields,
        }
        self.recent_events.appendleft(event)
        self.logger.info("realtime_event %s", json.dumps(event, default=str))

    def get_monitor_snapshot(self) -> dict:
        trained_profiles = sum(
            1
            for profile in self.analyzer.user_profiles.values()
            if profile.get("is_model_trained")
        )
        return {
            "metrics": dict(self.metrics),
            "runtime": {
                "sessions_active": len(self.user_sessions),
                "profiles_total": len(self.analyzer.user_profiles),
                "profiles_trained": trained_profiles,
                "global_model_trained": bool(self.analyzer.is_trained),
                "global_last_train_at": self.last_global_train_at.isoformat() if self.last_global_train_at else None,
                "global_last_train_samples": self.last_global_train_count,
            },
            "recent_events": list(self.recent_events)[:50],
        }
