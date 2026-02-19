import json
import logging
import os
from collections import deque
from datetime import datetime, timezone

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

    async def handle_client(self, websocket: WebSocket) -> None:
        await websocket.accept()
        client = websocket.client
        remote = f"{client.host}:{client.port}" if client else "unknown"
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
        username = data.get("userId")
        session_id = data.get("sessionId")
        keystroke_data = data.get("keystrokeData", [])
        mouse_data = data.get("mouseData", [])
        self._record_event(
            "behavioral_received",
            username=username,
            session_id=session_id,
            keystrokes=len(keystroke_data),
            mouse=len(mouse_data),
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

        risk_score = self.analyzer.analyze_real_time(keystroke_data, mouse_data, username)
        risk_explanation = self.analyzer.get_last_explanation(username)
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
                user_info["user"]["id"], session_id, keystroke_data, mouse_data, risk_score
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
            "riskScore": risk_score,
            "riskExplanation": risk_explanation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
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
        username = data.get("userId")
        session_id = data.get("sessionId")
        self._record_event("user_auth_message", username=username, session_id=session_id)

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
        if username not in self.analyzer.user_profiles:
            self.analyzer.create_user_profile(username, {"keystrokeData": [], "mouseData": []})
            profile_created = True
        profile = self.analyzer.user_profiles.get(username, {})
        self._record_event(
            "profile_state",
            username=username,
            session_id=session_id,
            created=profile_created,
            model_trained=bool(profile.get("is_model_trained")),
            samples=len(self.analyzer.user_feature_history.get(username, [])),
        )

        await websocket.send_text(json.dumps({"type": "authentication_success", "userId": username}))

    async def _handle_feedback(self, websocket: WebSocket, data: dict) -> None:
        username = data.get("userId")
        session_id = data.get("sessionId")
        feedback = data.get("feedback")
        behavioral_data = data.get("behavioralData")

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

        self.analyzer.update_user_profile(username, behavioral_data, feedback)
        profile = self.analyzer.user_profiles.get(username, {})
        self._record_event(
            "profile_updated",
            username=username,
            session_id=session_id,
            feedback=feedback,
            model_trained=bool(profile.get("is_model_trained")),
            samples=len(self.analyzer.user_feature_history.get(username, [])),
        )
        await websocket.send_text(json.dumps({"type": "feedback_received", "message": "User profile updated"}))

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
            },
            "recent_events": list(self.recent_events)[:50],
        }
