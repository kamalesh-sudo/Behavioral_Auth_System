import json
import logging
import os
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

    async def handle_client(self, websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            claims = await self._authenticate_connection(websocket)
            self.connection_auth[websocket] = claims
            while True:
                message = await websocket.receive_text()
                await self._process_message(websocket, message)
        except WebSocketDisconnect:
            pass
        finally:
            self.connection_auth.pop(websocket, None)

    async def _authenticate_connection(self, websocket: WebSocket) -> dict:
        auth_message = await websocket.receive_text()
        try:
            auth_data = json.loads(auth_message)
        except json.JSONDecodeError:
            await websocket.close(code=1008, reason="Authentication failed")
            raise WebSocketDisconnect

        token = (auth_data.get("token") or "").strip()
        if not token:
            await websocket.close(code=1008, reason="Authentication token missing")
            raise WebSocketDisconnect
        try:
            claims = verify_access_token(token, self.settings)
        except (ValueError, RuntimeError):
            if not AUTH_TOKEN or token != AUTH_TOKEN:
                await websocket.close(code=1008, reason="Invalid authentication token")
                raise WebSocketDisconnect
            claims = {"sub": None, "user_id": None}
        return claims

    async def _process_message(self, websocket: WebSocket, message: str) -> None:
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON format"}))
            return

        message_type = data.get("type")
        claimed_user = data.get("userId")
        auth_user = self.connection_auth.get(websocket, {}).get("sub")
        if auth_user and claimed_user and auth_user != claimed_user:
            await websocket.close(code=1008, reason="User mismatch for authenticated token")
            return

        if message_type == "behavioral_data":
            await self._handle_behavioral_data(websocket, data)
        elif message_type == "user_authentication":
            await self._handle_user_authentication(websocket, data)
        elif message_type == "feedback":
            await self._handle_feedback(websocket, data)

    async def _handle_behavioral_data(self, websocket: WebSocket, data: dict) -> None:
        username = data.get("userId")
        session_id = data.get("sessionId")
        keystroke_data = data.get("keystrokeData", [])
        mouse_data = data.get("mouseData", [])

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
        logging.info("User authentication received: userId=%s, sessionId=%s", username, session_id)

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

        if username not in self.analyzer.user_profiles:
            self.analyzer.create_user_profile(username, {"keystrokeData": [], "mouseData": []})

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
        self.user_sessions.pop(session_id, None)
