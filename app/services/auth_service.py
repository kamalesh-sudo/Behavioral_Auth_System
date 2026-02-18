import asyncio

from app.db.user_db import UserDatabase


class AuthService:
    def __init__(self, db: UserDatabase, high_risk_threshold: float):
        self.db = db
        self.high_risk_threshold = high_risk_threshold

    async def register(self, username: str, password: str) -> dict:
        return await asyncio.to_thread(self.db.create_user, username, password)

    async def start_session(self, username: str, password: str) -> dict:
        return await asyncio.to_thread(self.db.get_or_create_user, username, password)

    async def login(self, username: str, password: str, risk_score: float, ip_address: str | None) -> dict:
        result = await asyncio.to_thread(self.db.verify_user, username, password, ip_address)
        await asyncio.to_thread(self.db.log_login_attempt, username, int(result.get("success", False)), risk_score, ip_address)

        if result.get("success") and risk_score > self.high_risk_threshold:
            return {
                "success": False,
                "error": "High behavioral risk detected. Additional authentication required.",
                "risk_score": risk_score,
                "requires_mfa": True,
            }

        if result.get("success"):
            return {
                "success": True,
                "message": "Login successful",
                "user_id": result["user_id"],
                "username": result["username"],
                "risk_score": risk_score,
            }

        return result

    async def save_behavioral_profile(
        self,
        user_id: int,
        session_id: str,
        keystroke_data: list[dict],
        mouse_data: list[dict],
        risk_score: float,
    ) -> dict:
        return await asyncio.to_thread(
            self.db.save_behavioral_profile,
            user_id,
            session_id,
            keystroke_data,
            mouse_data,
            risk_score,
        )

    async def get_user(self, username: str) -> dict:
        return await asyncio.to_thread(self.db.get_user_by_username, username)

    async def get_behavioral_history(self, user_id: int, limit: int) -> dict:
        return await asyncio.to_thread(self.db.get_user_behavioral_history, user_id, limit)
