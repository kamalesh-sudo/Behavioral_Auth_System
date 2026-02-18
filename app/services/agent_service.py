import asyncio
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings


class AgentService:
    def __init__(self, settings: Settings):
        self.settings = settings

    async def query(self, prompt: str, session_id: str | None, context: dict | None) -> dict:
        # Placeholder async AI-agent response while preserving a backend focus for security workflows.
        lowered = prompt.lower()
        intent = "general"
        if "risk" in lowered or "anomaly" in lowered:
            intent = "risk_analysis"
        elif "session" in lowered:
            intent = "session_tracking"

        answer = (
            f"Intent: {intent}. "
            f"Processed query for behavioral-auth workflow with {len(context or {})} context fields."
        )

        await asyncio.sleep(0)
        return {
            "success": True,
            "answer": answer,
            "confidence": 0.72,
            "session_id": session_id,
        }

    async def save_upload(self, filename: str, content_type: str | None, payload: bytes) -> dict:
        upload_dir = Path(self.settings.upload_dir)
        upload_dir.mkdir(parents=True, exist_ok=True)

        safe_name = Path(filename).name
        destination = upload_dir / safe_name
        await asyncio.to_thread(destination.write_bytes, payload)

        return {
            "success": True,
            "filename": safe_name,
            "content_type": content_type or "application/octet-stream",
            "size_bytes": len(payload),
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
