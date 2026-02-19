import asyncio
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, FastAPI, File, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import get_db
from app.security import create_access_token
from app.schemas import (
    BehavioralHistoryResult,
    BehavioralProfilePayload,
    Credentials,
    LoginPayload,
    QueryPayload,
    QueryResult,
    UploadResult,
    UserResult,
)

settings = get_settings()
db = get_db()
app = FastAPI(title=settings.app_name)
router = APIRouter()

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def route_aliases(paths: list[str], **kwargs):
    def decorator(func):
        for path in paths:
            router.add_api_route(path, func, **kwargs)
        return func

    return decorator


def _is_blocked_error(message: str | None) -> bool:
    text = (message or "").lower()
    return "disabled" in text or "blocked" in text


def _ensure_username_not_blocked(username: str) -> None:
    if db.is_user_blocked(username):
        raise HTTPException(status_code=403, detail="Account is blocked due to behavioral anomaly detection.")


def _ensure_user_id_not_blocked(user_id: int) -> None:
    if db.is_user_id_blocked(user_id):
        raise HTTPException(status_code=403, detail="Account is blocked due to behavioral anomaly detection.")


@route_aliases(["/health", "/api/health", "/api/v1/health"], methods=["GET"], tags=["health"])
async def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "environment": settings.app_env}


@route_aliases(["/query", "/api/query", "/api/v1/query"], methods=["POST"], response_model=QueryResult, tags=["agent"])
async def query_agent(payload: QueryPayload) -> dict:
    text = payload.query.lower()
    intent = "risk_analysis" if ("risk" in text or "anomaly" in text) else "session_tracking" if "session" in text else "general"
    return {
        "success": True,
        "answer": f"Intent: {intent}. Processed query with {len(payload.context or {})} context fields.",
        "confidence": 0.72,
        "session_id": payload.session_id,
    }


@route_aliases(["/upload", "/api/upload", "/api/v1/upload"], methods=["POST"], response_model=UploadResult, tags=["agent"])
async def upload_file(file: UploadFile = File(...)) -> dict:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 10MB limit")

    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(file.filename).name
    destination = upload_dir / safe_name
    await asyncio.to_thread(destination.write_bytes, raw)

    return {
        "success": True,
        "filename": safe_name,
        "content_type": file.content_type or "application/octet-stream",
        "size_bytes": len(raw),
        "stored_at": datetime.now(timezone.utc).isoformat(),
    }


@route_aliases(
    ["/register", "/api/register", "/api/v1/register"],
    methods=["POST"],
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
)
async def register(payload: Credentials) -> dict:
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")

    result = await asyncio.to_thread(db.create_user, payload.username, payload.password)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Registration failed"))

    return {
        "success": True,
        "message": "User registered successfully",
        "user_id": result["user_id"],
        "username": result["username"],
    }


@route_aliases(["/start-session", "/api/start-session", "/api/v1/start-session"], methods=["POST"], tags=["auth"])
async def start_session(payload: Credentials) -> dict:
    _ensure_username_not_blocked(payload.username)
    result = await asyncio.to_thread(db.get_or_create_user, payload.username, payload.password)
    if not result.get("success"):
        if _is_blocked_error(result.get("error")):
            raise HTTPException(status_code=403, detail=result.get("error", "User blocked"))
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to start session"))
    access_token, expires_at = create_access_token(settings, result["username"], result["user_id"])
    result["access_token"] = access_token
    result["token_type"] = "bearer"
    result["expires_at"] = expires_at
    return result


@route_aliases(["/login", "/api/login", "/api/v1/login"], methods=["POST"], tags=["auth"])
async def login(payload: LoginPayload, request: Request) -> dict:
    _ensure_username_not_blocked(payload.username)
    result = await asyncio.to_thread(db.verify_user, payload.username, payload.password)
    client_ip = request.client.host if request.client else None
    await asyncio.to_thread(db.log_login_attempt, payload.username, int(result.get("success", False)), payload.risk_score, client_ip)

    if result.get("success") and payload.risk_score > settings.high_risk_threshold:
        raise HTTPException(status_code=403, detail="High behavioral risk detected. Additional authentication required.")
    if not result.get("success"):
        if _is_blocked_error(result.get("error")):
            raise HTTPException(status_code=403, detail=result.get("error", "User blocked"))
        raise HTTPException(status_code=401, detail=result.get("error", "Invalid credentials"))
    access_token, expires_at = create_access_token(settings, result["username"], result["user_id"])

    return {
        "success": True,
        "message": "Login successful",
        "user_id": result["user_id"],
        "username": result["username"],
        "risk_score": payload.risk_score,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
    }


@route_aliases(["/behavioral-profile", "/api/behavioral-profile", "/api/v1/behavioral-profile"], methods=["POST"], tags=["auth"])
async def save_behavioral_profile(payload: BehavioralProfilePayload) -> dict:
    _ensure_user_id_not_blocked(payload.user_id)
    result = await asyncio.to_thread(
        db.save_behavioral_profile,
        payload.user_id,
        payload.session_id,
        payload.keystroke_data,
        payload.mouse_data,
        payload.risk_score,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to save behavioral profile"))
    return {"success": True, "message": "Behavioral profile saved successfully"}


@route_aliases(["/user/{username}", "/api/user/{username}", "/api/v1/user/{username}"], methods=["GET"], response_model=UserResult, tags=["auth"])
async def get_user(username: str) -> dict:
    result = await asyncio.to_thread(db.get_user, username)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "User not found"))
    return result


@route_aliases(
    [
        "/user/{user_id}/behavioral-history",
        "/api/user/{user_id}/behavioral-history",
        "/api/v1/user/{user_id}/behavioral-history",
    ],
    methods=["GET"],
    response_model=BehavioralHistoryResult,
    tags=["auth"],
)
async def behavioral_history(user_id: int, limit: int = Query(default=10, ge=1)) -> dict:
    bounded_limit = min(limit, settings.max_behavior_history_limit)
    result = await asyncio.to_thread(db.get_behavioral_history, user_id, bounded_limit)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch behavioral history"))
    return result


app.include_router(router)

frontend_dir = Path(settings.frontend_dir)
if frontend_dir.exists():
    for route in ("dashboard", "collector", "login", "calibration"):
        mount_path = frontend_dir / route
        if mount_path.exists():
            app.mount(f"/{route}", StaticFiles(directory=str(mount_path)), name=route)


@app.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login/login.html", status_code=302)
