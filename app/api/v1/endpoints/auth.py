from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.config import get_settings
from app.db.dependencies import get_user_db
from app.db.user_db import UserDatabase
from app.schemas.auth import (
    BehavioralHistoryResponse,
    BehavioralProfileRequest,
    BehavioralProfileResponse,
    CredentialsRequest,
    LoginRequest,
    LoginResponse,
    RegisterResponse,
    SessionResponse,
    UserResponse,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="", tags=["auth"])


def get_auth_service(db: UserDatabase = Depends(get_user_db)) -> AuthService:
    settings = get_settings()
    return AuthService(db=db, high_risk_threshold=settings.high_risk_threshold)


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
@router.post("/api/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
@router.post("/api/v1/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: CredentialsRequest, service: AuthService = Depends(get_auth_service)) -> dict:
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters long")

    result = await service.register(payload.username, payload.password)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Registration failed"))

    return {
        "success": True,
        "message": "User registered successfully",
        "user_id": result["user_id"],
        "username": result["username"],
    }


@router.post("/start-session", response_model=SessionResponse)
@router.post("/api/start-session", response_model=SessionResponse)
@router.post("/api/v1/start-session", response_model=SessionResponse)
async def start_session(payload: CredentialsRequest, service: AuthService = Depends(get_auth_service)) -> dict:
    result = await service.start_session(payload.username, payload.password)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to start session"))
    return result


@router.post("/login", response_model=LoginResponse)
@router.post("/api/login", response_model=LoginResponse)
@router.post("/api/v1/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    client_ip = request.client.host if request.client else None
    result = await service.login(payload.username, payload.password, payload.risk_score, client_ip)

    if result.get("requires_mfa"):
        raise HTTPException(status_code=403, detail=result["error"])
    if not result.get("success"):
        raise HTTPException(status_code=401, detail=result.get("error", "Invalid credentials"))

    return result


@router.post("/behavioral-profile", response_model=BehavioralProfileResponse)
@router.post("/api/behavioral-profile", response_model=BehavioralProfileResponse)
@router.post("/api/v1/behavioral-profile", response_model=BehavioralProfileResponse)
async def save_behavioral_profile(
    payload: BehavioralProfileRequest,
    service: AuthService = Depends(get_auth_service),
) -> dict:
    result = await service.save_behavioral_profile(
        payload.user_id,
        payload.session_id,
        payload.keystroke_data,
        payload.mouse_data,
        payload.risk_score,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to save behavioral profile"))

    return {"success": True, "message": "Behavioral profile saved successfully"}


@router.get("/user/{username}", response_model=UserResponse)
@router.get("/api/user/{username}", response_model=UserResponse)
@router.get("/api/v1/user/{username}", response_model=UserResponse)
async def get_user(username: str, service: AuthService = Depends(get_auth_service)) -> dict:
    result = await service.get_user(username)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "User not found"))
    return result


@router.get("/user/{user_id}/behavioral-history", response_model=BehavioralHistoryResponse)
@router.get("/api/user/{user_id}/behavioral-history", response_model=BehavioralHistoryResponse)
@router.get("/api/v1/user/{user_id}/behavioral-history", response_model=BehavioralHistoryResponse)
async def get_behavioral_history(
    user_id: int,
    limit: int = Query(default=10, ge=1),
    service: AuthService = Depends(get_auth_service),
) -> dict:
    bounded_limit = min(limit, get_settings().max_behavior_history_limit)
    result = await service.get_behavioral_history(user_id, bounded_limit)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch behavioral history"))
    return result
