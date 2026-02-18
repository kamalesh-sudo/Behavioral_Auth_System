from pydantic import BaseModel, Field


class CredentialsRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginRequest(CredentialsRequest):
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class BehavioralProfileRequest(BaseModel):
    user_id: int = Field(gt=0)
    session_id: str = Field(min_length=1, max_length=256)
    keystroke_data: list[dict] = Field(default_factory=list)
    mouse_data: list[dict] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class RegisterResponse(BaseModel):
    success: bool
    message: str
    user_id: int
    username: str


class SessionResponse(BaseModel):
    success: bool
    user_id: int
    username: str
    is_new: bool | None = None


class LoginResponse(BaseModel):
    success: bool
    message: str | None = None
    user_id: int | None = None
    username: str | None = None
    risk_score: float | None = None
    requires_mfa: bool | None = None
    error: str | None = None


class UserInfo(BaseModel):
    id: int
    username: str
    created_at: str | None = None
    last_login: str | None = None
    is_active: int


class UserResponse(BaseModel):
    success: bool
    user: UserInfo


class BehavioralHistoryItem(BaseModel):
    session_id: str
    risk_score: float | None = None
    timestamp: str


class BehavioralHistoryResponse(BaseModel):
    success: bool
    history: list[BehavioralHistoryItem]


class BehavioralProfileResponse(BaseModel):
    success: bool
    message: str
