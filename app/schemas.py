from pydantic import BaseModel, Field


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class LoginPayload(Credentials):
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class BehavioralProfilePayload(BaseModel):
    user_id: int = Field(gt=0)
    session_id: str = Field(min_length=1, max_length=256)
    keystroke_data: list[dict] = Field(default_factory=list)
    mouse_data: list[dict] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


class QueryPayload(BaseModel):
    query: str = Field(min_length=1)
    session_id: str | None = Field(default=None, max_length=256)
    context: dict | None = None


class QueryResult(BaseModel):
    success: bool
    answer: str
    confidence: float = Field(ge=0.0, le=1.0)
    session_id: str | None = None


class UploadResult(BaseModel):
    success: bool
    filename: str
    content_type: str
    size_bytes: int
    stored_at: str


class UserInfo(BaseModel):
    id: int
    username: str
    role: str = "user"
    created_at: str | None = None
    last_login: str | None = None
    is_active: int


class UserResult(BaseModel):
    success: bool
    user: UserInfo


class BehavioralHistoryItem(BaseModel):
    session_id: str
    risk_score: float | None = None
    timestamp: str


class BehavioralHistoryResult(BaseModel):
    success: bool
    history: list[BehavioralHistoryItem]


class RoleUpdatePayload(BaseModel):
    role: str = Field(pattern="^(user|analyst|admin)$")
