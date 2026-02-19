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


class ProjectCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class TaskCreatePayload(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    status: str = Field(default="todo", pattern="^(todo|in_progress|review|done)$")
    priority: str = Field(default="medium", pattern="^(low|medium|high)$")
    assignee_username: str | None = Field(default=None, max_length=128)
    due_date: str | None = Field(default=None, max_length=64)


class TaskUpdatePayload(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    status: str | None = Field(default=None, pattern="^(todo|in_progress|review|done)$")
    priority: str | None = Field(default=None, pattern="^(low|medium|high)$")
    assignee_username: str | None = Field(default=None, max_length=128)
    due_date: str | None = Field(default=None, max_length=64)
