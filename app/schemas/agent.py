from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    query: str = Field(min_length=1)
    session_id: str | None = Field(default=None, max_length=256)
    context: dict | None = None


class QueryResponse(BaseModel):
    success: bool
    answer: str
    confidence: float = Field(ge=0.0, le=1.0)
    session_id: str | None = None


class UploadResponse(BaseModel):
    success: bool
    filename: str
    content_type: str
    size_bytes: int
    stored_at: str
