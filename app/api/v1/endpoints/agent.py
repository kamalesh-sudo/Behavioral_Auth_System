from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from app.core.config import Settings, get_settings
from app.schemas.agent import QueryRequest, QueryResponse, UploadResponse
from app.services.agent_service import AgentService

router = APIRouter(tags=["agent"])


def get_agent_service(settings: Settings = Depends(get_settings)) -> AgentService:
    return AgentService(settings=settings)


@router.post("/query", response_model=QueryResponse)
@router.post("/api/query", response_model=QueryResponse)
@router.post("/api/v1/query", response_model=QueryResponse)
async def query(payload: QueryRequest, service: AgentService = Depends(get_agent_service)) -> dict:
    return await service.query(payload.query, payload.session_id, payload.context)


@router.post("/upload", response_model=UploadResponse)
@router.post("/api/upload", response_model=UploadResponse)
@router.post("/api/v1/upload", response_model=UploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    service: AgentService = Depends(get_agent_service),
) -> dict:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 10MB limit")

    return await service.save_upload(file.filename, file.content_type, raw)
