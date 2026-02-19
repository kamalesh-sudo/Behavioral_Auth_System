from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile, WebSocket, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import get_db
from app.realtime import RealtimeBehaviorService
from app.alerts import send_security_alert
from app.security import create_access_token, verify_access_token
from app.schemas import (
    BehavioralHistoryResult,
    BehavioralProfilePayload,
    Credentials,
    LoginPayload,
    ProjectCreatePayload,
    RoleUpdatePayload,
    TaskCreatePayload,
    TaskUpdatePayload,
    UploadResult,
    UserResult,
)

settings = get_settings()
db = get_db()
realtime_service = RealtimeBehaviorService(settings, db)
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


def _parse_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization must use Bearer token")
    token = parts[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token")
    return token


async def get_current_principal(authorization: str | None = Header(default=None, alias="Authorization")) -> dict:
    token = _parse_bearer_token(authorization)
    try:
        claims = verify_access_token(token, settings)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    user = db.get_user(claims["sub"])
    if not user.get("success"):
        raise HTTPException(status_code=401, detail="User no longer exists")
    if int(user["user"].get("is_active", 1)) == 0:
        raise HTTPException(status_code=403, detail="Account is blocked")

    return {
        "username": user["user"]["username"],
        "user_id": user["user"]["id"],
        "role": user["user"].get("role", "user"),
    }


def require_roles(*roles: str):
    async def _role_dependency(principal: dict = Depends(get_current_principal)) -> dict:
        if principal["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role privileges")
        return principal

    return _role_dependency


def _ensure_project_access(principal: dict, project_id: int) -> dict:
    project = db.get_project(project_id)
    if not project.get("success"):
        raise HTTPException(status_code=404, detail=project.get("error", "Project not found"))
    if principal["role"] not in {"analyst", "admin"} and project["project"]["owner_id"] != principal["user_id"]:
        raise HTTPException(status_code=403, detail="Cannot access another user's project")
    return project["project"]


@route_aliases(["/health", "/api/health", "/api/v1/health"], methods=["GET"], tags=["health"])
async def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "environment": settings.app_env}


@route_aliases(["/security-events", "/api/security-events", "/api/v1/security-events"], methods=["GET"], tags=["security"])
async def get_security_events(
    limit: int = Query(default=50, ge=1, le=500),
    username: str | None = Query(default=None),
    principal: dict = Depends(require_roles("analyst", "admin")),
) -> dict:
    result = db.get_security_events(limit=limit, username=username)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch security events"))
    result["requested_by"] = principal["username"]
    return result


@route_aliases(
    ["/realtime-monitor", "/api/realtime-monitor", "/api/v1/realtime-monitor"],
    methods=["GET"],
    tags=["security"],
)
async def realtime_monitor(principal: dict = Depends(require_roles("analyst", "admin"))) -> dict:
    snapshot = realtime_service.get_monitor_snapshot()
    snapshot["requested_by"] = principal["username"]
    return snapshot


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
    destination.write_bytes(raw)

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

    role = "admin" if payload.username == settings.initial_admin_username else "user"
    result = db.create_user(payload.username, payload.password, role=role)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Registration failed"))

    return {
        "success": True,
        "message": "User registered successfully",
        "user_id": result["user_id"],
        "username": result["username"],
        "role": result["role"],
    }


@route_aliases(["/start-session", "/api/start-session", "/api/v1/start-session"], methods=["POST"], tags=["auth"])
async def start_session(payload: Credentials) -> dict:
    _ensure_username_not_blocked(payload.username)
    result = db.get_or_create_user(payload.username, payload.password)
    if not result.get("success"):
        if _is_blocked_error(result.get("error")):
            raise HTTPException(status_code=403, detail=result.get("error", "User blocked"))
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to start session"))
    if result["username"] == settings.initial_admin_username and result.get("role") != "admin":
        db.set_user_role(result["username"], "admin")
        result["role"] = "admin"

    access_token, expires_at = create_access_token(settings, result["username"], result["user_id"])
    result["access_token"] = access_token
    result["token_type"] = "bearer"
    result["expires_at"] = expires_at
    return result


@route_aliases(["/login", "/api/login", "/api/v1/login"], methods=["POST"], tags=["auth"])
async def login(payload: LoginPayload, request: Request) -> dict:
    _ensure_username_not_blocked(payload.username)
    result = db.verify_user(payload.username, payload.password)
    client_ip = request.client.host if request.client else None
    db.log_login_attempt(payload.username, int(result.get("success", False)), payload.risk_score, client_ip)

    if result.get("success") and payload.risk_score > settings.high_risk_threshold:
        db.log_security_event(
            username=payload.username,
            event_type="HIGH_RISK_LOGIN",
            reason="Risk score exceeded high risk threshold",
            risk_score=payload.risk_score,
        )
        send_security_alert(
            {
                "event_type": "HIGH_RISK_LOGIN",
                "username": payload.username,
                "risk_score": payload.risk_score,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )
        raise HTTPException(status_code=403, detail="High behavioral risk detected. Additional authentication required.")
    if not result.get("success"):
        if _is_blocked_error(result.get("error")):
            raise HTTPException(status_code=403, detail=result.get("error", "User blocked"))
        raise HTTPException(status_code=401, detail=result.get("error", "Invalid credentials"))

    if result["username"] == settings.initial_admin_username and result.get("role") != "admin":
        db.set_user_role(result["username"], "admin")
        result["role"] = "admin"

    access_token, expires_at = create_access_token(settings, result["username"], result["user_id"])

    return {
        "success": True,
        "message": "Login successful",
        "user_id": result["user_id"],
        "username": result["username"],
        "role": result["role"],
        "risk_score": payload.risk_score,
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
    }


@route_aliases(["/behavioral-profile", "/api/behavioral-profile", "/api/v1/behavioral-profile"], methods=["POST"], tags=["auth"])
async def save_behavioral_profile(payload: BehavioralProfilePayload, principal: dict = Depends(get_current_principal)) -> dict:
    if principal["user_id"] != payload.user_id and principal["role"] != "admin":
        raise HTTPException(status_code=403, detail="Cannot write another user's behavioral profile")
    _ensure_user_id_not_blocked(payload.user_id)
    result = db.save_behavioral_profile(
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
async def get_user(username: str, principal: dict = Depends(get_current_principal)) -> dict:
    if principal["username"] != username and principal["role"] not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Cannot read another user's profile")
    result = db.get_user(username)
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
async def behavioral_history(user_id: int, limit: int = Query(default=10, ge=1), principal: dict = Depends(get_current_principal)) -> dict:
    if principal["user_id"] != user_id and principal["role"] not in {"analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Cannot read another user's behavioral history")
    bounded_limit = min(limit, settings.max_behavior_history_limit)
    result = db.get_behavioral_history(user_id, bounded_limit)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch behavioral history"))
    return result


@route_aliases(
    ["/admin/users/{username}/role", "/api/admin/users/{username}/role", "/api/v1/admin/users/{username}/role"],
    methods=["POST"],
    tags=["security"],
)
async def update_user_role(
    username: str,
    payload: RoleUpdatePayload,
    principal: dict = Depends(require_roles("admin")),
) -> dict:
    result = db.set_user_role(username, payload.role)
    if not result.get("success"):
        raise HTTPException(status_code=404, detail=result.get("error", "User not found"))
    db.log_security_event(
        username=principal["username"],
        event_type="ROLE_UPDATED",
        reason=f"Set role for {username} to {payload.role}",
    )
    return {"success": True, "updated_user": username, "role": payload.role}


@route_aliases(["/projects", "/api/projects", "/api/v1/projects"], methods=["GET"], tags=["work"])
async def list_projects(principal: dict = Depends(get_current_principal)) -> dict:
    result = db.get_projects_for_user(principal["user_id"])
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch projects"))
    return result


@route_aliases(["/projects", "/api/projects", "/api/v1/projects"], methods=["POST"], tags=["work"])
async def create_project(payload: ProjectCreatePayload, principal: dict = Depends(get_current_principal)) -> dict:
    result = db.create_project(principal["user_id"], payload.name, payload.description)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create project"))
    db.log_security_event(
        username=principal["username"],
        event_type="PROJECT_CREATED",
        reason=f"Created project {result['project_id']}",
    )
    return {"success": True, "project_id": result["project_id"]}


@route_aliases(
    ["/projects/{project_id}/tasks", "/api/projects/{project_id}/tasks", "/api/v1/projects/{project_id}/tasks"],
    methods=["GET"],
    tags=["work"],
)
async def list_project_tasks(project_id: int, principal: dict = Depends(get_current_principal)) -> dict:
    _ensure_project_access(principal, project_id)
    result = db.get_tasks_for_project(project_id)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to fetch tasks"))
    return result


@route_aliases(
    ["/projects/{project_id}/tasks", "/api/projects/{project_id}/tasks", "/api/v1/projects/{project_id}/tasks"],
    methods=["POST"],
    tags=["work"],
)
async def create_project_task(
    project_id: int,
    payload: TaskCreatePayload,
    principal: dict = Depends(get_current_principal),
) -> dict:
    _ensure_project_access(principal, project_id)
    assignee_id = None
    if payload.assignee_username:
        assignee_user = db.get_user(payload.assignee_username)
        if not assignee_user.get("success"):
            raise HTTPException(status_code=404, detail="Assignee not found")
        assignee_id = assignee_user["user"]["id"]

    result = db.create_task(
        project_id=project_id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        priority=payload.priority,
        assignee_id=assignee_id,
        due_date=payload.due_date,
        created_by=principal["user_id"],
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to create task"))
    db.log_security_event(
        username=principal["username"],
        event_type="TASK_CREATED",
        reason=f"Created task {result['task_id']} in project {project_id}",
    )
    return {"success": True, "task_id": result["task_id"]}


@route_aliases(["/tasks/{task_id}", "/api/tasks/{task_id}", "/api/v1/tasks/{task_id}"], methods=["PATCH"], tags=["work"])
async def update_task(task_id: int, payload: TaskUpdatePayload, principal: dict = Depends(get_current_principal)) -> dict:
    task = db.get_task(task_id)
    if not task.get("success"):
        raise HTTPException(status_code=404, detail=task.get("error", "Task not found"))
    _ensure_project_access(principal, task["task"]["project_id"])

    assignee_id = None
    if payload.assignee_username:
        assignee_user = db.get_user(payload.assignee_username)
        if not assignee_user.get("success"):
            raise HTTPException(status_code=404, detail="Assignee not found")
        assignee_id = assignee_user["user"]["id"]

    result = db.update_task(
        task_id=task_id,
        title=payload.title,
        description=payload.description,
        status=payload.status,
        priority=payload.priority,
        assignee_id=assignee_id,
        due_date=payload.due_date,
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to update task"))
    db.log_security_event(
        username=principal["username"],
        event_type="TASK_UPDATED",
        reason=f"Updated task {task_id}",
    )
    return {"success": True, "task_id": task_id}


app.include_router(router)


@app.websocket("/ws/behavioral")
async def behavioral_websocket(websocket: WebSocket) -> None:
    await realtime_service.handle_client(websocket)

frontend_dir = Path(settings.frontend_dir)
if frontend_dir.exists():
    for route in ("dashboard", "collector", "login", "calibration"):
        mount_path = frontend_dir / route
        if mount_path.exists():
            app.mount(f"/{route}", StaticFiles(directory=str(mount_path)), name=route)


@app.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login/login.html", status_code=302)
