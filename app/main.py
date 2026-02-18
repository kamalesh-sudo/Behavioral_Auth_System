from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import get_settings

settings = get_settings()
app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

frontend_dir = Path(settings.frontend_dir)
if frontend_dir.exists():
    for route in ("dashboard", "collector", "login", "calibration"):
        mount_path = frontend_dir / route
        if mount_path.exists():
            app.mount(f"/{route}", StaticFiles(directory=str(mount_path)), name=route)


@app.get("/", include_in_schema=False)
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/login/login.html", status_code=302)
