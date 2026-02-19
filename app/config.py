from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Behavioral Auth API"
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 5000
    app_reload: bool = True

    allowed_origins: list[str] = Field(default_factory=lambda: ["*"])

    db_path: str = str((Path(__file__).resolve().parents[1] / "backend" / "users.db"))
    database_url: str = ""
    frontend_dir: str = str((Path(__file__).resolve().parents[1] / "frontend"))
    upload_dir: str = str((Path(__file__).resolve().parents[1] / "uploads"))

    high_risk_threshold: float = 0.7
    anomaly_block_threshold: float = 0.7
    max_behavior_history_limit: int = 100
    jwt_secret_key: str = ""
    jwt_access_token_expire_minutes: int = 120
    initial_admin_username: str = "admin"
    alert_webhook_url: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
