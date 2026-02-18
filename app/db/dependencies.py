from collections.abc import Generator
from functools import lru_cache

from app.core.config import get_settings
from app.db.user_db import UserDatabase


@lru_cache
def _get_db_instance() -> UserDatabase:
    settings = get_settings()
    return UserDatabase(settings.db_path)


def get_user_db() -> Generator[UserDatabase, None, None]:
    db = _get_db_instance()
    yield db
