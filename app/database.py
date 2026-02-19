import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from functools import lru_cache

try:
    import psycopg
except Exception:  # pylint: disable=broad-except
    psycopg = None


class _CursorProxy:
    def __init__(self, cursor, is_postgres: bool):
        self._cursor = cursor
        self._is_postgres = is_postgres

    def execute(self, query: str, params=None):
        sql = query.replace("?", "%s") if self._is_postgres else query
        if params is None:
            return self._cursor.execute(sql)
        return self._cursor.execute(sql, params)

    def __getattr__(self, item):
        return getattr(self._cursor, item)


class _ConnectionProxy:
    def __init__(self, conn, is_postgres: bool):
        self._conn = conn
        self._is_postgres = is_postgres

    def cursor(self):
        return _CursorProxy(self._conn.cursor(), self._is_postgres)

    def __getattr__(self, item):
        return getattr(self._conn, item)


class AuthDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.is_postgres = db_path.startswith("postgresql://") or db_path.startswith("postgres://")
        if not self.is_postgres:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    def _connect(self):
        if self.is_postgres:
            if psycopg is None:
                raise RuntimeError("PostgreSQL configured but psycopg is not installed.")
            return _ConnectionProxy(psycopg.connect(self.db_path), True)
        return _ConnectionProxy(sqlite3.connect(self.db_path, timeout=10), False)

    @staticmethod
    def _is_unique_violation(exc: Exception) -> bool:
        return "unique" in str(exc).lower()

    def _init_schema(self) -> None:
        conn = self._connect()
        cursor = conn.cursor()

        if self.is_postgres:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMPTZ,
                    is_active BOOLEAN DEFAULT TRUE
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS behavioral_profiles (
                    id BIGSERIAL PRIMARY KEY,
                    user_id BIGINT NOT NULL REFERENCES users (id),
                    session_id TEXT UNIQUE NOT NULL,
                    keystroke_data TEXT,
                    mouse_data TEXT,
                    risk_score DOUBLE PRECISION,
                    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    risk_score DOUBLE PRECISION,
                    ip_address TEXT,
                    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id BIGSERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    session_id TEXT,
                    risk_score DOUBLE PRECISION,
                    event_type TEXT NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id BIGSERIAL PRIMARY KEY,
                    owner_id BIGINT NOT NULL REFERENCES users (id),
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id BIGSERIAL PRIMARY KEY,
                    project_id BIGINT NOT NULL REFERENCES projects (id),
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'todo',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    assignee_id BIGINT REFERENCES users (id),
                    due_date TEXT,
                    created_by BIGINT NOT NULL REFERENCES users (id),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        else:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS behavioral_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_id TEXT UNIQUE NOT NULL,
                    keystroke_data TEXT,
                    mouse_data TEXT,
                    risk_score REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    risk_score REAL,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    session_id TEXT,
                    risk_score REAL,
                    event_type TEXT NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (owner_id) REFERENCES users (id)
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'todo',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    assignee_id INTEGER,
                    due_date TEXT,
                    created_by INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (project_id) REFERENCES projects (id),
                    FOREIGN KEY (assignee_id) REFERENCES users (id),
                    FOREIGN KEY (created_by) REFERENCES users (id)
                )
                """
            )

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON behavioral_profiles(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_username ON security_events(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_projects_owner_id ON projects(owner_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_project_id ON tasks(project_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_assignee_id ON tasks(assignee_id)")

        conn.commit()
        self._ensure_schema_migrations(conn)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        conn.commit()
        conn.close()

    def _ensure_schema_migrations(self, conn) -> None:
        cursor = conn.cursor()
        if self.is_postgres:
            cursor.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                """
            )
            columns = {row[0] for row in cursor.fetchall()}
            if "role" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
                conn.commit()
        else:
            cursor.execute("PRAGMA table_info(users)")
            columns = {row[1] for row in cursor.fetchall()}
            if "role" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
                conn.commit()

            cursor.execute("PRAGMA table_info(tasks)")
            task_columns = {row[1] for row in cursor.fetchall()}
            if "status" in task_columns:
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'todo'
                    WHERE status NOT IN ('todo', 'in_progress', 'review', 'done')
                    """
                )
                conn.commit()

        cursor.execute(
            """
            UPDATE tasks
            SET status = 'todo'
            WHERE status NOT IN ('todo', 'in_progress', 'review', 'done')
            """
        )
        conn.commit()

    @staticmethod
    def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
        salt = salt or secrets.token_hex(32)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
        return digest.hex(), salt

    def create_user(self, username: str, password: str, role: str = "user") -> dict:
        try:
            password_hash, salt = self._hash_password(password)
            conn = self._connect()
            cursor = conn.cursor()
            if self.is_postgres:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?) RETURNING id",
                    (username, password_hash, salt, role),
                )
                row = cursor.fetchone()
                user_id = row[0] if row else None
            else:
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                    (username, password_hash, salt, role),
                )
                user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {"success": True, "user_id": user_id, "username": username, "role": role}
        except sqlite3.IntegrityError:
            return {"success": False, "error": "Username already exists"}
        except Exception as exc:  # pylint: disable=broad-except
            if self._is_unique_violation(exc):
                return {"success": False, "error": "Username already exists"}
            return {"success": False, "error": str(exc)}

    def get_user(self, username: str) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, role, created_at, last_login, is_active FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return {"success": False, "error": "User not found"}
            return {
                "success": True,
                "user": {
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                    "created_at": row[3],
                    "last_login": row[4],
                    "is_active": row[5],
                },
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_user_by_id(self, user_id: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, role, created_at, last_login, is_active FROM users WHERE id = ?",
                (user_id,),
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return {"success": False, "error": "User not found"}
            return {
                "success": True,
                "user": {
                    "id": row[0],
                    "username": row[1],
                    "role": row[2],
                    "created_at": row[3],
                    "last_login": row[4],
                    "is_active": row[5],
                },
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def verify_user(self, username: str, password: str) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, password_hash, salt, role, is_active FROM users WHERE username = ?",
                (username,),
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return {"success": False, "error": "Invalid username or password"}

            user_id, stored_hash, salt, role, is_active = row
            if not is_active:
                return {"success": False, "error": "Account is disabled"}

            calculated_hash, _ = self._hash_password(password, salt)
            if not hmac.compare_digest(calculated_hash, stored_hash):
                return {"success": False, "error": "Invalid username or password"}

            self._update_last_login(user_id)
            return {"success": True, "user_id": user_id, "username": username, "role": role}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_or_create_user(self, username: str, password: str) -> dict:
        user = self.get_user(username)
        if user.get("success"):
            verified = self.verify_user(username, password)
            if not verified.get("success"):
                return {"success": False, "error": verified.get("error", "Invalid password")}
            return {
                "success": True,
                "user_id": user["user"]["id"],
                "username": username,
                "role": user["user"]["role"],
                "is_new": False,
            }

        created = self.create_user(username, password)
        if created.get("success"):
            created["is_new"] = True
        return created

    def _update_last_login(self, user_id: int) -> None:
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

    def log_login_attempt(
        self,
        username: str,
        success: int,
        risk_score: float | None = None,
        ip_address: str | None = None,
    ) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO login_attempts (username, success, risk_score, ip_address) VALUES (?, ?, ?, ?)",
                (username, success, risk_score, ip_address),
            )
            conn.commit()
            conn.close()
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def block_user(
        self,
        username: str,
        session_id: str | None,
        risk_score: float | None,
        reason: str,
    ) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET is_active = ? WHERE username = ?", (False, username))
            user_updated = cursor.rowcount > 0
            cursor.execute(
                """
                INSERT INTO security_events (username, session_id, risk_score, event_type, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, session_id, risk_score, "ANOMALY_BLOCK", reason),
            )
            conn.commit()
            conn.close()
            return {"success": True, "user_updated": user_updated}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def set_user_role(self, username: str, role: str) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()
            if not updated:
                return {"success": False, "error": "User not found"}
            return {"success": True, "username": username, "role": role}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def log_security_event(
        self,
        username: str,
        event_type: str,
        reason: str,
        session_id: str | None = None,
        risk_score: float | None = None,
    ) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO security_events (username, session_id, risk_score, event_type, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, session_id, risk_score, event_type, reason),
            )
            conn.commit()
            conn.close()
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_security_events(self, limit: int = 100, username: str | None = None) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            if username:
                cursor.execute(
                    """
                    SELECT username, session_id, risk_score, event_type, reason, timestamp
                    FROM security_events
                    WHERE username = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (username, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT username, session_id, risk_score, event_type, reason, timestamp
                    FROM security_events
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cursor.fetchall()
            conn.close()
            return {
                "success": True,
                "events": [
                    {
                        "username": row[0],
                        "session_id": row[1],
                        "risk_score": row[2],
                        "event_type": row[3],
                        "reason": row[4],
                        "timestamp": row[5],
                    }
                    for row in rows
                ],
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def create_project(self, owner_id: int, name: str, description: str | None = None) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            if self.is_postgres:
                cursor.execute(
                    """
                    INSERT INTO projects (owner_id, name, description)
                    VALUES (?, ?, ?) RETURNING id
                    """,
                    (owner_id, name, description),
                )
                row = cursor.fetchone()
                project_id = row[0] if row else None
            else:
                cursor.execute(
                    """
                    INSERT INTO projects (owner_id, name, description)
                    VALUES (?, ?, ?)
                    """,
                    (owner_id, name, description),
                )
                project_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return {"success": True, "project_id": project_id}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_projects_for_user(self, user_id: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, name, description, created_at, updated_at
                FROM projects
                WHERE owner_id = ?
                ORDER BY updated_at DESC, id DESC
                """,
                (user_id,),
            )
            rows = cursor.fetchall()
            conn.close()
            return {
                "success": True,
                "projects": [
                    {
                        "id": row[0],
                        "name": row[1],
                        "description": row[2],
                        "created_at": row[3],
                        "updated_at": row[4],
                    }
                    for row in rows
                ],
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_project(self, project_id: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, owner_id, name, description, created_at, updated_at
                FROM projects
                WHERE id = ?
                """,
                (project_id,),
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return {"success": False, "error": "Project not found"}
            return {
                "success": True,
                "project": {
                    "id": row[0],
                    "owner_id": row[1],
                    "name": row[2],
                    "description": row[3],
                    "created_at": row[4],
                    "updated_at": row[5],
                },
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def create_task(
        self,
        project_id: int,
        title: str,
        description: str | None,
        status: str,
        priority: str,
        assignee_id: int | None,
        due_date: str | None,
        created_by: int,
    ) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            if self.is_postgres:
                cursor.execute(
                    """
                    INSERT INTO tasks (project_id, title, description, status, priority, assignee_id, due_date, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
                    """,
                    (project_id, title, description, status, priority, assignee_id, due_date, created_by),
                )
                row = cursor.fetchone()
                task_id = row[0] if row else None
            else:
                cursor.execute(
                    """
                    INSERT INTO tasks (project_id, title, description, status, priority, assignee_id, due_date, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (project_id, title, description, status, priority, assignee_id, due_date, created_by),
                )
                task_id = cursor.lastrowid
            cursor.execute(
                """
                UPDATE projects
                SET updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (project_id,),
            )
            conn.commit()
            conn.close()
            return {"success": True, "task_id": task_id}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_tasks_for_project(self, project_id: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT t.id, t.title, t.description, t.status, t.priority, t.assignee_id, u.username, t.due_date, t.created_by, t.created_at, t.updated_at
                FROM tasks t
                LEFT JOIN users u ON t.assignee_id = u.id
                WHERE t.project_id = ?
                ORDER BY t.updated_at DESC, t.id DESC
                """,
                (project_id,),
            )
            rows = cursor.fetchall()
            conn.close()
            return {
                "success": True,
                "tasks": [
                    {
                        "id": row[0],
                        "title": row[1],
                        "description": row[2],
                        "status": row[3],
                        "priority": row[4],
                        "assignee_id": row[5],
                        "assignee_username": row[6],
                        "due_date": row[7],
                        "created_by": row[8],
                        "created_at": row[9],
                        "updated_at": row[10],
                    }
                    for row in rows
                ],
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_task(self, task_id: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, project_id, title, description, status, priority, assignee_id, due_date, created_by
                FROM tasks
                WHERE id = ?
                """,
                (task_id,),
            )
            row = cursor.fetchone()
            conn.close()
            if not row:
                return {"success": False, "error": "Task not found"}
            return {
                "success": True,
                "task": {
                    "id": row[0],
                    "project_id": row[1],
                    "title": row[2],
                    "description": row[3],
                    "status": row[4],
                    "priority": row[5],
                    "assignee_id": row[6],
                    "due_date": row[7],
                    "created_by": row[8],
                },
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def update_task(
        self,
        task_id: int,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        assignee_id: int | None = None,
        due_date: str | None = None,
    ) -> dict:
        try:
            current = self.get_task(task_id)
            if not current.get("success"):
                return current
            task = current["task"]
            next_title = title if title is not None else task["title"]
            next_description = description if description is not None else task["description"]
            next_status = status if status is not None else task["status"]
            next_priority = priority if priority is not None else task["priority"]
            next_assignee = assignee_id if assignee_id is not None else task["assignee_id"]
            next_due_date = due_date if due_date is not None else task["due_date"]

            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE tasks
                SET title = ?, description = ?, status = ?, priority = ?, assignee_id = ?, due_date = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (next_title, next_description, next_status, next_priority, next_assignee, next_due_date, task_id),
            )
            cursor.execute(
                """
                UPDATE projects
                SET updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (task["project_id"],),
            )
            conn.commit()
            conn.close()
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def save_behavioral_profile(
        self,
        user_id: int,
        session_id: str,
        keystroke_data: list[dict],
        mouse_data: list[dict],
        risk_score: float,
    ) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT keystroke_data, mouse_data FROM behavioral_profiles WHERE session_id = ?",
                (session_id,),
            )
            existing = cursor.fetchone()
            if existing:
                existing_keystrokes = json.loads(existing[0] or "[]")
                existing_mouse = json.loads(existing[1] or "[]")
                existing_keystrokes.extend(keystroke_data or [])
                existing_mouse.extend(mouse_data or [])
                cursor.execute(
                    """
                    UPDATE behavioral_profiles
                    SET keystroke_data = ?, mouse_data = ?, risk_score = ?, timestamp = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                    """,
                    (json.dumps(existing_keystrokes), json.dumps(existing_mouse), risk_score, session_id),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO behavioral_profiles (user_id, session_id, keystroke_data, mouse_data, risk_score)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (user_id, session_id, json.dumps(keystroke_data or []), json.dumps(mouse_data or []), risk_score),
                )
            conn.commit()
            conn.close()
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_behavioral_history(self, user_id: int, limit: int) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT session_id, risk_score, timestamp
                FROM behavioral_profiles
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (user_id, limit),
            )
            rows = cursor.fetchall()
            conn.close()
            return {
                "success": True,
                "history": [
                    {"session_id": row[0], "risk_score": row[1], "timestamp": row[2]}
                    for row in rows
                ],
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_behavioral_training_data(self, limit: int = 5000) -> dict:
        try:
            conn = self._connect()
            cursor = conn.cursor()
            active_filter = "TRUE" if self.is_postgres else "1"
            cursor.execute(
                f"""
                SELECT u.username, b.keystroke_data, b.mouse_data
                FROM behavioral_profiles b
                JOIN users u ON u.id = b.user_id
                WHERE u.is_active = {active_filter}
                ORDER BY b.timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            conn.close()
            dataset = []
            for row in rows:
                dataset.append(
                    {
                        "user_id": row[0],
                        "behavioral_data": {
                            "keystrokeData": json.loads(row[1] or "[]"),
                            "mouseData": json.loads(row[2] or "[]"),
                        },
                    }
                )
            return {"success": True, "dataset": dataset}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def is_user_blocked(self, username: str) -> bool:
        user = self.get_user(username)
        if not user.get("success"):
            return False
        return int(user["user"].get("is_active", 1)) == 0

    def is_user_id_blocked(self, user_id: int) -> bool:
        user = self.get_user_by_id(user_id)
        if not user.get("success"):
            return False
        return int(user["user"].get("is_active", 1)) == 0


@lru_cache
def get_db() -> AuthDatabase:
    from app.config import get_settings

    settings = get_settings()
    return AuthDatabase(settings.database_url or settings.db_path)
