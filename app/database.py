import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from functools import lru_cache


class AuthDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_schema(self) -> None:
        conn = self._connect()
        cursor = conn.cursor()

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

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON behavioral_profiles(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_security_events_username ON security_events(username)")

        conn.commit()
        self._ensure_schema_migrations(conn)
        conn.close()

    def _ensure_schema_migrations(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in cursor.fetchall()}
        if "role" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
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
            cursor.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
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
    return AuthDatabase(settings.db_path)
