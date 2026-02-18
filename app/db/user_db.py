import hashlib
import json
import os
import secrets
import sqlite3


class UserDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(db_dir, exist_ok=True)
        self.init_database()

    def init_database(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
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

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON behavioral_profiles(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp)")

        conn.commit()
        conn.close()

    def hash_password(self, password: str, salt: str | None = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(32)

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )

        return password_hash.hex(), salt

    def create_user(self, username: str, password: str) -> dict:
        try:
            password_hash, salt = self.hash_password(password)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
                """,
                (username, password_hash, salt),
            )

            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            return {"success": True, "user_id": user_id, "username": username}
        except sqlite3.IntegrityError:
            return {"success": False, "error": "Username already exists"}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_or_create_user(self, username: str, password: str) -> dict:
        try:
            user_info = self.get_user_by_username(username)
            if user_info["success"]:
                verification = self.verify_user(username, password)
                if verification["success"]:
                    return {
                        "success": True,
                        "user_id": user_info["user"]["id"],
                        "username": username,
                        "is_new": False,
                    }
                return {"success": False, "error": "Invalid password"}

            created = self.create_user(username, password)
            if created.get("success"):
                created["is_new"] = True
            return created
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def verify_user(self, username: str, password: str, ip_address: str | None = None) -> dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, password_hash, salt, is_active
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
            result = cursor.fetchone()
            conn.close()

            if not result:
                self.log_login_attempt(username, 0, None, ip_address)
                return {"success": False, "error": "Invalid username or password"}

            user_id, stored_hash, salt, is_active = result
            if not is_active:
                self.log_login_attempt(username, 0, None, ip_address)
                return {"success": False, "error": "Account is disabled"}

            password_hash, _ = self.hash_password(password, salt)
            if password_hash == stored_hash:
                self.update_last_login(user_id)
                self.log_login_attempt(username, 1, None, ip_address)
                return {"success": True, "user_id": user_id, "username": username}

            self.log_login_attempt(username, 0, None, ip_address)
            return {"success": False, "error": "Invalid username or password"}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def update_last_login(self, user_id: int) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()
        conn.close()

    def save_behavioral_profile(
        self,
        user_id: int,
        session_id: str,
        keystroke_data: list,
        mouse_data: list,
        risk_score: float,
    ) -> dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT keystroke_data, mouse_data FROM behavioral_profiles WHERE session_id = ?",
                (session_id,),
            )
            existing = cursor.fetchone()

            if existing:
                existing_keystrokes = json.loads(existing[0]) if existing[0] else []
                existing_mouse = json.loads(existing[1]) if existing[1] else []
                existing_keystrokes.extend(keystroke_data or [])
                existing_mouse.extend(mouse_data or [])

                cursor.execute(
                    """
                    UPDATE behavioral_profiles
                    SET keystroke_data = ?, mouse_data = ?, risk_score = ?, timestamp = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                    """,
                    (
                        json.dumps(existing_keystrokes),
                        json.dumps(existing_mouse),
                        risk_score,
                        session_id,
                    ),
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

    def log_login_attempt(
        self,
        username: str,
        success: int,
        risk_score: float | None = None,
        ip_address: str | None = None,
    ) -> dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO login_attempts (username, success, risk_score, ip_address)
                VALUES (?, ?, ?, ?)
                """,
                (username, success, risk_score, ip_address),
            )
            conn.commit()
            conn.close()
            return {"success": True}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_user_behavioral_history(self, user_id: int, limit: int = 10) -> dict:
        try:
            conn = sqlite3.connect(self.db_path)
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
            results = cursor.fetchall()
            conn.close()

            history = [
                {"session_id": row[0], "risk_score": row[1], "timestamp": row[2]}
                for row in results
            ]
            return {"success": True, "history": history}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}

    def get_user_by_username(self, username: str) -> dict:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, created_at, last_login, is_active
                FROM users
                WHERE username = ?
                """,
                (username,),
            )
            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    "success": True,
                    "user": {
                        "id": result[0],
                        "username": result[1],
                        "created_at": result[2],
                        "last_login": result[3],
                        "is_active": result[4],
                    },
                }
            return {"success": False, "error": "User not found"}
        except Exception as exc:  # pylint: disable=broad-except
            return {"success": False, "error": str(exc)}
