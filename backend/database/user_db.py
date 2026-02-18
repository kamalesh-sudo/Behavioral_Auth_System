import sqlite3
import hashlib
import secrets
from datetime import datetime
import json
import os

class UserDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            # Get absolute path to backend/users.db (up one level from backend/database/user_db.py)
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, 'users.db')
        else:
            self.db_path = db_path
            
        print(f"DEBUG: UserDatabase using path: {os.path.abspath(self.db_path)}")
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')
            
            # Behavioral profiles table (Normalized with UNIQUE session_id)
            cursor.execute('''
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
            ''')
            
            # Login attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    risk_score REAL,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON behavioral_profiles(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_timestamp ON login_attempts(timestamp)")
            
            conn.commit()
            conn.close()
            print(f"Database initialized successfully at {self.db_path}")
        except Exception as e:
            print(f"CRITICAL ERROR initializing database: {e}")
            raise e
    
    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        
        return password_hash.hex(), salt
    
    def create_user(self, username, password):
        """Create a new user"""
        try:
            password_hash, salt = self.hash_password(password)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            ''', (username, password_hash, salt))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'user_id': user_id,
                'username': username
            }
        except sqlite3.IntegrityError:
            return {
                'success': False,
                'error': 'Username already exists'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_or_create_user(self, username, password):
        """Get existing user (verify password) or create new one"""
        try:
            # Check if user exists
            user_info = self.get_user_by_username(username)
            
            if user_info['success']:
                # Verify password for existing user
                verification = self.verify_user(username, password)
                if verification['success']:
                    return {
                        'success': True,
                        'user_id': user_info['user']['id'],
                        'username': username,
                        'is_new': False
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Invalid password'
                    }
            
            # Create new user
            return self.create_user(username, password)
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    def verify_user(self, username, password, ip_address=None):
        """Verify user credentials"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
        
            cursor.execute('''
                 SELECT id, password_hash, salt, is_active
                 FROM users
                 WHERE username = ?
                 ''', (username,))
        
            result = cursor.fetchone()
            conn.close()
        
            if not result:
            # Log failed attempt (user not found)
               self.log_login_attempt(username, 0, None, ip_address)
               return {
                   'success': False,
                'error': 'Invalid username or password'
                  }
        
            user_id, stored_hash, salt, is_active = result
        
            if not is_active:
               self.log_login_attempt(username, 0, None, ip_address)
               return {
                'success': False,
                'error': 'Account is disabled'
               }
        
        # Verify password
            password_hash, _ = self.hash_password(password, salt)
        
            if password_hash == stored_hash:
            # Update last login
               self.update_last_login(user_id)

            # Log successful login
               self.log_login_attempt(username, 1, None, ip_address)
            
               return {
                'success': True,
                'user_id': user_id,
                'username': username
               }
            else:
            # Log failed login
                self.log_login_attempt(username, 0, None, ip_address)
            
                return {
                     'success': False,
                'error': 'Invalid username or password'
                     }
        except Exception as e:
                return {
                  'success': False,
                  'error': str(e)
                }

    
    def update_last_login(self, user_id):
        """Update user's last login timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users
            SET last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
    
    def save_behavioral_profile(self, user_id, session_id, keystroke_data, mouse_data, risk_score):
        """Save or accumulate behavioral profile data (UPSERT)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if session exists
            cursor.execute("SELECT keystroke_data, mouse_data FROM behavioral_profiles WHERE session_id = ?", (session_id,))
            existing = cursor.fetchone()

            if existing:
                # Accumulate data
                existing_keystrokes = json.loads(existing[0]) if existing[0] else []
                existing_mouse = json.loads(existing[1]) if existing[1] else []
                
                existing_keystrokes.extend(keystroke_data if keystroke_data else [])
                existing_mouse.extend(mouse_data if mouse_data else [])

                cursor.execute('''
                    UPDATE behavioral_profiles 
                    SET keystroke_data = ?, mouse_data = ?, risk_score = ?, timestamp = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (json.dumps(existing_keystrokes), json.dumps(existing_mouse), risk_score, session_id))
            else:
                # Insert new
                cursor.execute('''
                    INSERT INTO behavioral_profiles 
                    (user_id, session_id, keystroke_data, mouse_data, risk_score)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    session_id,
                    json.dumps(keystroke_data if keystroke_data else []),
                    json.dumps(mouse_data if mouse_data else []),
                    risk_score
                ))
            
            conn.commit()
            conn.close()
            
            return {'success': True}
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def log_login_attempt(self, username, success, risk_score=None, ip_address=None):
        """Log login attempt"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO login_attempts 
                (username, success, risk_score, ip_address)
                VALUES (?, ?, ?, ?)
            ''', (username, success, risk_score, ip_address))
            
            conn.commit()
            conn.close()
            
            return {'success': True}
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_user_behavioral_history(self, user_id, limit=10):
        """Get user's behavioral history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT session_id, risk_score, timestamp
                FROM behavioral_profiles
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (user_id, limit))
            
            results = cursor.fetchall()
            conn.close()
            
            history = []
            for row in results:
                history.append({
                    'session_id': row[0],
                    'risk_score': row[1],
                    'timestamp': row[2]
                })
            
            return {
                'success': True,
                'history': history
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_user_by_username(self, username):
        """Get user information by username"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, username, created_at, last_login, is_active
                FROM users
                WHERE username = ?
            ''', (username,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'success': True,
                    'user': {
                        'id': result[0],
                        'username': result[1],
                        'created_at': result[2],
                        'last_login': result[3],
                        'is_active': result[4]
                    }
                }
            else:
                return {
                    'success': False,
                    'error': 'User not found'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

# Initialize database when module is imported
if __name__ == '__main__':
    db = UserDatabase()
    print("Database setup complete")
