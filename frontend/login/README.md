# Login Page with Behavioral Authentication

## Overview

This login system integrates behavioral biometrics to enhance security during the authentication process. It captures and analyzes user behavior (keystroke dynamics and mouse movements) in real-time to detect anomalies and prevent unauthorized access.

## Features

✨ **Modern UI/UX**
- Premium dark-themed design with glassmorphism effects
- Smooth animations and micro-interactions
- Real-time risk score visualization
- Responsive layout for all devices

🔒 **Security Features**
- Behavioral biometric authentication
- Real-time risk scoring
- Secure password hashing (PBKDF2-HMAC-SHA256)
- Session management
- Login attempt logging

📊 **Behavioral Analysis**
- Keystroke dynamics (dwell time, flight time, typing rhythm)
- Mouse behavior (velocity, acceleration, movement patterns)
- AI-powered anomaly detection
- User-specific behavioral profiles

## File Structure

```
frontend/login/
├── login.html          # Login page HTML
├── login.css           # Styling with modern design
└── login.js            # Behavioral data collection & WebSocket integration

backend/
├── api/
│   └── auth_api.py     # Flask REST API for authentication
├── database/
│   └── user_db.py      # SQLite database management
└── websocket_server.py # Real-time behavioral analysis server
```

## Setup Instructions

### 1. Install Dependencies

Make sure you have all required Python packages:

```bash
cd backend
pip install flask flask-cors
```

### 2. Initialize Database

The database will be automatically created when you first run the API server:

```bash
cd backend
python database/user_db.py
```

### 3. Start the Servers

You need to run THREE servers:

**Terminal 1 - WebSocket Server (Behavioral Analysis):**
```bash
cd backend
python websocket_server.py
```

**Terminal 2 - Flask API Server (Authentication):**
```bash
cd backend/api
python auth_api.py
```

**Terminal 3 - Frontend Server:**
```bash
cd frontend
npm start
```

### 4. Access the Login Page

Open your browser and navigate to:
```
http://localhost:3000/login/login.html
```

## How It Works

### 1. **User Interaction**
- User enters username and password
- System captures keystroke and mouse behavior in real-time

### 2. **Behavioral Data Collection**
- Keystroke events (keydown, keyup, dwell time)
- Mouse events (movement, clicks, velocity)
- Data sent to WebSocket server every 2 seconds

### 3. **Real-Time Analysis**
- WebSocket server analyzes behavioral patterns
- ML models calculate risk score (0-1 scale)
- Risk score displayed on login page

### 4. **Authentication Decision**
- Credentials verified via Flask API
- Risk score evaluated:
  - **Low Risk (< 0.3)**: Login approved ✅
  - **Medium Risk (0.3-0.7)**: Login approved with warning ⚠️
  - **High Risk (> 0.7)**: Additional authentication required 🚫

### 5. **Data Storage**
- User credentials stored securely in SQLite
- Behavioral profiles saved for future analysis
- Login attempts logged for security monitoring

## API Endpoints

### Register User
```http
POST /api/register
Content-Type: application/json

{
  "username": "john_doe",
  "password": "secure_password"
}
```

### Login
```http
POST /api/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "secure_password",
  "risk_score": 0.25
}
```

### Get User Info
```http
GET /api/user/{username}
```

### Get Behavioral History
```http
GET /api/user/{user_id}/behavioral-history?limit=10
```

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password_hash`: Hashed password
- `salt`: Password salt
- `created_at`: Registration timestamp
- `last_login`: Last login timestamp
- `is_active`: Account status

### Behavioral Profiles Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `session_id`: Session identifier
- `keystroke_data`: JSON keystroke events
- `mouse_data`: JSON mouse events
- `risk_score`: Calculated risk score
- `timestamp`: Profile timestamp

### Login Attempts Table
- `id`: Primary key
- `username`: Attempted username
- `success`: Login success status
- `risk_score`: Behavioral risk score
- `ip_address`: Client IP address
- `timestamp`: Attempt timestamp

## Risk Score Interpretation

| Score Range | Level | Color | Action |
|------------|-------|-------|--------|
| 0.0 - 0.3 | Low | 🟢 Green | Allow login |
| 0.3 - 0.7 | Medium | 🟡 Yellow | Allow with warning |
| 0.7 - 1.0 | High | 🔴 Red | Require MFA |

## Testing the System

### Create a Test User

1. Open the login page
2. Click "Create New Account"
3. Or use the API directly:

```bash
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"test123"}'
```

### Test Login

1. Enter credentials on login page
2. Type naturally and move your mouse
3. Observe the real-time risk score
4. Submit the form

## Customization

### Adjust Risk Thresholds

Edit `login.js` line ~245:
```javascript
if (this.currentRiskScore < 0.7) {
  // Change threshold here
}
```

### Change WebSocket Server

Edit `login.js` line ~52:
```javascript
const wsHost = 'localhost';
const wsPort = 8765;
```

### Modify UI Colors

Edit `login.css` CSS variables:
```css
:root {
    --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    --success-color: #10b981;
    --warning-color: #f59e0b;
    --danger-color: #ef4444;
}
```

## Security Considerations

⚠️ **Important Notes:**

1. **Authentication Token**: Change the hardcoded token in `websocket_server.py`:
   ```python
   AUTH_TOKEN = os.environ.get("AUTH_TOKEN", "your-secret-auth-token")
   ```

2. **HTTPS**: Use HTTPS in production (not HTTP)

3. **Password Policy**: Implement stronger password requirements

4. **Rate Limiting**: Add rate limiting to prevent brute force attacks

5. **Session Management**: Implement proper session expiration

6. **Database**: Use PostgreSQL or MySQL in production instead of SQLite

## Troubleshooting

### WebSocket Connection Failed
- Ensure WebSocket server is running on port 8765
- Check firewall settings
- Verify the correct host/port in `login.js`

### API Errors
- Ensure Flask server is running on port 5000
- Check CORS configuration
- Verify database file permissions

### Risk Score Always 0
- Make sure WebSocket server has trained models
- Check that behavioral data is being collected
- Verify data is being sent to the server

## Next Steps

- [ ] Implement user registration page
- [ ] Add password reset functionality
- [ ] Implement multi-factor authentication
- [ ] Add session management
- [ ] Create admin dashboard
- [ ] Deploy to production server

## License

This project is part of the Behavioral Authentication System developed by Kamalesh S at Elevate Labs.
