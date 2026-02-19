# Behavioral Authentication System

Clean, Python-first behavioral auth project with two runtime components:
- FastAPI app for REST APIs + static frontend serving + websocket realtime risk scoring

## Project Structure

```text
app/
  config.py        # Environment settings
  database.py      # SQLite auth/profile storage
  schemas.py       # Pydantic request/response models
  main.py          # FastAPI routes + static mounts
backend/
  websocket_server.py
  ml/
  models/
frontend/
  login/
  calibration/
  dashboard/
  collector/
tests/
  smoke_test.py
```

## Start

```bash
cd backend
pip install -r requirements.txt
cd ..
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Set `JWT_SECRET_KEY` (or `AUTH_TOKEN` as fallback) in `.env` before starting services.

Optional websocket server (recommended for behavioral scoring):

```bash
No separate process needed. WebSocket is served by FastAPI at `/ws/behavioral`.
```

## Main Endpoints

- `GET /health`
- `POST /upload`
- `POST /api/register`
- `POST /api/start-session`
- `POST /api/login`
- `POST /api/behavioral-profile`
- `GET /api/user/{username}`
- `GET /api/user/{user_id}/behavioral-history`
- `GET /api/security-events` (analyst/admin)
- `POST /api/admin/users/{username}/role` (admin)

Frontend pages are served at `http://localhost:5000`.

JWT tokens are now returned by `/api/start-session` and `/api/login`, and the frontend stores them for websocket auth automatically.

Role model:
- `user`: standard account
- `analyst`: can read security events + other user data
- `admin`: full access including role changes
