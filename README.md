# Behavioral Authentication System

Behavioral authentication platform with a Python-only backend stack:
- FastAPI for REST endpoints and static frontend serving
- WebSocket behavioral analyzer for real-time risk scoring
- SQLite-backed user/session/profile data

## FastAPI Layout

```text
app/
  main.py
  api/v1/endpoints/
    auth.py
    agent.py
    health.py
  core/config.py
  db/
    dependencies.py
    user_db.py
  models/
  schemas/
  services/
backend/
  websocket_server.py
tests/
  utils/
```

## Key Endpoints

- `POST /query` and `POST /api/v1/query`
- `POST /upload` and `POST /api/v1/upload`
- `GET /health` and `GET /api/v1/health`
- `POST /api/start-session`
- `POST /api/login`
- `POST /api/behavioral-profile`
- `GET /api/user/{username}`
- `GET /api/user/{user_id}/behavioral-history`

## Run

```bash
cd backend
pip install -r requirements.txt
cd ..
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Optional websocket analyzer:

```bash
cd backend
python websocket_server.py
```

Frontend static pages are served by FastAPI at:
- `http://localhost:5000/login/login.html`
- `http://localhost:5000/dashboard/index.html`
