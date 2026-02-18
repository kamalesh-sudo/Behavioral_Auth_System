# Behavioral Authentication System

Clean, Python-first behavioral auth project with two runtime components:
- FastAPI app for REST APIs + static frontend serving
- WebSocket server for real-time behavioral risk scoring

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

Optional websocket server (recommended for behavioral scoring):

```bash
cd backend
python websocket_server.py
```

## Main Endpoints

- `GET /health`
- `POST /query`
- `POST /upload`
- `POST /api/register`
- `POST /api/start-session`
- `POST /api/login`
- `POST /api/behavioral-profile`
- `GET /api/user/{username}`
- `GET /api/user/{user_id}/behavioral-history`

Frontend pages are served at `http://localhost:5000`.
