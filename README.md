# Freelancer Workspace + Behavioral Security

Python-first freelancer task manager with continuous behavioral anomaly monitoring.

Core stack:
- FastAPI for REST APIs and static frontend hosting
- WebSocket pipeline for realtime behavioral risk scoring
- SQLite (default) or PostgreSQL (optional)

## Project Structure

```text
app/
  config.py        # Environment settings
  database.py      # SQLite/PostgreSQL auth/profile storage
  schemas.py       # Pydantic request/response models
  main.py          # FastAPI routes + static mounts
backend/
  websocket_server.py  # legacy standalone realtime server (optional)
  ml/
  models/
frontend/
  login/
  dashboard/
tests/
  smoke_test.py
```

## Prerequisites

- Python 3.10+
- `pip`
- Optional: PostgreSQL (if you do not want SQLite)

## Quick Start

```bash
cp .env.example .env
cd backend
pip install -r requirements.txt
cd ..
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Before starting, set `JWT_SECRET_KEY` (or `AUTH_TOKEN` as fallback) in `.env`.

Default database: SQLite (`DB_PATH` in `.env`).

Use PostgreSQL instead by setting:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/behavioral_auth
```

If `DATABASE_URL` is not set, the app uses SQLite automatically.

Realtime WebSocket is served by FastAPI at `/ws/behavioral` (no extra process needed).

## Main Endpoints

- Health
  - `GET /health`
- Authentication
  - `POST /api/register`
  - `POST /api/start-session`
  - `POST /api/login`
- Project and task management
  - `GET /api/projects`
  - `POST /api/projects`
  - `GET /api/projects/{project_id}/tasks`
  - `POST /api/projects/{project_id}/tasks`
  - `PATCH /api/tasks/{task_id}`
  - Compatibility aliases: `/api/projects/{project_id}/task` and `/api/task/{task_id}`
- Security and monitoring
  - `GET /api/security-events` (analyst/admin)
  - `GET /api/realtime-monitor` (analyst/admin)
  - `POST /api/admin/users/{username}/role` (admin)

Frontend pages are served at `http://localhost:5000`.

`/api/start-session` and `/api/login` return JWTs. The frontend stores and reuses them for WebSocket authentication.

Role model:
- `user`: standard account
- `analyst`: can read security events + other user data
- `admin`: full access including role changes

## Realtime Monitoring

Run API with verbose logs:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload --log-level info
```

The realtime service emits `realtime_event` logs for:
- websocket connect/auth/disconnect
- behavioral packet receipt + risk score
- profile updates/training state
- anomaly blocks/session terminations

You can also query monitor state (as `analyst` or `admin`):

```bash
curl -s http://localhost:5000/api/realtime-monitor -H "Authorization: Bearer <TOKEN>" | jq
```

## Automatic Global Training

The server can periodically train the global model from stored behavioral profiles.
Configure in `.env`:

```bash
GLOBAL_TRAIN_INTERVAL_SECONDS=300
GLOBAL_TRAIN_MIN_SAMPLES=30
GLOBAL_TRAIN_MAX_SAMPLES=5000
```

Set `GLOBAL_TRAIN_INTERVAL_SECONDS=0` to disable.
