# Freelancer Workspace + Behavioral Security

Python-first freelancer task manager with continuous behavioral anomaly monitoring.

## Core Stack

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

File: `.env`

```bash
cp .env.example .env
```

File: `backend/requirements.txt`

```bash
cd backend
pip install -r requirements.txt
cd ..
```

File: `app/main.py`

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Before starting, set `JWT_SECRET_KEY` (or `AUTH_TOKEN` fallback) in `.env`.

Default database is SQLite (`DB_PATH` in `.env`).
Use PostgreSQL by setting:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/behavioral_auth
```

If `DATABASE_URL` is empty, the app uses SQLite automatically.

Realtime WebSocket is served by FastAPI at `/ws/behavioral`.
No extra process is needed.

Legacy standalone WebSocket server file:
- `backend/websocket_server.py`

Run it only if you specifically need the legacy mode:

```bash
python backend/websocket_server.py
```

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
  - Compatibility aliases: `/api/projects/{project_id}/task`, `/api/task/{task_id}`
- Security and monitoring
  - `GET /api/security-events` (analyst/admin)
  - `GET /api/realtime-monitor` (analyst/admin)
- Administration
  - `POST /api/admin/users/{username}/role` (admin)
  - `GET /api/admin/users` (analyst/admin)
  - `POST /api/admin/users/{username}/status` (admin)
  - `POST /api/admin/security/block-ip` (analyst/admin)
  - `POST /api/admin/security/unblock-ip` (analyst/admin)
  - `GET /api/admin/security/blocked-ips` (analyst/admin)
  - `POST /api/admin/security/block-device` (analyst/admin)
  - `POST /api/admin/security/unblock-device` (analyst/admin)
  - `GET /api/admin/security/blocked-devices` (analyst/admin)

## Security Features

- IP blocklist checks on authentication and WebSocket connections
- Device fingerprint blocklist checks on authentication and behavioral traffic
- Known-device tracking per user (`user_devices`) with new-device security events
- Automatic temporary IP blocks after repeated failed login attempts

Frontend pages are served at `http://localhost:5000`.

`/api/start-session` and `/api/login` return JWTs.
The frontend stores and reuses them for WebSocket authentication.

## Roles

- `user`: standard account
- `analyst`: can read security events and user data
- `admin`: full access, including role and status changes

## Realtime Monitoring

Run API with verbose logs:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload --log-level info
```

Tail logs while presenting to beginners:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload --log-level info
```

The realtime service emits `realtime_event` logs for:

- WebSocket connect, auth, and disconnect events
- Behavioral packet receipt and risk scoring
- Profile updates and training state
- Anomaly blocks and session termination

Query monitor state (as `analyst` or `admin`):

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

## Presentation Tips for Beginners

Use these tips when explaining code to new developers:

- Show full code when the listener needs to run it end-to-end.
- Show snippets when teaching one concept, one function, or one bug fix.
- Add this pattern before each demo block: `File -> Command -> Expected Result`.
- Example mini-flow: `backend/websocket_server.py` -> `python backend/websocket_server.py` -> "server listens on configured host/port".
- Add a one-line context before each code block: what it does and where it runs.
- Keep snippets short (5-20 lines) so the key idea is easy to see.
- Highlight placeholders clearly, such as `<TOKEN>` or `your_username`.
- Add expected output when possible so beginners can verify success.
- Keep command examples and app code separate to avoid confusion.
