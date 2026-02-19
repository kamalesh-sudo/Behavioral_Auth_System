# Freelancer Workspace + Behavioral Security

Python-first freelancer task manager with continuous behavioral anomaly monitoring:
- FastAPI app for REST APIs + static frontend + websocket realtime risk scoring

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

## Start

```bash
cd backend
pip install -r requirements.txt
cd ..
cp .env.example .env
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Set `JWT_SECRET_KEY` (or `AUTH_TOKEN` as fallback) in `.env` before starting services.

Use PostgreSQL by setting:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/behavioral_auth
```

If `DATABASE_URL` is empty, the app uses SQLite via `DB_PATH`.

Optional websocket server (recommended for behavioral scoring):

No separate process needed. WebSocket is served by FastAPI at `/ws/behavioral`.

## Main Endpoints

- `GET /health`
- `POST /api/register`
- `POST /api/start-session`
- `POST /api/login`
- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/{project_id}/tasks`
- `POST /api/projects/{project_id}/tasks`
- `PATCH /api/tasks/{task_id}`
- `GET /api/security-events` (analyst/admin)
- `POST /api/admin/users/{username}/role` (admin)

Frontend pages are served at `http://localhost:5000`.

JWT tokens are now returned by `/api/start-session` and `/api/login`, and the frontend stores them for websocket auth automatically.

Role model:
- `user`: standard account
- `analyst`: can read security events + other user data
- `admin`: full access including role changes
