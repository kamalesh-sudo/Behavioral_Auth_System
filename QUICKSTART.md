# Quickstart

Use this guide to run the project quickly on your local machine.

## 1. Install Dependencies

File context:
- Work from project root: `Behavioral_Auth_System/`
- Install from: `backend/requirements.txt`

```bash
cd backend
pip install -r requirements.txt
cd ..
```

## 2. Configure Environment Variables

File to edit: `.env` (create from template first)

```bash
cp .env.example .env
```

Open `.env` and set these required values:

```bash
JWT_SECRET_KEY=replace_with_strong_secret
INITIAL_ADMIN_USERNAME=admin
```

Choose one database mode:

```bash
# Option A: SQLite (default, easiest for local development)
DB_PATH=backend/users.db
DATABASE_URL=

# Option B: PostgreSQL (recommended for production)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/behavioral_auth
```

## 3. Start the API Server

File used by command: `app/main.py`
Run from project root:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

## 4. Realtime Behavioral Monitoring

No separate WebSocket server is required.
FastAPI serves realtime monitoring at `/ws/behavioral`.

Legacy option (not required for normal setup):

```bash
python backend/websocket_server.py
```

## 5. Open the App

- Login page: `http://localhost:5000/login/login.html`
- Workspace dashboard: `http://localhost:5000/dashboard/index.html`
- API docs (Swagger): `http://localhost:5000/docs`
- Health check: `http://localhost:5000/health`
- Realtime monitor API: `GET /api/realtime-monitor` (analyst/admin token required)

JWT is issued by `/api/start-session` and stored by the frontend automatically.

## Optional Settings

- Set `ALERT_WEBHOOK_URL` to receive security event webhooks.
- Enable automatic global model training:
  - `GLOBAL_TRAIN_INTERVAL_SECONDS=300`
  - `GLOBAL_TRAIN_MIN_SAMPLES=30`
  - `GLOBAL_TRAIN_MAX_SAMPLES=5000`

## Presentation Tips for Newbies

Use these rules when reading or presenting code:

- Full code block: Use when someone needs complete, runnable steps.
- Snippet: Use when explaining one idea or one small change.
- Mention the target file before every block: Example, "File: `backend/websocket_server.py`".
- Add command line right after file mention: Example, ``python backend/websocket_server.py``.
- Keep one purpose per block: Avoid mixing setup, run, and debugging in one block.
- Add a short label before each block: Example, "Install dependencies" or "Run server".
- Explain expected result after commands: Example, "Server should start on port 5000".
- Prefer copy-paste-safe commands: Avoid placeholders unless you explain them right below.
