# Quickstart

## 1. Install dependencies

```bash
cd backend
pip install -r requirements.txt
cd ..
```

## 2. Configure env

```bash
cp .env.example .env
```

Set JWT secret in `.env`:

```bash
JWT_SECRET_KEY=replace_with_strong_secret
INITIAL_ADMIN_USERNAME=admin
```

Choose one database mode:

```bash
# SQLite (default)
DB_PATH=backend/users.db
DATABASE_URL=

# PostgreSQL (recommended for production)
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/behavioral_auth
```

## 3. Run API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

## 4. Websocket analyzer

No separate websocket server is required now. Realtime monitoring is served from FastAPI at `/ws/behavioral`.

## 5. Open

- Login: `http://localhost:5000/login/login.html`
- Workspace: `http://localhost:5000/dashboard/index.html`
- Swagger: `http://localhost:5000/docs`
- Health: `http://localhost:5000/health`

JWT is issued by `/api/start-session` and stored by the frontend automatically.

Optional:
- Set `ALERT_WEBHOOK_URL` to receive security event webhooks.
