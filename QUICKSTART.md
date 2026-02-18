# Quickstart Guide

## Prerequisites
- Python 3.9+

## 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
cd ..
```

## 2. Configure Environment

```bash
cp .env.example .env
```

Adjust values in `.env` if needed (`APP_PORT`, `DB_PATH`, `FRONTEND_DIR`, etc.).

## 3. Run Services

Terminal 1: FastAPI app (API + frontend static)
```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

Terminal 2: Behavioral websocket server
```bash
cd backend
python websocket_server.py
```

## 4. Open the App
- Login UI: `http://localhost:5000/login/login.html`
- Health: `http://localhost:5000/health`
- API docs: `http://localhost:5000/docs`

## Core Endpoints
- `POST /query`
- `POST /upload`
- `GET /health`
- `POST /api/start-session`
- `POST /api/login`
- `POST /api/behavioral-profile`
