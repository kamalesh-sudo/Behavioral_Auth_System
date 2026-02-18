# Login + Behavioral Authentication

The login UI sends credential/session calls to FastAPI and behavioral telemetry to the websocket analyzer.

## Runtime

1. FastAPI (API + static frontend):
```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

2. WebSocket analyzer:
```bash
cd backend
python websocket_server.py
```

## URLs
- Login page: `http://localhost:5000/login/login.html`
- API docs: `http://localhost:5000/docs`

## Primary API calls used by login flow
- `POST /api/start-session`
- `POST /api/login`
- `POST /api/behavioral-profile`
- `GET /api/user/{username}`
- `GET /api/user/{user_id}/behavioral-history?limit=10`
