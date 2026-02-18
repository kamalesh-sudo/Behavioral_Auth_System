# Login Frontend

This page is served directly by FastAPI and uses:
- REST API at `http://localhost:5000/api/...`
- WebSocket analyzer at `ws://localhost:8765`

## Run backend

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

## Run websocket analyzer

```bash
cd backend
python websocket_server.py
```

## Open login

`http://localhost:5000/login/login.html`
