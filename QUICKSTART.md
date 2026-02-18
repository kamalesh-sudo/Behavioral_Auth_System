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

## 3. Run API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

## 4. Run websocket analyzer (optional but recommended)

```bash
cd backend
python websocket_server.py
```

## 5. Open

- Login: `http://localhost:5000/login/login.html`
- Swagger: `http://localhost:5000/docs`
- Health: `http://localhost:5000/health`
