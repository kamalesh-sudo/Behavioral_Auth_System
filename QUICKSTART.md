# Quickstart Guide

For a fast setup of the Behavioral Authentication System.

## Prerequisites
- Python 3.8+
- Node.js 14+

## 1. Backend Setup

Open a terminal in the `backend` folder:
```bash
cd backend
pip install -r requirements.txt
# If pip fails, try: python -m pip install -r requirements.txt
# Note: You might need to manually install flask-cors: pip install flask-cors
```

Start the API server (Terminal 1):
```bash
python api/auth_api.py
# Runs on http://0.0.0.0:5000
```

Start the WebSocket server (Terminal 2):
```bash
python websocket_server.py
# Runs on ws://localhost:8765
```

## 2. Frontend Setup

Open a terminal in the `frontend` folder (Terminal 3):
```bash
cd frontend
npm install
npm start
# Server runs on http://localhost:3000
```

## 3. Usage Flow

1.  Open your browser to `http://localhost:3000`.
2.  You will be redirected to the login page.
3.  Enter any **username** (e.g., `user1`) and click **Start Session**.
4.  You will be redirected to the **Calibration Page**.
5.  Type the given phrase to register your baseline behavior.
6.  Click **Complete Calibration** to enter the Dashboard.

## Troubleshooting

-   **Database Error**: If you see errors about `users.db`, delete the file in `backend/` and restart the backend processes.
-   **Connection Error**: Ensure both `auth_api.py` and `websocket_server.py` are running.
