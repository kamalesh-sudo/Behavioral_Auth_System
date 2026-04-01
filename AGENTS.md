# AGENTS.md

## Project Overview
FastAPI-based Python service with JWT auth, realtime behavioral anomaly detection over WebSocket, SQLite/PostgreSQL persistence, and a vanilla HTML/CSS/JS frontend.

## Key Commands
- Install dependencies: `python -m venv .venv && .venv/bin/pip install -r backend/requirements.txt`
- Run dev server: `.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload`
- Build/syntax gate: `.venv/bin/python -m py_compile app/main.py app/realtime.py app/database.py backend/ml/behavioral_analyzer.py backend/ml/feature_extractor.py`
- Test (all core tests): `.venv/bin/python -m unittest -q tests/test_database.py tests/test_behavioral_ml.py`
- Test single file: `.venv/bin/python -m unittest -q tests/test_behavioral_ml.py`
- Test single case: `.venv/bin/python -m unittest -q tests.test_behavioral_ml.BehavioralMLTests.test_cross_user_impostor_can_reach_alert_threshold`
- Lint: no dedicated linter is configured; use `py_compile` + unit tests as required quality gate.
- Optional legacy websocket server: `.venv/bin/python backend/websocket_server.py`

## Project Structure
- `app/`: FastAPI app, route handlers, auth, settings, DB access layer, realtime service.
- `backend/ml/`: behavioral feature extraction and anomaly/classification logic.
- `backend/models/`: serialized ML artifacts (`*.pkl`, optional `lstm_model.h5`).
- `backend/requirements.txt`: Python dependencies.
- `frontend/login|dashboard|calibration|collector/`: static client pages/scripts served by FastAPI.
- `tests/`: unit tests for database and behavioral ML behavior.
- `README.md`, `QUICKSTART.md`: runbook and onboarding docs.

## Code Style
- Python: snake_case for functions/variables, explicit type hints where practical, and Pydantic models for request payloads.
- API behavior: return structured JSON with stable keys; DB methods typically return `{"success": bool, ...}`.
- Error handling: translate low-level exceptions into safe API errors (`HTTPException` in routes).
- Security-sensitive code must preserve semantics: higher `riskScore` means higher anomaly/suspicion.
- Frontend is vanilla JS (class-based modules, camelCase fields/methods); do not introduce Node tooling unless requested.

## Non-Obvious Patterns
- Route aliasing is intentional: each API endpoint is mounted under root, `/api/*`, and `/api/v1/*` via `route_aliases(...)`.
- WebSocket auth contract is strict: first frame must contain auth token, then message types (`behavioral_data`, `user_authentication`, `feedback`).
- DB engine abstraction is manual: `AuthDatabase` wraps SQLite/PostgreSQL and rewrites query placeholders (`?` -> `%s`) through proxy cursors.
- Schema migration strategy is in-code: startup applies `CREATE TABLE IF NOT EXISTS`, then `_ensure_schema_migrations()` (for example `users.role` and task status normalization).
- Realtime model updates have guardrails: short-event buffering, anti-poisoning profile update checks, and critical-risk passthrough to avoid EMA alert lag.
- `backend/websocket_server.py` is legacy compatibility; primary realtime path is `app/main.py` websocket endpoint `/ws/behavioral`.

## Boundaries
- ✅ **Allowed**
- Read any file in repo and update documentation/tests.
- Modify application code under `app/`, `backend/ml/`, and `frontend/` when task requires.
- Run local quality checks (`py_compile`, `unittest`).

- ⚠️ **Ask First**
- Add/remove Python dependencies in `backend/requirements.txt`.
- Change DB schema/table definitions or migration logic in `app/database.py`.
- Change auth/token contract or public API/WebSocket payload shape used by frontend.
- Delete files or remove existing tests.

- 🚫 **Never**
- Commit secrets from `.env`, tokens, or private credentials.
- Manually edit generated artifacts (`backend/models/*.pkl`, `backend/models/*.h5`, `models/*.pkl`).
- Modify virtualenv/system directories (`.venv/`, `node_modules/`, `dist/`, build caches).
- Use destructive git commands (`git reset --hard`, force-push) without explicit approval.
