# Architecture

## Target Service Design

### Core Module
The core runtime is **`app/realtime.py` + `backend/ml/behavioral_analyzer.py`**.

- `RealtimeBehaviorService` (`app/realtime.py`) orchestrates websocket sessions, auth checks, security policy enforcement (IP/device/user blocking), persistence, and alerting.
- `BehavioralAnalyzer` (`backend/ml/behavioral_analyzer.py`) performs feature extraction, per-user behavioral profiling, impostor risk scoring, drift/context checks, and smoothing/guardrails.

### Request/Processing Flow
1. Client connects to `ws://.../ws/behavioral`.
2. First message must include JWT token (or legacy fallback token).
3. Behavioral packets (`behavioral_data`) are scored in real time.
4. Score and explanation are returned as `analysis_result`.
5. If score >= `ANOMALY_BLOCK_THRESHOLD` (default `0.6`), service blocks user/session and emits security events.
6. Behavioral events are appended to persistent session profile in DB.

### Supporting Modules
- `app/main.py`: HTTP routes and websocket mount, static file mounts, startup background task for periodic global training.
- `app/security.py`: JWT creation/verification (`HS256`) with environment-based secret policy.
- `app/database.py`: unified DB access for SQLite/PostgreSQL via query proxy.
- `app/alerts.py`: optional webhook dispatch for security events.

## Target Data Model

The data layer is defined in `app/database.py` and initialized at startup.

### Tables (SQLite/PostgreSQL parity)

#### `users`
- Columns: `id` (PK), `username` (UNIQUE), `password_hash`, `salt`, `role` (default `user`), `created_at`, `last_login`, `is_active`.
- Purpose: identity, role-based authorization, and block/disable state.

#### `behavioral_profiles`
- Columns: `id` (PK), `user_id` (FK -> `users.id`), `session_id` (UNIQUE), `keystroke_data` (JSON text), `mouse_data` (JSON text), `risk_score`, `timestamp`.
- Purpose: session-level behavioral traces used for history and training.

#### `login_attempts`
- Columns: `id` (PK), `username`, `success`, `risk_score`, `ip_address`, `timestamp`.
- Purpose: auth auditing and temporary IP abuse detection.

#### `security_events`
- Columns: `id` (PK), `username`, `session_id`, `risk_score`, `event_type`, `reason`, `timestamp`.
- Purpose: durable event trail for analyst/admin monitoring.

#### `blocked_ips`
- Columns: `id` (PK), `ip_address` (UNIQUE), `reason`, `blocked_until`, `blocked_by`, `created_at`, `updated_at`.
- Purpose: policy-driven IP deny list, supports temporary and permanent blocks.

#### `blocked_devices`
- Columns: `id` (PK), `fingerprint_hash` (UNIQUE), `reason`, `blocked_by`, `created_at`, `updated_at`.
- Purpose: deny list for hashed device fingerprints.

#### `user_devices`
- Columns: `id` (PK), `user_id` (FK), `fingerprint_hash`, `first_seen`, `last_seen`, `last_ip`, `UNIQUE(user_id, fingerprint_hash)`.
- Purpose: known-device tracking and new-device eventing.

#### `projects`
- Columns: `id` (PK), `owner_id` (FK -> `users.id`), `name`, `description`, `created_at`, `updated_at`.
- Purpose: project workspace ownership model.

#### `tasks`
- Columns: `id` (PK), `project_id` (FK), `title`, `description`, `status`, `priority`, `assignee_id` (FK), `due_date`, `created_by` (FK), `created_at`, `updated_at`.
- Purpose: task tracking with assignee scoping and status pipeline.

### Indexes
Indexes exist for lookup-heavy columns including usernames, profile user IDs, login timestamps, security event usernames, blocked IP/device keys, user-device keys, project owner, and task project/assignee.

### Migration Strategy
- No external migration framework is used.
- Startup schema strategy:
1. `CREATE TABLE IF NOT EXISTS` for all tables.
2. `_ensure_schema_migrations(conn)` applies additive/repair migrations:
   - add `users.role` if missing,
   - normalize invalid `tasks.status` values to `'todo'`.
3. Create/refresh indexes idempotently.

This is an **in-code migration model**. Changes must remain backward-compatible and idempotent.

## API Design Overview

`app/main.py` registers alias paths for root + `/api` + `/api/v1`.

### Health and Monitoring
- `GET /health`: service health metadata.
- `GET /security-events`: analyst/admin view of security events (`limit`, optional `username`).
- `GET /realtime-monitor`: analyst/admin realtime metrics and recent events snapshot.

### Authentication and Session
- `POST /register` (`Credentials`): create user.
- `POST /start-session` (`Credentials`): create-or-verify user, issue JWT, device registration.
- `POST /login` (`LoginPayload`): verify user with risk-aware and device-aware controls.

### Behavioral Data
- `POST /behavioral-profile` (`BehavioralProfilePayload`, auth required): persist profile samples.
- `GET /user/{user_id}/behavioral-history` (auth/role restricted): recent risk history.

### Admin and Security Controls
- `POST /admin/users/{username}/role`
- `GET /admin/users`
- `POST /admin/users/{username}/status`
- `POST /admin/security/block-ip`
- `POST /admin/security/unblock-ip`
- `GET /admin/security/blocked-ips`
- `POST /admin/security/block-device`
- `POST /admin/security/unblock-device`
- `GET /admin/security/blocked-devices`

### Work Management
- `GET /projects`
- `POST /projects`
- `GET /projects/{project_id}/tasks` (and compatibility alias `/task`)
- `POST /projects/{project_id}/tasks` (and compatibility alias `/task`)
- `PATCH /tasks/{task_id}` (and compatibility alias `/task/{task_id}`)

### WebSocket API
- Endpoint: `WS /ws/behavioral`
- Initial auth frame: `{"token": "<jwt-or-legacy-token>"}`
- Message types:
  - `behavioral_data` with `userId`, `sessionId`, `keystrokeData`, `mouseData`, optional `context`
  - `user_authentication`
  - `feedback`
- Response types:
  - `analysis_result` (`riskScore`, `riskExplanation`, optional `alert`)
  - `authentication_success`
  - `feedback_received`
  - `session_terminated`
  - `error`

## Validation Plan

### 1) Database correctness
- Run: `.venv/bin/python -m unittest -q tests/test_database.py`
- Validate: user lifecycle, blocking/unblocking, security event logging, behavioral persistence, projects/tasks flow.

### 2) Behavioral ML correctness
- Run: `.venv/bin/python -m unittest -q tests/test_behavioral_ml.py`
- Validate:
  - finite feature extraction outputs,
  - low-signal fallback behavior,
  - short-window accumulation before scoring,
  - anomaly risk increase versus baseline,
  - context novelty risk behavior,
  - cross-user impostor risk and separation behavior,
  - anti-poisoning profile update guardrail,
  - critical risk bypasses EMA lag for alerting.

### 3) API/WebSocket parity checks
- Start server:
  - `.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload`
- Verify:
  - JWT issuance in `/start-session` and `/login`,
  - websocket token handshake requirement,
  - anomaly block path (`session_terminated`, user/device/IP block effects),
  - monitor snapshots at `/api/realtime-monitor`.

### 4) Static analysis/syntax gate
- Run:
  - `.venv/bin/python -m py_compile app/main.py app/realtime.py app/database.py backend/ml/behavioral_analyzer.py backend/ml/feature_extractor.py`

### 5) Known caveats to track
- `tests/smoke_test.py` may drift from current function signatures; treat as legacy unless updated.
- `frontend/login/README.md` documents a legacy websocket endpoint; current primary websocket path is `/ws/behavioral` via FastAPI.
