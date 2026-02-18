# Improvement Plan

## Goals
- Make anomaly blocking reliable and fast in real time.
- Improve model quality and reduce false positives.
- Harden security and session controls.
- Keep the codebase easy to maintain.

## Current Gaps
- Real-time behavior monitoring works, but operational safeguards are minimal.
- Blocking logic exists, but lacks observability and admin tooling.
- Test coverage is light (mostly smoke-level).
- Model lifecycle (retraining, drift checks, rollback) is not formalized.

## Roadmap

### Phase 1: Reliability Baseline (1-2 weeks)
1. Add structured logging for API + websocket server.
2. Add request/session correlation IDs.
3. Add health checks for DB and model loading state.
4. Add retry-safe DB writes and timeout handling.

Acceptance criteria:
- API/websocket logs include `session_id`, `username`, and event type.
- `/health` returns dependency status (db/model).
- No unhandled exceptions in normal startup/shutdown paths.

### Phase 2: Security Enforcement (1-2 weeks)
1. Replace hardcoded websocket token with environment secret only.
2. Add token rotation strategy and startup validation.
3. Enforce blocked-user checks on all sensitive routes.
4. Add rate limiting on auth/session endpoints.
5. Add explicit session termination reason codes.

Acceptance criteria:
- No hardcoded secrets in repo.
- Blocked users are denied consistently across API + websocket paths.
- Repeated abusive login attempts are throttled.

### Phase 3: Detection Quality (2-4 weeks)
1. Define anomaly threshold policy per user segment.
2. Add feature validation (missing/invalid event fields).
3. Add offline evaluation script (precision/recall/FPR).
4. Add model versioning metadata and rollback pointer.
5. Add drift detection on behavioral feature distributions.

Acceptance criteria:
- Documented threshold tuning process with baseline metrics.
- New model versions can be promoted/rolled back safely.
- Drift alerts emitted when feature distributions shift.

### Phase 4: Product Usability (1-2 weeks)
1. Add admin endpoint/UI to review security events.
2. Add unblock flow with audit trail.
3. Improve user-facing messaging for blocked sessions.
4. Auto-reconnect strategy with max retry window.

Acceptance criteria:
- Admin can inspect `ANOMALY_BLOCK` events and unblock accounts.
- Users receive clear, actionable block/termination messages.

### Phase 5: Developer Experience (ongoing)
1. Add unit tests for `app/database.py` methods.
2. Add integration tests for auth + websocket anomaly flows.
3. Add linting + formatting (`ruff`, `black`) in CI.
4. Add Makefile commands: `run`, `test`, `lint`, `format`.
5. Add architecture diagram and sequence flow in docs.

Acceptance criteria:
- CI runs tests + lint on every PR.
- Reproducible local workflow in <= 3 commands.

## Priority Task Backlog
1. Remove hardcoded websocket auth token.
2. Add blocked-user checks to every auth/session path.
3. Add security event inspection endpoint.
4. Add websocket anomaly integration test.
5. Add model version file (`models/manifest.json`).

## Risks
- Aggressive thresholds may over-block genuine users.
- Model retraining without version control can regress detection quality.
- Missing observability can hide production incidents.

## Success Metrics
- Mean anomaly decision latency < 200ms.
- False-positive block rate < 2%.
- 100% blocked-user enforcement consistency across routes.
- Test coverage of critical auth/block flows > 80%.

## Suggested Next Step
Start with Phase 2 Task 1 and Task 2 (secret handling + enforcement consistency), then implement Phase 5 Task 1 tests in parallel.
