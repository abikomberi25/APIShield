# APIShield — Project Progress

Last updated based on repository HEAD `fe125a7` with all milestones through M8 complete.

---

## Phase 1 — Project Setup (M0)

**Objective:** Create a clean repository structure before writing any application code.

**Status:** Complete

**Main files:** `SPEC.md`, `.gitignore`, `README.md`, directory scaffolding

**Implementation:**
- Created `backend/`, `attacks/`, `detection/`, `tests/`, `docs/` directories
- Wrote `SPEC.md` defining the project scope, safety rules, and milestone plan
- Initialized git and made the first commit, tagged `m0-skeleton-complete`

**Testing:** No application code to test at this stage.

**Result:** The project structure established here remained stable throughout development. The spec was referenced repeatedly when making design decisions.

---

## Phase 2 — FastAPI Baseline (M1-A through M1-D)

**Objective:** Build a working FastAPI backend with SQLite storage, JWT authentication, bcrypt password hashing, and protected item routes.

**Status:** Complete

**Main files:**
- `backend/main.py` — FastAPI app factory
- `backend/config.py` — JWT secret, lab mode flag, dotenv loading
- `backend/database.py` — SQLAlchemy engine and session factory
- `backend/models/user.py`, `backend/models/item.py` — ORM models
- `backend/auth/security.py` — bcrypt hashing, JWT creation and verification
- `backend/auth/deps.py` — `get_current_user()` and `require_admin()` dependencies
- `backend/routes/auth.py` — `POST /auth/login`
- `backend/routes/items.py` — `GET /items/{id}` (authorization checks here)
- `backend/seed.py` — synthetic data seeder
- `tests/test_auth.py`, `tests/test_items.py`, `tests/test_seed.py`

**Implementation:**
- M1-A: Health endpoint (`GET /health`)
- M1-B: SQLite + SQLAlchemy + User and Item models
- M1-C: bcrypt hashing with 12 rounds; constant-time `verify_password()`
- M1-D: JWT (HS256, 30-minute expiry) with role-based claims; protected item route

**Testing:** Unit tests for authentication, JWT edge cases (expired, malformed, tampered), item authorization, and seeding idempotence.

**Result:** Stable foundation. The `get_current_user()` dependency and the ownership check in `GET /items/{id}` remained unchanged throughout all subsequent milestones.

**Notable issue:** `ModuleNotFoundError: No module named 'backend'` on first Uvicorn run — resolved by launching from the project root.

---

## Phase 3 — Security Gateway and Defense Toggles (M2)

**Objective:** Add a middleware layer that measures latency, implement runtime defense toggles, and build the security event logging infrastructure.

**Status:** Complete

**Main files:**
- `backend/security/middleware.py` — `SecurityGatewayMiddleware`
- `backend/security/defenses.py` — `DefenseManager`
- `backend/security/events.py` — `log_security_event()`
- `backend/routes/admin.py` — `/admin/defenses`, `/admin/events`, `/admin/lab-mode`
- `tests/test_defenses.py`, `tests/test_events.py`, `tests/test_middleware.py`

**Implementation:**
- Middleware adds `X-Response-Time-Ms` header using `time.perf_counter()`
- `DefenseManager` stores six boolean toggles in memory, all defaulting to `False`
- Admin API enforces validation: unknown toggle names and non-boolean values return HTTP 422
- `log_security_event()` validates event fields before persisting; raises `SecurityEventPersistenceError` if the database write fails (fail-closed design)

**Testing:** Tests verify that the latency header is present on all responses, that toggle updates are validated, that admin-only endpoints reject non-admin tokens, and that event pagination and filtering work correctly.

**Result:** Complete. The middleware ordering issue (CORS before gateway in Starlette's reverse-application order) was resolved early.

---

## Phase 4 — BOLA Experiment (M3)

**Objective:** Implement the first full end-to-end vulnerability module: BOLA (API1:2023).

**Status:** Complete

**Main files:**
- `backend/routes/items.py` — BOLA ownership check
- `detection/bola.py` — `detect_bola()`
- `attacks/bola.py` — dual-run attack script
- `tests/test_bola.py` — 17 tests

**Implementation:**
- Ownership check gate in `GET /items/{id}`: outside lab mode → always HTTP 403; inside lab mode → evaluate `bola` toggle
- Detection emits event with `rule_name="bola_cross_tenant_access"`, `severity="HIGH"`, action `"detected"` or `"blocked"`
- Attack script: validates target URL, authenticates as Alice, requests item 3 (Bob's), verifies the correlated security event
- Dual-run orchestration in `main()`: captures original `bola` toggle state, runs vulnerable pass, runs defended pass, restores state in finally block, writes combined JSON only after both passes verified

**Testing:** Covers auth baseline, owner access (no events), admin access (no events), nonexistent item (404), safe-mode behavior (always 403), vulnerable mode (200 + detected event), defended mode (403 + blocked event), fail-closed behavior, attack script allowlist validation, and dual-run orchestration.

**Result:** Complete. Event ID baseline correlation prevents false correlation with prior experiments.

---

## Phase 5 — BFLA/RBAC Experiment (M4-A)

**Objective:** Implement function-level authorization bypass: Alice accessing admin-only `GET /admin/events`.

**Status:** Complete

**Main files:**
- `backend/routes/admin.py` — RBAC-gated events endpoint
- `detection/rbac.py` — `detect_bfla()`
- `attacks/rbac.py` — dual-run attack script
- `tests/test_rbac.py` — 15 tests

**Implementation:**
- The BFLA vulnerability is isolated to `GET /admin/events` only. `require_admin()` remains strict on all other admin routes.
- When `rbac` toggle is off and lab mode is on: non-admin users receive the event list and a detected event is logged.
- When `rbac` toggle is on: HTTP 403 and a blocked event is logged.
- Attack script uses baseline event ID before attacking to correlate the specific event generated.

**Testing:** Covers admin access (always works), non-admin access in various states, event correlation, detection without blocking, blocking with detection, and attack script allowlist rejection.

**Result:** Complete. The key design insight — isolating the vulnerability to one endpoint rather than weakening the shared `require_admin()` dependency — preserved the integrity of the other admin routes.

---

## Phase 6 — BOPLA Experiment (M4-B)

**Objective:** Simulate excessive data exposure: Alice requesting restricted internal fields (`internal_notes`, `is_confidential`) on her own item using `?include_internal=true`.

**Status:** Complete

**Main files:**
- `backend/models/item.py` — added `internal_notes` and `is_confidential` fields
- `backend/routes/items.py` — BOPLA property check
- `backend/seed.py` — updated to seed internal field values, plus migration check
- `detection/bopla.py` — `detect_bopla_read()`
- `attacks/bopla.py` — dual-run attack script
- `tests/test_bopla.py` — 34 tests

**Implementation:**
- Schema migration: `seed.py` checks `PRAGMA table_info(items)` and adds missing columns with `ALTER TABLE` to avoid destroying existing development databases.
- Detection gate: when non-admin requests `?include_internal=true` in lab mode, `detect_bopla_read()` always runs. If `schema_validation` is off: `ItemInternalResponse` returned. If on: HTTP 403.
- `verification_passed: bool` added to prevent false success from ambiguous outcome strings.
- Dual-run orchestration with seven-field event correlation.

**Testing:** Covers property exposure in vulnerable mode, schema validation in defended mode, fail-closed on event failure, dual-run orchestration, exception path restoration, second toggle failure behavior, and suppression of combined results when `results_path=False`.

**Result:** Complete. Three separate implementation bugs found and fixed during this milestone: schema migration issue, outcome string ambiguity, and insufficiently specific event correlation.

---

## Phase 7 — Broken Authentication (M4-C)

**Objective:** Simulate brute-force login: seven failed attempts against Alice's account. With `auth_hardening` off: account stays open. With it on: account locks after attempt 5.

**Status:** Complete

**Main files:**
- `backend/security/lockout.py` — `LoginAttemptTracker`
- `backend/routes/auth.py` — lockout check integrated into login route
- `detection/auth.py` — `detect_brute_force()`
- `attacks/auth.py` — dual-run attack script
- `tests/test_auth_hardening.py` — 20 tests

**Implementation:**
- `LoginAttemptTracker` maintains per-username failure timestamps in a rolling 5-minute window using a threading lock.
- After 5 failures, `lockout_until` is set 5 minutes in the future. Subsequent login attempts within that window return HTTP 429 with a `Retry-After` header.
- The login route checks lockout state before verifying the password (defense on). Failure tracking always runs regardless of defense state.

**Testing:** Covers lockout trigger, lockout expiry, success clearing failure history, independent per-user tracking, detection events, and attack script dual-run behavior.

**Result:** Complete.

---

## Phase 8 — Rate Limiting (M5)

**Objective:** Simulate unrestricted resource consumption: Alice sends 25 requests in a short window. Rate limiter allows 20, rejects 5 with HTTP 429 when defense is on.

**Status:** Complete

**Main files:**
- `backend/security/rate_limiter.py` — `RateLimiter` (fixed window, 20 req / 60 s)
- `backend/security/rate_limit_dep.py` — `check_rate_limit()` FastAPI dependency
- `detection/rate_limit.py` — `detect_rate_limit_exceeded()`
- `attacks/rate_limit.py` — dual-run attack script with latency measurement
- `tests/test_rate_limit.py` — 13 tests

**Implementation:**
- Rate limiter keyed by `user:<user_id>` (not IP address, since all lab traffic comes from loopback).
- Applied to `GET /items/{id}` via the `check_rate_limit` dependency.
- Latency measured with `time.perf_counter()` per request; p50 and p95 included in result JSON.

**Testing:** Unit tests for window reset behavior, `reset_key()` and `reset_all()` isolation methods, 429 response content, detection events, and dual-run outcomes.

**Result:** Complete. Actual experiment result: vulnerable run allowed 25/25 requests (p50 = 6.25 ms); defended run limited 25/25 requests at HTTP 429 (p50 = 14.53 ms).

---

## Phase 9 — React Dashboard (M6)

**Objective:** Build a frontend that shows API health, lab mode status, live defense toggle controls, the security event log, and experiment result cards.

**Status:** Complete

**Main files:**
- `frontend/src/App.jsx` — four-tab dashboard
- `frontend/src/api.js` — API client functions
- `frontend/public/results/` — static JSON result files served to the browser
- `frontend/vite.config.js` — Vite configuration with API proxy

**Implementation:**
- Four tabs: Status, Defenses, Events, Results.
- JWT held in React component state only (not localStorage).
- Results loaded from static JSON files in `public/results/` — not fetched from the API at runtime.
- Each result card shows Vulnerable Run and Defended Run as separate columns.
- CORS configured in `backend/main.py` for `localhost:5173` and `127.0.0.1:5173`.

**Testing:** No automated pytest tests for the frontend. Manual verification via browser.

**Result:** Complete. CORS preflight issue resolved by ensuring `CORSMiddleware` is added after `SecurityGatewayMiddleware` in `main.py`.

---

## Phase 10 — Inventory Management (M7)

**Objective:** Simulate improper inventory management: a deprecated route (`/api/v0/items/{id}`) that is accessible when the defense is off.

**Status:** Complete

**Main files:**
- `backend/routes/inventory.py` — deprecated route + inventory listing
- `backend/security/defenses.py` — added `deprecated_route_protection` toggle
- `detection/inventory.py` — `detect_deprecated_route_access()`
- `attacks/inventory.py` — dual-run attack script
- `tests/test_inventory.py` — 17 tests

**Implementation:**
- `GET /api/v0/items/{id}` only works in lab mode. Outside lab mode: HTTP 404.
- When `deprecated_route_protection` is off and lab mode is on: returns item data, emits detected event.
- When toggle is on: HTTP 403, blocked event emitted.
- `GET /admin/inventory` lists all routes including deprecated ones (admin only).

**Testing:** Covers admin-only inventory endpoint, deprecated route gating, vulnerable and defended behavior, event correlation, and attack script allowlist validation.

**Result:** Complete.

---

## Phase 11 — Evaluation Framework and Documentation (M8)

**Objective:** Create a multi-run evaluation script and finalize all project documentation.

**Status:** Complete (framework implemented; aggregate results require a live server session)

**Main files:**
- `scripts/evaluate.py` — evaluation framework
- `docs/results/evaluation_summary.json` — placeholder (requires live server run)
- `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/TESTING.md`
- `docs/EXPERIMENT_METHODOLOGY.md`, `docs/FINAL_REPORT.md`
- `docs/results/README.md`

**Implementation:**
- `evaluate.py` can call each attack module's `main()` function N times and count successes and failures.
- All five main result files (`bola`, `bopla`, `rbac`, `auth`, `rate_limit`) contain genuine dual-run results from live experiment runs.
- `evaluation_summary.json` contains a placeholder with instructions for generating real aggregate data.

**Testing:** Experiment result files verified by manual inspection. `evaluate.py` verified by unit structure review; live aggregate run not included in the automated test suite.

**Result:** Complete for the per-module results. Aggregate multi-run statistics not yet generated.

---

## Phase 12 — Docker Support

**Objective:** Package the application for containerized deployment.

**Status:** Complete

**Main files:**
- `Dockerfile`
- `docker-compose.yml`

**Implementation:**
- Python 3.12-slim base image, non-root user (`apishield`), `HEALTHCHECK` on `GET /health`.
- `docker-compose.yml` passes `JWT_SECRET` from host environment.
- `JWT_SECRET` is explicitly not hardcoded in the image.

**Result:** Complete. Note: the `docker-compose.yml` publishes port 8000 on `0.0.0.0` within the container, which is necessary for host access to the containerized service, unlike the development setup which always uses `127.0.0.1`.

---

## Overall Summary

| Phase | Description | Status |
|---|---|---|
| 1 | Project setup | Complete |
| 2 | FastAPI + auth + database | Complete |
| 3 | Security gateway + toggles | Complete |
| 4 | BOLA (API1) | Complete |
| 5 | BFLA/RBAC (API5) | Complete |
| 6 | BOPLA (API3) | Complete |
| 7 | Broken Auth (API2) | Complete |
| 8 | Rate Limiting (API4) | Complete |
| 9 | React Dashboard | Complete |
| 10 | Inventory Management (API9) | Complete |
| 11 | Evaluation Framework | Complete (single-run results); aggregate stats pending |
| 12 | Docker | Complete |

**Test count:** 162 tests, all passing.

**Remaining work:**
- Multi-run aggregate statistics via `scripts/evaluate.py` against a live server
- Additional OWASP categories (API6, API7, API8)
- Distributed rate limiting with Redis for multi-worker support
