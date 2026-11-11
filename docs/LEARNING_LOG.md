# APIShield — Learning Log

This document records the development journey of APIShield chronologically. For each phase, it explains what I was trying to build, what actually happened, what went wrong, and what I took away from it. The goal is to make the implementation process transparent — not just show the finished result.

---

## M0 — Project Skeleton

### What I was trying to do

Set up a clean repository that could serve as a foundation for the entire project. The main goal was to decide on the folder structure before writing any real code, so I would not have to reorganize later.

### What I implemented

Created the basic directory tree: `backend/`, `attacks/`, `detection/`, `tests/`, `docs/`. Wrote `SPEC.md` as the project contract, added a `.gitignore`, and made the first commit tagged `m0-skeleton-complete`.

### What I learned

Starting with a clear specification before writing code is genuinely useful. The `SPEC.md` defined safety rules (localhost-only, synthetic data, no hardcoded secrets) that shaped every later decision. It is much easier to enforce rules you wrote down before you got into the implementation.

---

## M1-A — FastAPI Health Endpoint

### What I was trying to do

Get the simplest possible FastAPI app running so I could confirm the project structure was correct.

### What I implemented

`backend/main.py` with a single `GET /health` endpoint returning `{"status": "ok"}`. Installed `fastapi` and `uvicorn` in a virtual environment.

### What went wrong

The first attempt to run `uvicorn backend.main:app` failed with `ModuleNotFoundError: No module named 'backend'`. The fix was straightforward: Uvicorn must be launched from the project root directory, not from inside `backend/`. This seems obvious afterward, but it took a moment to figure out the first time.

### What I learned

Python imports are relative to where the process starts. When you structure a project as a package, you have to run everything from the top level. This also meant using `python -m uvicorn` rather than the bare `uvicorn` command to ensure the working directory is the module root.

---

## M1-B — SQLite Database and User Model

### What I was trying to do

Add persistent storage. I wanted to store users and items in SQLite using SQLAlchemy so I would not have to manage raw SQL.

### What I implemented

`backend/database.py` with the SQLAlchemy engine, session factory, and `Base`. `backend/models/user.py` and `backend/models/item.py` as ORM models. The database uses `sqlite:///./apishield.db` by default.

### What I learned

SQLAlchemy's `Base.metadata.create_all()` creates tables only if they do not already exist. This is useful for creating the schema on first run, but it also means that if you add a column to a model later, the existing database will not get the new column automatically. I ran into this during BOPLA (M4-B) when I added `internal_notes` and `is_confidential` to the `Item` model. The solution was a custom migration check using `PRAGMA table_info(items)` to add missing columns without destroying existing data.

---

## M1-C — bcrypt Password Hashing

### What I was trying to do

Store passwords securely. The project specification required bcrypt, not plain MD5 or SHA-256.

### What I implemented

`backend/auth/security.py` with `hash_password()` using `bcrypt.gensalt(rounds=12)` and `bcrypt.hashpw()`, and `verify_password()` using `bcrypt.checkpw()`.

### What I learned

bcrypt automatically generates and embeds a random salt into the hash output. This means two calls to `hash_password("same_password")` produce different hashes, which is exactly what you want. The `rounds=12` parameter controls how slow the hashing is — more rounds means more time for each attempt, which makes offline brute-force attacks harder.

The `checkpw` function uses constant-time comparison internally, which prevents timing attacks where an attacker could figure out how many characters of a password are correct by measuring how long the comparison takes.

---

## M1-D — JWT Authentication and Protected Endpoints

### What I was trying to do

Add a login endpoint that returns a JWT, and protect the item routes so only authenticated users can access them.

### What I implemented

`POST /auth/login` in `backend/routes/auth.py`. On successful login it calls `create_access_token()` from `backend/auth/security.py`, which builds a payload with `sub` (user ID), `iat` (issued at), `exp` (expiry), `username`, and `role`, then signs it using HS256.

`backend/auth/deps.py` provides `get_current_user()` as a FastAPI dependency that extracts and validates the JWT from the `Authorization: Bearer` header on every protected request.

### What went wrong

Early on, I was storing the user ID as an integer in the `sub` field. JWT's `sub` claim is specified to be a string, so PyJWT was inconsistent about how it serialized and deserialized it. The fix was to always encode it as `str(user_id)` and parse it back to `int` when looking up the user.

### What I learned

JWTs are not encrypted — they are just signed. Anyone can decode the payload with a base64 decoder. The signature only proves that the server issued the token and that it has not been tampered with. This is why you must never put sensitive data like passwords or authorization decisions in the token that are not already public.

Token expiry (`exp` claim) is enforced by PyJWT's `decode()` call. If the token is expired, it raises `ExpiredSignatureError`, which I catch and convert to an HTTP 401. This distinction matters for the BOLA tests that explicitly check that expired tokens return 401, not 403.

---

## M2 — Security Gateway and Defense Toggles

### What I was trying to do

Add a middleware layer that runs before every request, and build the in-memory defense toggle system.

### What I implemented

`backend/security/middleware.py` — `SecurityGatewayMiddleware` measures end-to-end request time using `time.perf_counter()` and adds the `X-Response-Time-Ms` header to every response.

`backend/security/defenses.py` — `DefenseManager` as a simple in-memory dictionary. All toggles default to `False`. The admin API (`PATCH /admin/defenses`) validates that only known toggle names and boolean values are accepted.

`backend/security/events.py` — `log_security_event()` as the shared event persistence function used by all detection modules.

### What went wrong

I initially put the CORS middleware after the security gateway middleware. This caused browser preflight `OPTIONS` requests to get a `405 Method Not Allowed` before CORS headers could be added. The fix was to register CORS middleware after the gateway middleware in `main.py`, because FastAPI/Starlette applies middleware in reverse registration order (last registered runs first).

### What I learned

Middleware ordering in FastAPI is counterintuitive. You call `app.add_middleware()` in the order you want things to run, but they are actually applied in reverse. CORS handling needs to happen before anything else sees the request, so it needs to be registered last.

I also learned the difference between a blocked request and a detected event. At this point in the project, I had the middleware measuring latency, but I had not yet connected the detection logic. The important design decision was to make event logging happen regardless of whether the defense blocks the request. Blocking and detecting are two separate things.

---

## M3 — BOLA (API1:2023)

### What I was trying to do

Implement the first full end-to-end vulnerability module: BOLA (Broken Object Level Authorization). Alice should be able to access Bob's item when the defense is off, and be blocked when it is on.

### What I implemented

The ownership check in `backend/routes/items.py` at `GET /items/{item_id}`:
- If the user is the owner or an admin, let them through.
- If neither, and lab mode is off: HTTP 403 immediately (safe default).
- If lab mode is on: call `detect_bola()`, then either return the item (defense off) or HTTP 403 (defense on).

`detection/bola.py` — calls `log_security_event()` with `rule_name="bola_cross_tenant_access"`, `owasp_category="API1:2023"`, `severity="HIGH"`.

`attacks/bola.py` — the attack script validates the target URL before any network call, authenticates as Alice, requests Bob's item (ID 3), then authenticates as admin and checks whether the correct event was created.

### What I predicted

I initially thought that just receiving an HTTP 403 was enough to prove the defense worked.

### What actually happened

The event correlation step made me realize that blocking a request and recording a security event are two different things. A firewall can block a request without knowing what kind of attack it was. APIShield's design is different: the detection engine explicitly identifies the attack type, records it, and then the defense decides whether to block.

The attack script's verification step — checking that an event with `id > baseline_id` and the right category, rule, endpoint, user, and action was created — ensures the detection actually ran, not just that the response code was what we expected.

### What I learned

The fail-closed behavior was an important design decision: if the security event cannot be persisted to the database (simulated in tests by patching `log_security_event` to raise an exception), the route handler returns HTTP 500 instead of allowing the request through. This prevents an attacker from exploiting a database failure to bypass detection.

The dual containment pattern — lab mode AND defense toggle — means a production server started normally can never exhibit BOLA. The vulnerable code path only runs when you explicitly opt in at startup.

---

## M4-A — BFLA/RBAC (API5:2023)

### What I was trying to do

Simulate Broken Function Level Authorization: a regular user (Alice) accessing an admin-only endpoint (`GET /admin/events`).

### What I predicted

I thought the simplest approach would be to modify `require_admin()` to allow non-admins through when the RBAC toggle is off.

### What actually happened

That approach would have broken every other admin endpoint (`/admin/defenses`, `/admin/lab-mode`). Those endpoints need to stay secure even during the BFLA experiment. Making `require_admin()` toggle-aware would have undermined the experiment's validity — you cannot meaningfully test function-level authorization bypass if the bypass also disables the authorization that protects the defense toggles themselves.

The solution was to keep `require_admin()` strict everywhere and implement the RBAC vulnerability directly in the `GET /admin/events` route handler as a separate, isolated code path.

### What I learned

Simulated vulnerabilities must be precisely targeted. If your vulnerability simulation leaks into shared security infrastructure, it corrupts the experiment. The attack scripts use a pre-attack event baseline (`latest_id_before`) to avoid correlating with events from previous runs, and the BFLA experiment reinforced why that matters — the event log was already populated from prior tests.

---

## M4-B — BOPLA (API3:2023)

### What I was trying to do

Simulate Broken Object Property Level Authorization (Excessive Data Exposure). Alice requests her own item but adds `?include_internal=true` to get fields that should be admin-only: `internal_notes` and `is_confidential`.

### What went wrong — SQLite schema migration

Adding `internal_notes` and `is_confidential` to the `Item` model and running the application failed silently on existing development databases. `create_all()` did not add the columns because the `items` table already existed. The fix was to add a migration check in `backend/seed.py` using `PRAGMA table_info(items)` to detect and add missing columns with `ALTER TABLE`.

### What went wrong — verification logic

The first version of the BOPLA result used an outcome string (`"vulnerability_exploited"` vs `"attack_blocked"`) as the only way to determine whether the experiment succeeded. The problem was that an unverified detection (where the HTTP response matched expectations but the event was not found) could produce a misleading outcome string.

Adding the `verification_passed: bool` field fixed this. The dual-run orchestrator only writes the combined result file when both `verification_passed` values are `True`.

### What went wrong — event correlation

Initial event correlation only checked `owasp_category` and `rule_name`. This was not specific enough — if two tests ran close together, an event from one test could be accepted as correlation evidence for another. The final version checks seven fields: `id > baseline`, `owasp_category`, `rule_name`, `endpoint`, `user_id`, `object_id`, and `action`.

### What I learned

Backward-compatible database migrations are harder than they look. Dropping and recreating the database works fine in tests (which use in-memory SQLite), but it destroys experiment results in the development database. The `PRAGMA table_info` approach was the right non-destructive alternative.

Boolean verification flags are better than string parsing for programmatic checks. If you find yourself writing `if result["outcome"] == "vulnerability_exploited"`, a `result["verification_passed"] == True` is clearer and less error-prone.

The finally block in the dual-run orchestrator is not optional. If the first run raises an exception midway through, the defense toggle needs to be restored. If it is not, the server is left in an unexpected state that affects every subsequent test.

---

## M4-C — Broken Authentication (API2:2023)

### What I was trying to do

Simulate brute-force login: an attacker submitting many failed login attempts to find the correct password. With the defense off, the account stays accessible indefinitely. With the defense on, the account locks out after 5 failures.

### What I implemented

`backend/security/lockout.py` — `LoginAttemptTracker` maintains per-username failure timestamps in a rolling window (5 minutes). After 5 failures, the account is locked for 5 minutes. The tracker uses a threading lock for thread safety.

The login route (`backend/routes/auth.py`) checks `login_tracker.is_locked_out()` before even verifying the password if `auth_hardening` is enabled. This prevents the check being bypassed by sending multiple concurrent requests (the lock is applied at the tracker level, not at the route level).

`attacks/auth.py` sends 7 failed login attempts (more than the 5-attempt threshold) and checks whether the account locks out (defense on) or stays open (defense off).

### What I learned

Tracking failures separately from blocking them is important. The `LoginAttemptTracker` records failures regardless of whether the defense is on. This means you can detect brute-force patterns even in monitor-only mode (defense off, lab mode on). The defense toggle controls whether the lockout is enforced, not whether attempts are tracked.

The lockout window is rolling, not fixed. This means 5 failures spread over 10 minutes do not trigger a lockout if each set of failures is more than 5 minutes apart. A fixed window would reset the counter at the boundary even if the failures were clustered right at the end of the window.

---

## M5 — Rate Limiting (API4:2023)

### What I was trying to do

Simulate unrestricted resource consumption: Alice sends a burst of 25 requests in a short window. The rate limiter should allow the first 20 and reject the rest with HTTP 429 when the defense is on.

### What I implemented

`backend/security/rate_limiter.py` — `RateLimiter` with a fixed window of 20 requests per 60 seconds, keyed by `user:<user_id>`. The key design decision was to key by user ID rather than IP address, because in a local lab all requests come from the same IP (`127.0.0.1`).

`backend/security/rate_limit_dep.py` — a FastAPI dependency (`check_rate_limit`) applied to `GET /items/{item_id}`.

`attacks/rate_limit.py` — sends 25 sequential requests and records per-request latency using `time.perf_counter()`. The result file includes `latency_p50_ms` and `latency_p95_ms` for both runs.

### What I learned

Manual testing with Swagger UI is not useful for rate limiting — you would have to click 25 times very quickly. This is exactly why automated attack scripts exist. The rate limiter is also stateful in a way that matters for tests: if you do not reset the limiter between tests, one test's requests count toward the next test's window. The `autouse` fixture in `conftest.py` resets the rate limiter before each test to prevent this.

The latency result was interesting: the defended run (`latency_p50_ms = 14.53`) was noticeably slower than the vulnerable run (`latency_p50_ms = 6.25`). This overhead comes from the rate limiter's threading lock, which is expected.

---

## M6 — React Dashboard

### What I was trying to do

Build a frontend that shows the current API status, lets an admin toggle defenses, displays the security event log, and renders experiment results.

### What I implemented

A React 19 + Vite 8 single-page app with four tabs:

- **Status**: API health check and current lab mode indicator.
- **Defenses**: Live toggle state for all five main defenses (not `deprecated_route_protection`, which is not shown in the DEFENSE_LABELS map). Toggle buttons send `PATCH /admin/defenses` requests.
- **Events**: Paginated event log fetched from `GET /admin/events`.
- **Results**: Loads five JSON files from `/results/` and renders Vulnerable Run and Defended Run cards for each.

The dashboard only reads and displays data. It does not trigger attack scripts.

### What went wrong

Frontend `fetch` calls to `http://127.0.0.1:8000` from `http://localhost:5173` triggered CORS preflight requests. These were failing with `405 Method Not Allowed` before I added the `CORSMiddleware` to `backend/main.py`. The middleware only allows `http://localhost:5173` and `http://127.0.0.1:5173` as origins.

The token security model was a deliberate decision: the JWT is held only in React component state, never in `localStorage` or `sessionStorage`. This means if you close or refresh the tab, you have to log in again, but it avoids token theft via XSS in a persistent storage.

### What I learned

CORS errors in the browser console look alarming but are usually a configuration problem on the server side. The key was understanding that the browser sends an `OPTIONS` preflight before the actual request, and that preflight must return proper CORS headers with a 2xx status before the browser will proceed.

---

## M7 — Inventory Management (API9:2023)

### What I was trying to do

Simulate improper inventory management: a deprecated API route (`/api/v0/items/{id}`) that should have been removed but still works. When the `deprecated_route_protection` defense is off, the route is accessible. When it is on, it returns HTTP 403.

### What I implemented

`backend/routes/inventory.py` with two things:
1. `GET /admin/inventory` — returns a list of all routes including the deprecated one, so an admin can see what endpoints exist.
2. The deprecated route `/api/v0/items/{id}` — only accessible in lab mode. Outside lab mode it returns HTTP 404.

`detection/inventory.py` — emits events with `rule_name="deprecated_route_access"` and `owasp_category="API9:2023"`.

### What I learned

API inventory management is easy to understand conceptually (do not leave old endpoints running) but slightly tricky to simulate in a controlled way. The double gating — lab mode AND defense toggle — means the deprecated route is never accessible in a production-like (non-lab) run, which preserves the safety model.

---

## M8 — Evaluation Framework and Final Documentation

### What I was trying to do

Create an evaluation script that could run each experiment multiple times and aggregate the results, plus write final documentation.

### What I implemented

`scripts/evaluate.py` — a framework that can call each attack module's `main()` function N times and aggregate success/failure counts. The `docs/results/evaluation_summary.json` is a placeholder (all zero counts) because generating real aggregate results requires a live server session and is not part of the automated test suite.

Final documentation: `docs/ARCHITECTURE.md`, `docs/SECURITY_MODEL.md`, `docs/TESTING.md`, `docs/EXPERIMENT_METHODOLOGY.md`, `docs/FINAL_REPORT.md`, and `docs/results/README.md`.

### What I learned

Writing documentation after implementation reveals gaps. For example, the PROGRESS.md file still had encoding issues from being auto-generated during an earlier session. The LEARNING_LOG.md only covered up to M4-B. The final documentation pass was an opportunity to reconcile what was planned against what was actually built.

---

## Cross-Cutting Lessons

### Separating detection from blocking

The biggest conceptual shift during this project was understanding that "attack blocked" and "attack detected" are not the same thing. A firewall blocks without necessarily categorizing. APIShield's design runs the detection engine first, writes an event, and then decides whether to block. The event is evidence; the HTTP response code is the enforcement action.

This distinction affected how I wrote the attack scripts. The first version of `run_bola_attack()` only checked the HTTP status code. Later versions also check that a matching security event exists in the database with the correct ID, category, rule, and action. Without that check, the experiment result could be misleading — you might get the right HTTP status for the wrong reason.

### Fail-closed vs. fail-open

Every detection module is fail-closed: if `log_security_event()` raises an exception, the route handler returns HTTP 500 instead of proceeding. This is a deliberate security property. In a system that is supposed to audit every security-relevant event, allowing an un-audited event to pass through would undermine the experiment's integrity.

### In-memory state and test isolation

The `DefenseManager`, `LoginAttemptTracker`, and `RateLimiter` are process-level singletons. In tests, the `reset_defense_and_lab_state` autouse fixture resets all of them before each test. Without this, state leaks between tests would cause flaky, order-dependent failures — which happened before the fixture was added.

### The value of the pre-attack baseline

Every attack script captures the latest security event ID before making any malicious request. The post-attack verification only accepts events with `id > baseline_id`. Without this, the script might accept a stale event from a previous run as proof that the current attack was detected. This made the experiment results genuinely reliable rather than just plausible.
