# APIShield Testing Guide

This document explains how the project was tested: automated unit tests, manual API exploration, and automated attack experiments.

---

## Environment Setup

```powershell
cd C:\path\to\apishield

# Create and activate virtual environment
python -m venv .venv
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process   # if needed
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure environment (set JWT_SECRET to 32+ chars)
Copy-Item .env.example .env
```

---

## 1. Automated Unit Tests (pytest)

The test suite uses pytest with an in-memory SQLite database. No server needs to be running.

```powershell
# Run all tests
python -m pytest tests/ -v

# Quick summary only
python -m pytest -q

# Single module
python -m pytest tests/test_bola.py -v

# Short tracebacks on failure
python -m pytest --tb=short
```

**Current count:** 162 tests passing, 1 deprecation warning (harmless, from the httpx/TestClient package).

### Test Organization

| File | Tests | What it covers |
|---|---|---|
| `test_auth.py` | — | JWT generation and validation, login, expired/malformed/tampered tokens |
| `test_auth_hardening.py` | 20 | Lockout tracker, login lockout, attack counts, 429 response, detection events |
| `test_bola.py` | 17 | Ownership checks, lab-mode gating, detection, blocked events, dual-run orchestration |
| `test_bopla.py` | 34 | Property exposure, schema validation defense, detection, dual-run orchestration |
| `test_defenses.py` | — | Toggle CRUD, admin-only enforcement, validation of unknown/non-boolean values |
| `test_events.py` | — | Event persistence, pagination, action filtering, field validation |
| `test_inventory.py` | 17 | Deprecated route gating, inventory listing, detection, defended behavior |
| `test_items.py` | — | Item read authorization, 404 handling, JWT enforcement |
| `test_middleware.py` | — | X-Response-Time-Ms header present on all responses |
| `test_rate_limit.py` | 13 | Fixed-window limiter, 429 responses, detection events, isolation between tests |
| `test_rbac.py` | 15 | Admin event access, non-admin BFLA, detection, defense, attack script behavior |
| `test_seed.py` | — | Seeding idempotence, column migration, user password verification |

### Test Infrastructure

**`tests/conftest.py`** provides shared fixtures:

| Fixture | Scope | Purpose |
|---|---|---|
| `reset_defense_and_lab_state` | autouse, function | Resets `defense_manager`, `login_tracker`, `rate_limiter`, and lab mode before and after every test |
| `lab_mode_enabled` | function | Sets lab mode on for one test, then restores it |
| `db_session` | function | Isolated in-memory SQLite session |
| `client` | function | FastAPI TestClient wired to the test database |

The `reset_defense_and_lab_state` autouse fixture is important. Without it, a test that modifies `defense_manager` would leak state into the next test. This was a source of flaky tests early in development.

**Test database:** `sqlite:///:memory:` with `StaticPool`. Each test gets a clean schema via `create_all()` and `drop_all()`. The development database (`apishield.db`) is never touched.

### Safety Properties Verified by Tests

Every test run verifies:

1. Attack scripts reject non-local targets before any network call.
2. Vulnerable behaviors do not execute outside lab mode.
3. Normal users cannot access admin endpoints or modify defenses.
4. Missing, expired, malformed, and tampered JWT tokens return HTTP 401.
5. If security event persistence fails, the request is denied (HTTP 500), not allowed.
6. No passwords, tokens, or Authorization headers appear in event records or result files.
7. Attack orchestrators restore the original defense state in `finally` blocks.
8. Security events are emitted regardless of whether the defense blocks the request.

---

## 2. Manual API Testing

### Swagger UI

FastAPI generates interactive documentation automatically. While the server is running:

```
http://127.0.0.1:8000/docs
```

Useful for:
- Checking that endpoints exist and accept the expected parameters.
- Testing authentication by clicking **Authorize** and entering a Bearer token.
- Verifying that unauthorized requests return the correct error codes.
- Single request/response inspection.

**Not useful for:** Rate limiting experiments (requires 20+ rapid requests), timing measurements, or dual-run comparisons.

### PowerShell

For quick manual verification without the browser:

```powershell
# Log in and capture token
$resp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" `
    -Method Post `
    -Body '{"username":"alice","password":"AliceSyntheticPass123!"}' `
    -ContentType "application/json"
$token = $resp.access_token

# Access your own item
Invoke-RestMethod -Uri "http://127.0.0.1:8000/items/1" `
    -Headers @{Authorization="Bearer $token"}

# Attempt cross-user access (requires lab mode ON)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/items/3" `
    -Headers @{Authorization="Bearer $token"}

# Admin: view defenses
$adminResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" `
    -Method Post `
    -Body '{"username":"admin","password":"AdminSyntheticPass123!"}' `
    -ContentType "application/json"
$adminToken = $adminResp.access_token

Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/defenses" `
    -Headers @{Authorization="Bearer $adminToken"}

# Admin: toggle a defense
Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/defenses" `
    -Method Patch `
    -Body '{"bola": true}' `
    -ContentType "application/json" `
    -Headers @{Authorization="Bearer $adminToken"}

# Admin: view security events
Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/events?limit=10" `
    -Headers @{Authorization="Bearer $adminToken"}
```

---

## 3. Automated Attack Experiments

The Python attack scripts in `attacks/` are the primary tool for running experiments against a live server. Each script:

1. Validates the target URL against a hardcoded allowlist before any network call.
2. Authenticates as the synthetic attacker.
3. Captures the highest security event ID before attacking (baseline).
4. Runs two passes: defense off (vulnerable), then defense on (defended).
5. Verifies that the correct security event was created for each pass.
6. Restores the original defense state in a `finally` block.
7. Writes a combined JSON result only after both passes pass verification.

**Why automated scripts instead of manual testing?**

Manual testing through Swagger UI or PowerShell is useful for checking individual responses. But for controlled experiments you need:
- Exact repeatability (same user, same item, same parameters every time).
- Automated defense toggle management (set off, attack, set on, attack, restore).
- Event ID baseline tracking (to avoid accepting stale events as evidence).
- Result persistence in a standard format.
- Rate limiting experiments that require 25+ requests in rapid succession.

The scripts provide all of these.

### How to Run an Experiment

```powershell
# Terminal 1 — Start server in lab mode
$env:APISHIELD_LAB_MODE = "true"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2 — Seed the database (if not already seeded)
python -m backend.seed

# Terminal 2 — Run the experiment
python attacks/bola.py --target http://127.0.0.1:8000
```

After running, copy the result file to the frontend:

```powershell
Copy-Item docs\results\bola_results.json frontend\public\results\bola_results.json
```

---

## 4. Attack Scripts — Detailed Reference

### `attacks/bola.py` — BOLA (API1:2023)

| Field | Value |
|---|---|
| OWASP category | API1:2023 — Broken Object Level Authorization |
| Attack idea | A regular user reads another user's object by changing the item ID in the URL |
| Attacker | `alice` (user, owns items 1 and 2) |
| Target | `GET /items/3` (Bob's item) |
| Vulnerable run | HTTP 200, `attack_success=true`, `outcome="vulnerability_exploited"` |
| Defended run | HTTP 403, `blocked=true`, `outcome="attack_blocked"` |
| Detection verification | `rule_name="bola_cross_tenant_access"`, `owasp_category="API1:2023"`, `id > baseline` |
| Result file | `docs/results/bola_results.json` |

---

### `attacks/bopla.py` — BOPLA (API3:2023)

| Field | Value |
|---|---|
| OWASP category | API3:2023 — Broken Object Property Level Authorization |
| Attack idea | A regular user requests administrative fields on their own object using `?include_internal=true` |
| Attacker | `alice` (user, owner of item 1) |
| Target | `GET /items/1?include_internal=true` |
| Vulnerable run | HTTP 200, `internal_notes` and `is_confidential` present in response |
| Defended run | HTTP 403, fields not disclosed |
| Detection verification | `rule_name="bopla_excessive_data_exposure"`, `owasp_category="API3:2023"`, `id > baseline` |
| Result file | `docs/results/bopla_read_results.json` |

The result includes per-run `disclosed_internal_notes` and `disclosed_is_confidential` boolean fields that record whether the properties were actually present in the response — not just whether the HTTP status was 200.

---

### `attacks/auth.py` — Broken Authentication (API2:2023)

| Field | Value |
|---|---|
| OWASP category | API2:2023 — Broken Authentication |
| Attack idea | Submit 7 failed login attempts to simulate brute-force |
| Attacker | The script itself (submitting wrong passwords for `alice`) |
| Target | `POST /auth/login` |
| Vulnerable run | 7x HTTP 401, account stays accessible, `failed_429=0` |
| Defended run | 5x HTTP 401 then 2x HTTP 429, account locked, `failed_429=2` |
| Detection verification | `rule_name` matching auth brute-force rule, `id > baseline` |
| Result file | `docs/results/auth_results.json` |

The lockout triggers after 5 failures within a 5-minute window. After that, additional attempts return HTTP 429 with a `Retry-After` header.

---

### `attacks/rate_limit.py` — Rate Limiting (API4:2023)

| Field | Value |
|---|---|
| OWASP category | API4:2023 — Unrestricted Resource Consumption |
| Attack idea | Send 25 rapid requests (threshold is 20 per 60-second window) |
| Attacker | `alice` |
| Target | `GET /items/1` (25 times) |
| Vulnerable run | 25 HTTP 200, `block_rate=0.0` |
| Defended run | 25 HTTP 429 (rate limiter was already warm from run 1), `block_rate=1.0` |
| Detection verification | `rule_name` matching rate limit rule, `id > baseline` |
| Result file | `docs/results/rate_limit_results.json` |

Result also includes `latency_p50_ms` and `latency_p95_ms` per run, measured with `time.perf_counter()`.

Note: the defended run shows all 25 as 429 because the rate limiter window carries state between runs in a live server session. Each attack script run against a live server does not reset the limiter state.

---

### `attacks/rbac.py` — BFLA/RBAC (API5:2023)

| Field | Value |
|---|---|
| OWASP category | API5:2023 — Broken Function Level Authorization |
| Attack idea | A regular user accesses an admin-only endpoint |
| Attacker | `alice` (role: user) |
| Target | `GET /admin/events` |
| Vulnerable run | HTTP 200, full event list returned |
| Defended run | HTTP 403, access denied |
| Detection verification | `rule_name` matching BFLA rule, `owasp_category="API5:2023"`, `id > baseline` |
| Result file | `docs/results/rbac_results.json` |

---

### `attacks/inventory.py` — Inventory Management (API9:2023)

| Field | Value |
|---|---|
| OWASP category | API9:2023 — Improper Inventory Management |
| Attack idea | Access a deprecated API route that should have been removed |
| Attacker | `alice` |
| Target | `GET /api/v0/items/1` (deprecated route) |
| Vulnerable run | HTTP 200, item data returned |
| Defended run | HTTP 403, route blocked |
| Detection verification | `rule_name="deprecated_route_access"`, `owasp_category="API9:2023"`, `id > baseline` |
| Result file | `docs/results/inventory_results.json` (not generated by default) |

---

## 5. Adding New Tests

1. Create `tests/test_<module>.py`.
2. Use the `client`, `db_session`, `lab_mode_enabled`, and optionally `seeded_db` fixtures.
3. Never start a real server or make network requests to external hosts.
4. The `reset_defense_and_lab_state` autouse fixture runs before every test, so you generally do not need to call reset methods explicitly unless your test modifies state mid-test.
5. Never hardcode JWT secrets or real credentials. Use `create_access_token()` from `backend/auth/security.py` for token generation in tests.

---

## 6. Checking for Secret Leaks Before Committing

```powershell
# Check for whitespace errors
git diff --cached --check

# Quick check for accidentally staged secrets
git diff --cached | Select-String "password|secret|token|Authorization" | Select-Object -First 20
```

The `.env` file is in `.gitignore` and must never be committed.
