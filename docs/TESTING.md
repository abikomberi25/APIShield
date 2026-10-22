# APIShield Testing Guide

## Environment Setup

```powershell
# Clone the repository and enter the project directory
cd C:\path\to\apishield

# Create virtual environment (Python 3.11+)
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy .env.example and set a strong JWT_SECRET (32+ chars)
Copy-Item .env.example .env
# Edit .env: JWT_SECRET=<your-strong-secret-here>
```

## Running the Test Suite

```powershell
# All tests (recommended)
.venv\Scripts\python.exe -m pytest -v

# Quick summary only
.venv\Scripts\python.exe -m pytest -q

# Single module
.venv\Scripts\python.exe -m pytest tests/test_bopla.py -v

# With short tracebacks on failure
.venv\Scripts\python.exe -m pytest --tb=short
```

## Test Categories

| File | Coverage |
|---|---|
| `test_auth.py` | JWT validation, registration, login basics |
| `test_auth_hardening.py` | M4-C: Broken Authentication — lockout tracker, login lockout, attack script |
| `test_bola.py` | M3: BOLA — ownership checks, lab-mode gating, detection, attack script |
| `test_bopla.py` | M4-B: BOPLA — property exposure, detection, dual-run orchestration |
| `test_defenses.py` | Defense toggle CRUD, admin-only access, validation |
| `test_events.py` | Security event creation, pagination, filtering, validation |
| `test_items.py` | Item CRUD authorization, JWT enforcement |
| `test_middleware.py` | X-Response-Time-Ms header, latency measurement |
| `test_rate_limit.py` | M5: Rate limiting — RateLimiter unit tests, endpoint integration |
| `test_rbac.py` | M4-A: BFLA/RBAC — admin event access, detection, attack script |
| `test_seed.py` | Database seeding idempotence, user access control |

## Safety Properties Verified by Tests

Every test run verifies:

1. **Allowlist enforcement:** Attack scripts reject non-local targets before any network call.
2. **Safe-mode isolation:** Vulnerable behaviors do not execute outside lab mode, regardless of toggle state.
3. **Admin-only access:** Normal users cannot read events or modify defenses.
4. **JWT correctness:** Missing, expired, malformed, and tampered tokens are rejected.
5. **Fail-closed behavior:** If security event persistence fails, the request is denied (HTTP 500), not allowed.
6. **Credential hygiene:** No passwords, tokens, or Authorization headers in security events or result files.
7. **Toggle restoration:** Attack orchestrators restore the original defense state in `finally` blocks.
8. **Detection independence:** Events are emitted whether or not the request is blocked.

## Test Infrastructure

### Fixtures (`tests/conftest.py`)

| Fixture | Scope | Description |
|---|---|---|
| `reset_defense_and_lab_state` | autouse (function) | Resets `defense_manager`, `login_tracker`, `rate_limiter`, and lab mode before/after every test |
| `lab_mode_enabled` | function | Temporarily sets lab mode ON for the test |
| `db_session` | function | Isolated in-memory SQLite session (StaticPool) |
| `client` | function | FastAPI `TestClient` wired to the test DB session |

### Test Database

Tests use `sqlite:///:memory:` (StaticPool). Each test gets a fresh schema via `Base.metadata.create_all()` and `drop_all()`. The development database (`apishield.db`) is never touched by tests.

## Expected Output (clean run)

```
pytest -q
..........................................................................  [100%]
N passed, 1 warning in Xs
```

The one persistent warning is a `StarletteDeprecationWarning` from the httpx/TestClient package — it is harmless and does not affect test correctness.

## Adding New Tests

1. Put tests in `tests/test_<module>.py`.
2. Use the `client`, `db_session`, `lab_mode_enabled`, and `seeded_db` fixtures.
3. Do not start a real server or make network requests to external hosts.
4. Call `defense_manager.reset()` / `login_tracker.reset_all()` / `rate_limiter.reset_all()` explicitly if your test modifies state beyond what the `autouse` fixture covers.
5. Never hardcode JWT secrets or real credentials.

## Running Security-Specific Checks

```powershell
# Check for whitespace errors before committing
git diff --cached --check

# Verify no secrets are staged
git diff --cached | Select-String "password|secret|token" | Select-Object -First 20
```
