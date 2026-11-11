# APIShield

**A controlled, local platform for simulating, detecting, and defending against OWASP API Security Top 10 (2023) risks.**

APIShield is built around one central idea: the same API endpoint can behave in a vulnerable way or a defended way depending on a runtime toggle. This makes it possible to run a controlled experiment — attack the endpoint with the defense off, record what happens, switch the defense on, attack again, and compare the two outcomes.

The core workflow is:

```
Attack Simulation → API Request → Detection → Security Event → Defense Decision → Response → Verification
```

This is not a production API or a security tool for real deployments. It is a learning and research platform that runs entirely on localhost using synthetic data.

---

## Project Goals

1. Simulate selected API security vulnerabilities in a controlled, reproducible environment.
2. Detect suspicious behavior and record structured security events.
3. Enable or disable defenses at runtime without restarting the server.
4. Compare vulnerable and defended behavior using the same attack scenario.
5. Verify that detection happened — not just that a request was blocked.
6. Provide a React dashboard and JSON result files for visualization and reporting.

---

## Implemented OWASP Modules

| OWASP Category | Risk | Attack Script | Defense Toggle |
|---|---|---|---|
| API1:2023 | Broken Object Level Authorization (BOLA) | `attacks/bola.py` | `bola` |
| API2:2023 | Broken Authentication | `attacks/auth.py` | `auth_hardening` |
| API3:2023 | Broken Object Property Level Authorization (BOPLA) | `attacks/bopla.py` | `schema_validation` |
| API4:2023 | Unrestricted Resource Consumption | `attacks/rate_limit.py` | `rate_limit` |
| API5:2023 | Broken Function Level Authorization (BFLA) | `attacks/rbac.py` | `rbac` |
| API9:2023 | Improper Inventory Management | `attacks/inventory.py` | `deprecated_route_protection` |

---

## Architecture

```
Attack Scripts / Frontend / API Client
              |
              v
    SecurityGatewayMiddleware       ← measures latency, adds X-Response-Time-Ms
              |
              v
         FastAPI Routes
      /auth  /items  /admin  /api/v0
              |
     +--------+--------+
     |        |        |
     v        v        v
  Auth    Defense   Detection
  (JWT/   Manager   Engines
  bcrypt) (toggles) (bola/bopla/
                     rbac/auth/
                     rate_limit/
                     inventory)
              |
              v
         SQLite Database
         (users · items · security_events)
              |
              v
    /admin/events  →  Dashboard / Results
```

---

## Security Workflow

```
Request arrives
      |
      v
JWT Authentication
      |
      +-- Missing/invalid/expired → HTTP 401
      |
      v
Authorization check (ownership, role)
      |
      +-- Outside lab mode, cross-user/admin access → HTTP 403 (always)
      |
      v
Detection module runs (regardless of defense state)
      |
      v
Security event written to database
      |
      +-- Defense OFF → request proceeds, event action = "detected"
      |
      +-- Defense ON  → request blocked, event action = "blocked"
                              |
                              v
                         HTTP 4xx returned
```

---

## Project Milestones

| Tag | Milestone | Status |
|---|---|---|
| `m0-skeleton-complete` | M0 — Project skeleton, SPEC, git init | Complete |
| `m1-a-complete` | M1-A — FastAPI health endpoint | Complete |
| `m1-b-complete` | M1-B — SQLite + SQLAlchemy + user model | Complete |
| `m1-c-complete` | M1-C — bcrypt password hashing | Complete |
| `m1-d-complete` | M1-D — JWT authentication + protected items | Complete |
| `m2-security-gateway-complete` | M2 — Gateway middleware + defense toggles + event logging | Complete |
| `m3-bola-complete` | M3 — BOLA end-to-end (attack, detection, defense, tests) | Complete |
| `m4-a-bfla-complete` | M4-A — BFLA/RBAC experiment | Complete |
| `m4-b-bopla-complete` | M4-B — BOPLA dual-run orchestration | Complete |
| `m4-c-broken-auth-complete` | M4-C — Broken Authentication + lockout | Complete |
| `m5-resource-consumption-complete` | M5 — Rate limiting + unrestricted resource consumption | Complete |
| `m6-dashboard-complete` | M6 — React + Vite security dashboard | Complete |
| `m7-inventory-complete` | M7 — API9 Improper Inventory Management | Complete |
| `m8-evaluation-complete` | M8 — Evaluation framework + final report | Complete |

---

## Key Features

- FastAPI backend with async request handling and automatic OpenAPI docs
- JWT authentication (HS256, 30-minute expiry, role-based)
- bcrypt password hashing (12 rounds, constant-time verification)
- Object-level authorization (BOLA) with owner and admin checks
- Property-level authorization (BOPLA) with schema sanitization
- Broken authentication simulation with per-user lockout tracking
- Fixed-window rate limiting keyed by authenticated user ID
- Function-level authorization (BFLA/RBAC) on admin endpoints
- Deprecated endpoint simulation (API9/Inventory Management)
- Security event logging with OWASP category, rule name, severity, and action
- Runtime defense toggles via admin API (no server restart needed)
- Lab mode flag (`APISHIELD_LAB_MODE`) read at startup — cannot be changed over HTTP
- Six attack simulation scripts with pre-flight target validation
- Six detection modules with event ID baseline correlation
- Dual-run experiment pattern with state restoration
- 162 automated tests using in-memory SQLite
- React + Vite dashboard with four tabs: Status, Defenses, Events, Results
- Docker support with non-root user and health check

---

## Installation

### Prerequisites

- Python 3.12 or later
- Node.js 18+ and npm (for the frontend only)
- Git

### Setup

```powershell
# Clone and enter the project directory
git clone <REPOSITORY_URL>
cd apishield

# Create virtual environment
python -m venv .venv

# Activate it (if you get an execution policy error, run the line below first)
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
.\.venv\Scripts\Activate.ps1

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
Copy-Item .env.example .env
# Open .env and set JWT_SECRET to a random string of at least 32 characters

# Seed the database with synthetic users and items
python -m backend.seed
```

The seed script creates three synthetic accounts and four items:

| Username | Password | Role | Owns |
|---|---|---|---|
| `alice` | `AliceSyntheticPass123!` | user | Items 1, 2 |
| `bob` | `BobSyntheticPass123!` | user | Items 3, 4 |
| `admin` | `AdminSyntheticPass123!` | admin | — |

> These are local synthetic test credentials only. They are not real accounts.

### Run the Tests

```powershell
python -m pytest tests/ -v
```

All 162 tests use an in-memory SQLite database. No server needs to be running.

### Start the Backend

**Safe mode** (default — intentionally vulnerable behavior disabled):

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

**Lab mode** (required for attack experiments):

```powershell
$env:APISHIELD_LAB_MODE = "true"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

API documentation is available at `http://127.0.0.1:8000/docs`.

### Start the Frontend

In a separate terminal:

```powershell
cd frontend
npm install
npm run dev
```

Dashboard is available at `http://localhost:5173`. It requires the backend to be running.

---

## Running an Experiment

Each attack script runs two passes automatically: one with the defense off, one with it on.

```powershell
# Start server in lab mode (separate terminal)
$env:APISHIELD_LAB_MODE = "true"
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Run any experiment
python attacks/bola.py --target http://127.0.0.1:8000
python attacks/bopla.py --target http://127.0.0.1:8000
python attacks/auth.py --target http://127.0.0.1:8000
python attacks/rate_limit.py --target http://127.0.0.1:8000
python attacks/rbac.py --target http://127.0.0.1:8000
python attacks/inventory.py --target http://127.0.0.1:8000
```

Results are written to `docs/results/` and need to be copied to `frontend/public/results/` for the dashboard:

```powershell
Copy-Item docs\results\bola_results.json frontend\public\results\bola_results.json
```

---

## Lab Mode and Defense Toggles

**Lab mode** (`APISHIELD_LAB_MODE=true`) is a startup-time flag. It gates all intentionally vulnerable behavior. A server started without it can never expose vulnerable code paths, regardless of toggle state.

**Defense toggles** are runtime boolean flags managed via `PATCH /admin/defenses`. They start OFF in lab mode (per SPEC). The toggles are:

| Toggle | Protects Against |
|---|---|
| `bola` | Cross-user object access (BOLA) |
| `auth_hardening` | Brute-force login (5 attempts → 5-minute lockout) |
| `schema_validation` | Restricted property disclosure (BOPLA) |
| `rate_limit` | Request flooding (20 req / 60 s per user) |
| `rbac` | Non-admin access to admin-only functions (BFLA) |
| `deprecated_route_protection` | Deprecated `/api/v0/...` route access (API9) |

Vulnerable behavior requires **both** lab mode ON **and** the relevant toggle OFF.

---

## Safety Rules

1. Everything binds to `127.0.0.1` in development. Docker uses an internal network.
2. All attack scripts validate the target URL against a hardcoded allowlist before making any network request.
3. Only synthetic data — no real names, emails, or personal information.
4. Secrets come from environment variables or `.env` (git-ignored). `.env.example` has a placeholder only.
5. Security events, logs, and result files never contain passwords, JWT tokens, or Authorization header values.
6. Lab mode can only be set at process startup. It cannot be enabled via the API.

---

## Troubleshooting

**Port 8000 in use:**
```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen
Stop-Process -Id <PID> -Force
```

**`No module named 'backend'` error:**
You must run Uvicorn from the project root directory, not from inside `backend/`.

**PowerShell will not run `.ps1` scripts:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

**Dashboard does not show results:**
Copy the result file from `docs/results/` to `frontend/public/results/` and refresh.

**JWT_SECRET warning at startup:**
Set a strong secret (32+ characters) in your `.env` file.

---

## Documentation

| Document | Description |
|---|---|
| [SPEC.md](SPEC.md) | Project specification and safety rules |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component architecture and data flow |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Authentication, authorization, and event detection |
| [docs/EXPERIMENT_METHODOLOGY.md](docs/EXPERIMENT_METHODOLOGY.md) | Dual-run protocol and metric definitions |
| [docs/TESTING.md](docs/TESTING.md) | Test organization and how to run experiments |
| [docs/LEARNING_LOG.md](docs/LEARNING_LOG.md) | Development journal and lessons learned |
| [docs/PROGRESS.md](docs/PROGRESS.md) | Phase-by-phase implementation progress |
| [docs/FINAL_REPORT.md](docs/FINAL_REPORT.md) | Full academic project report |
| [docs/results/README.md](docs/results/README.md) | Result file schemas |

---

## Future Improvements

- PostgreSQL support with distributed in-memory state via Redis
- Additional OWASP categories (API6, API7 SSRF mock, API8 misconfiguration)
- Multi-run evaluation statistics (mean, standard deviation, false-positive rates)
- Real-time dashboard updates using WebSockets
- CI/CD pipeline with GitHub Actions
- Token revocation and refresh token support
- Stronger per-endpoint rate limiting and adaptive thresholds

---

> APIShield is an educational and research project. The intentional vulnerabilities exist for controlled study only. Do not use the attack scripts against any system you do not own or have explicit permission to test.
