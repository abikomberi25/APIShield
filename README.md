# APIShield

A controlled, reproducible platform for quantitatively evaluating detection and mitigation of OWASP API Security Top 10 (2023) risks.

## Goal

Build one local API containing intentionally vulnerable behavior, plus a security gateway that can detect and block attacks. Defenses are toggleable at runtime, so the SAME endpoint can be attacked with defenses OFF and then ON. The project measures how effective and how costly each defense is.

## Flow per Vulnerability

```text
attack → detect → defend → verify
```

- **Attack:** An exploit script targets the API endpoint with defenses toggled OFF to demonstrate vulnerable behavior.
- **Detect:** The detection engine evaluates the request and emits structured security events (active in monitor and defense modes).
- **Defend:** The security gateway defense toggle is switched ON to actively block or mitigate the attack while keeping legitimate traffic functional.
- **Verify:** Automated tests and metrics measure defense efficacy (success, detection, block, and false positive rates) and latency overhead.

## Safety Rules (Non-Negotiable)

1. Everything binds to `127.0.0.1` or a Docker internal network. Never `0.0.0.0` on a real network.
2. Attack scripts in `attacks/` must check the target host against a hardcoded allowlist (`127.0.0.1`, `localhost`, and the Docker service name) and refuse to run otherwise.
3. Only synthetic data. No real names, emails, credentials, or personal data.
4. Secrets (JWT signing key etc.) come from environment variables or a `.env` file that is git-ignored. `.env.example` contains placeholders only.
5. Logs must never contain passwords, tokens, or full Authorization headers.
6. Vulnerable code is always clearly marked with a comment: `# VULNERABLE (OWASP APIx): <why>` and gated behind the relevant defense toggle.
7. Attack modules exist for demonstrating and testing this lab only.

## Scope

| Tier | Modules |
|---|---|
| **Core** | API1 BOLA, API2 Broken Authentication, API3 BOPLA, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization |
| **Stretch** | API9 Improper Inventory, API8 Misconfiguration, API7 SSRF (local mock internal service only) |
| **Optional** | API6, API10, SQL injection (note: injection is not in the 2023 Top 10) |

## Milestones

| # | Deliverable | Status |
|---|---|---|
| **M0** | Repo skeleton, this spec, README, git init | Completed |
| **M1** | FastAPI + SQLite + JWT + roles, seeded users and items, tests | Completed |
| **M2** | Gateway middleware, defense toggles, event logging | Completed |
| **M3** | BOLA end to end (attack, detector, defense, tests, first experiment) | Completed |
| **M4** | Broken Auth, BOPLA, RBAC (M4-A completed) | In Progress |
| **M5** | Resource consumption + rate limiting + load tests | Upcoming |
| **M6** | Dashboard | Upcoming |
| **M7** | Stretch modules, ZAP/Postman baseline | Upcoming |
| **M8** | Experiments, results, report or paper | Upcoming |

## How to Run

### 1. Environment Setup

Create and activate a Python virtual environment, then install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Ensure `.env` exists with your local secret (copy from `.env.example` if needed):
```powershell
Copy-Item .env.example .env
```

### 2. Database Seeding (Explicit & Idempotent)

Seed the SQLite database with deterministic synthetic test data:

```powershell
python -m backend.seed
```

> [!NOTE]
> **LOCAL / SYNTHETIC / TEST-ONLY CREDENTIALS**:
> The following credentials are intentionally fake, synthetic test fixtures for local lab evaluation only:
> - `alice` / `AliceSyntheticPass123!` (role: `user`, owns Items 1 & 2)
> - `bob` / `BobSyntheticPass123!` (role: `user`, owns Items 3 & 4)
> - `admin` / `AdminSyntheticPass123!` (role: `admin`, baseline administrative access)
> Passwords are stored exclusively as bcrypt hashes.

### 3. Running Automated Tests

Run the full automated pytest suite:

```powershell
python -m pytest tests/ -v
```

### 4. Running the Development Server

Start the local API development server binding strictly to `127.0.0.1:8000`:

```powershell
# Default Safe Mode (Lab Mode disabled; vulnerable behavior cannot execute):
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Explicit Experimental Lab Mode (required for BOLA vulnerability evaluation):
$env:APISHIELD_LAB_MODE="true"; python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

## Security Gateway & Admin Endpoints (Milestone M2)

### Security Gateway Middleware
All incoming HTTP requests pass through `SecurityGatewayMiddleware`, which calculates high-resolution request duration and appends the `X-Response-Time-Ms` response header to enable quantitative latency overhead measurements.

### Runtime Defense Toggles (Admin Only)
Defenses are managed via in-memory toggles and default to `False` (all OFF) at startup:
- `GET /admin/defenses` - Inspect current states of `bola`, `auth_hardening`, `schema_validation`, `rate_limit`, `rbac`.
- `PATCH /admin/defenses` - Update one or more defense flags. Rejects unknown fields, non-boolean values, or empty payloads with `HTTP 422`.
- `GET /admin/lab-mode` - Inspect startup lab mode status (read-only; cannot be enabled over HTTP).

### Security Event Audit Log (Admin Only)
Detected and blocked events are persisted in the SQLite `security_events` table with dual service-layer and database-level (`CheckConstraint`) validation:
- `GET /admin/events` - Query events with bounded pagination (`limit` 1–100, `offset >= 0`) and optional `action` filter (`detected` | `blocked`).

## OWASP API1:2023 BOLA Experiment (Milestone M3)

### Running the BOLA Attack Experiment
The attack script in `attacks/bola.py` executes a controlled, reproducible BOLA attack:
1. Validates the target URL pre-flight against a strict local allowlist (`http`, `127.0.0.1:8000`).
2. Authenticates synthetic user `alice`.
3. Requests Bob's private item (`/items/3`).
4. Verifies the corresponding security event via the Admin API.
5. Writes experiment results to `docs/results/bola_results.json`.

```powershell
# 1. Start server in lab mode:
$env:APISHIELD_LAB_MODE="true"; python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 2. Run attack with defense OFF (vulnerability demonstrated):
python attacks/bola.py --target http://127.0.0.1:8000
# -> HTTP 200, outcome: vulnerability_exploited, event verified (action: detected)

# 3. Enable BOLA defense toggle via admin:
$adminToken = (Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" -Method Post -Body '{"username":"admin","password":"AdminSyntheticPass123!"}' -ContentType "application/json").access_token
Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/defenses" -Method Patch -Headers @{Authorization="Bearer $adminToken"} -Body '{"bola":true}' -ContentType "application/json" | Out-Null

# 4. Run attack with defense ON (mitigation demonstrated):
python attacks/bola.py --target http://127.0.0.1:8000
# -> HTTP 403, outcome: attack_blocked, event verified (action: blocked)
```

## OWASP API5:2023 BFLA / RBAC Experiment (Milestone M4-A)

### Running the BFLA / RBAC Attack Experiment
The attack script in `attacks/rbac.py` executes a controlled, reproducible BFLA attack against the designated experiment endpoint `GET /admin/events`:
1. Validates the target URL pre-flight against a strict local allowlist (`http`, `127.0.0.1:8000`).
2. Takes an administrative event baseline snapshot (`latest_id_before`) prior to the attack to guarantee exact event correlation.
3. Authenticates synthetic user `alice` (non-admin).
4. Attempts unauthorized administrative function read (`GET /admin/events`).
5. Authenticates as `admin` to verify the exact correlated security event generated during the attack (`id > latest_id_before`, matching attacker, endpoint, rule, and action).
6. Writes experiment results to `docs/results/rbac_results.json`.

```powershell
# 1. Start server in lab mode:
$env:APISHIELD_LAB_MODE="true"; python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 2. Run the full dual-mode experiment (script manages defense toggle automatically):
python attacks/rbac.py --target http://127.0.0.1:8000
# -> [Vulnerable] HTTP 200, outcome: vulnerability_exploited, detection_verified=True
# -> [Defended]   HTTP 403, outcome: attack_blocked,           detection_verified=True
# -> Results written to docs/results/rbac_results.json

# 3. (Optional) Toggle the RBAC defense manually via the admin API:
$adminToken = (Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" -Method Post -Body '{"username":"admin","password":"AdminSyntheticPass123!"}' -ContentType "application/json").access_token
Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/defenses" -Method Patch -Headers @{Authorization="Bearer $adminToken"} -Body '{"rbac":true}' -ContentType "application/json" | Out-Null
# To disable: replace true with false in the Body above.
```
