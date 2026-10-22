# APIShield — Final Project Report

> **OWASP API Security Top 10 (2023) Controlled Experimentation Platform**

---

## 1. Project Overview

**APIShield** is a self-contained cybersecurity research platform built to demonstrate, detect, and defend against the OWASP API Security Top 10 (2023) vulnerabilities in a controlled, reproducible, and well-documented environment.

The project implements a dual-mode FastAPI backend:
- **Safe mode** (default): all defenses are active and vulnerable behaviors are suppressed
- **Lab mode** (`APISHIELD_LAB_MODE=true`): controlled experiments can be enabled via admin toggles

Each vulnerability module includes:
1. A backend route or middleware that exhibits the vulnerability when the relevant defense toggle is OFF
2. A detection engine that emits auditable `SecurityEvent` records
3. A controlled attack script with dual-run orchestration (vulnerable run → defended run)
4. A comprehensive test suite using in-memory SQLite for complete isolation

---

## 2. Implemented OWASP Categories

| # | Category | OWASP ID | Status | Defense Toggle | Test Count |
|---|----------|----------|--------|----------------|------------|
| M1 | Skeleton & JWT auth | — | ✅ Complete | — | 42 |
| M2 | Security Gateway | — | ✅ Complete | — | 8 |
| M3 | Broken Object Level Authorization | API1:2023 | ✅ Complete | `bola` | 18 |
| M4-A | Broken Function Level Authorization | API5:2023 | ✅ Complete | `rbac` | 15 |
| M4-B | Excessive Data Exposure | API3:2023 | ✅ Complete | `schema_validation` | 34 |
| M4-C | Broken Authentication | API2:2023 | ✅ Complete | `auth_hardening` | 20 |
| M5 | Unrestricted Resource Consumption | API4:2023 | ✅ Complete | `rate_limit` | 13 |
| M6 | React Security Dashboard | — | ✅ Complete | — | — |
| M7 | Improper Inventory Management | API9:2023 | ✅ Complete | `deprecated_route_protection` | 17 |
| M8 | Evaluation Framework | — | ✅ Complete | — | — |

**Total test count: 156 passing** (139 baseline + 17 M7 tests)

---

## 3. Architecture Summary

```
APIShield
├── backend/              FastAPI application
│   ├── routes/           HTTP route handlers (auth, items, admin, inventory)
│   ├── models/           SQLAlchemy ORM models (User, Item, SecurityEvent)
│   ├── security/         Defense managers (defenses, lockout, rate_limiter, middleware)
│   └── auth/             JWT authentication (security, deps)
├── detection/            OWASP detection engines (bola, bfla, bopla, auth, rate_limit, inventory)
├── attacks/              Controlled attack scripts (one per module)
├── tests/                Pytest test suite (in-memory SQLite)
├── scripts/              Utility scripts (evaluate.py for M8)
├── docs/                 Documentation and experiment results
└── frontend/             React dashboard (Vite)
```

**Key design decisions:**
- **In-memory defense state**: `DefenseManager`, `LoginAttemptTracker`, and `RateLimiter` are in-process singletons — fast, no persistence overhead, clean test isolation
- **Fail-closed event logging**: if a security event cannot be persisted to the DB, the request is rejected (HTTP 500) rather than allowed through un-audited
- **Dual-mode safety**: vulnerable behaviors require **both** lab mode ON **and** the relevant defense toggle OFF — accidental exposure in production is impossible
- **JWT secret hardening**: if `JWT_SECRET` is missing, "change-me", or < 32 chars, an ephemeral random key is generated and a WARNING is printed to stderr

---

## 4. Experiment Results (from docs/results/)

### API1:2023 — BOLA (bola_results.json)
- **Timestamp:** 2026-10-11T01:21:30 UTC
- **Attacker:** alice (regular user accessing bob's item)
- **Vulnerable run:** HTTP 200, cross-tenant item data returned _(from prior session)_
- **Defended run:** HTTP 403, attack blocked, `blocked` event verified
- **Outcome:** ✅ Vulnerability confirmed, defense effective

### API5:2023 — BFLA/RBAC (rbac_results.json)
- **Timestamp:** 2026-10-12T16:12:52 UTC
- **Attacker:** alice accessing `GET /admin/events`
- **Vulnerable run:** HTTP 200, event list returned, `detected` event (ID 10) verified
- **Defended run:** HTTP 403, `blocked` event (ID 11) verified
- **Outcome:** ✅ Vulnerability confirmed, defense effective

### API3:2023 — BOPLA Excessive Data Exposure (bopla_read_results.json)
- **Timestamp:** 2026-10-15T11:15:55 UTC
- **Attacker:** alice requesting `?include_internal=true`
- **Vulnerable run:** HTTP 200, `internal_notes` + `is_confidential` disclosed, `detected` event (ID 12) verified
- **Defended run:** HTTP 403, no restricted properties disclosed, `blocked` event (ID 13) verified
- **Outcome:** ✅ Vulnerability confirmed, defense effective

### API2:2023 — Broken Authentication
- Results require live server with `APISHIELD_LAB_MODE=true`
- Run: `python attacks/auth.py`
- Expected: account lockout after 5 failed attempts with `auth_hardening=ON`

### API4:2023 — Rate Limiting
- Results require live server with `APISHIELD_LAB_MODE=true`
- Run: `python attacks/rate_limit.py`
- Expected: HTTP 429 after 20 requests/60s window with `rate_limit=ON`

### API9:2023 — Improper Inventory Management
- Results require live server with `APISHIELD_LAB_MODE=true`
- Run: `python attacks/inventory.py`
- Expected: deprecated `/api/v0/items/{id}` accessible with defense OFF, blocked (403) with defense ON

---

## 5. Security Model

### Defense Toggles

| Toggle | Protects Against | Default | Enforced By |
|--------|-----------------|---------|-------------|
| `bola` | Cross-user object access | OFF | `detect_bola()` in items route |
| `rbac` | Unauthorized function access | OFF | `detect_bfla()` in admin events route |
| `schema_validation` | Excessive data exposure | OFF | `detect_bopla()` in items route |
| `auth_hardening` | Brute-force login | OFF | `LoginAttemptTracker` in auth route |
| `rate_limit` | Resource exhaustion | OFF | `RateLimiter` FastAPI dependency |
| `deprecated_route_protection` | Deprecated route access | OFF | `detect_deprecated_route_access()` in inventory route |

### SecurityEvent Schema

All security detections emit a `SecurityEvent` with:
- `owasp_category` (e.g., `API1:2023`)
- `rule_name` (e.g., `bola_cross_tenant_access`)
- `action` (`detected` or `blocked`)
- `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `user_id` (never username or password)
- `endpoint` and `method`

**What is never logged:** passwords, tokens, Authorization header values, or restricted property values.

---

## 6. Running the Project

### Prerequisites
```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt
```

### Run all tests
```bash
.venv/Scripts/python -m pytest -v
```

### Start the server (safe mode)
```bash
.venv/Scripts/uvicorn backend.main:app --reload
```

### Start the server (lab mode — enables controlled experiments)
```bash
APISHIELD_LAB_MODE=true .venv/Scripts/uvicorn backend.main:app --reload
```

### Run a controlled attack experiment (requires lab-mode server)
```bash
python attacks/bola.py          # API1:2023
python attacks/bfla.py          # API5:2023
python attacks/bopla.py         # API3:2023
python attacks/auth.py          # API2:2023
python attacks/rate_limit.py    # API4:2023
python attacks/inventory.py     # API9:2023
```

### Multi-run evaluation (requires lab-mode server)
```bash
python scripts/evaluate.py --all --runs 10
```

### Docker
```bash
docker-compose up --build
```

---

## 7. Limitations

1. **Single-process in-memory state**: Defense toggles, lockout state, and rate limiter are stored in process memory. Multi-worker or multi-process deployments would require a shared backing store (Redis, database).

2. **SQLite persistence**: The security event log uses SQLite. For production-scale event volumes, a proper RDBMS (PostgreSQL) would be needed.

3. **Single-run experiment results**: The existing `docs/results/*.json` files represent single dual-run experiments. The M8 evaluation framework (`scripts/evaluate.py`) is provided to run multi-run experiments (up to 10 runs) but requires a live server.

4. **Windows-only tested**: Development and testing was performed on Windows with PowerShell. The project should work on Linux/macOS but has not been tested there.

5. **Lab mode at startup only**: `APISHIELD_LAB_MODE` is read at startup; it cannot be changed via HTTP. This is intentional — it prevents runtime escalation.

6. **M7 stretch only (API9)**: Of the three planned stretch modules (API7 SSRF, API8 Misconfiguration, API9 Inventory), only API9 was implemented due to complexity and time constraints.

7. **No distributed rate limiting**: The rate limiter is per-process with a fixed window. True production rate limiting would use a distributed counter (Redis INCR with TTL).

---

## 8. References

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy ORM](https://docs.sqlalchemy.org/en/20/)
- [PyJWT](https://pyjwt.readthedocs.io/)
- [bcrypt](https://pypi.org/project/bcrypt/)

---

*Generated: October 2026 | APIShield v0.1.0*
