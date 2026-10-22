# APIShield Architecture

## Overview

APIShield is a single-process, single-worker FastAPI application that intentionally implements selected OWASP API Security Top 10 (2023) vulnerabilities in a controlled lab environment. Its purpose is to provide reproducible, measurable security experiments for research and education.

```
┌─────────────────────────────────────────────────────────────┐
│                      Attack Scripts                          │
│  attacks/bola.py  attacks/bopla.py  attacks/rbac.py         │
│  attacks/auth.py  attacks/rate_limit.py                     │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP (local only, validated allowlist)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Security Gateway (Middleware)                   │
│         backend/security/middleware.py                       │
│  • Measures end-to-end request latency                       │
│  • Appends X-Response-Time-Ms header                         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               FastAPI Route Handlers                         │
│  /auth/*   /items/*   /admin/*                               │
│                                                             │
│  Auth dependencies:                                          │
│    get_current_user() — JWT verification                     │
│    require_admin()    — role check                           │
│    check_rate_limit() — per-user rate limiting               │
└──────┬───────────────────────────────────────────────────────┘
       │
       ├─── Defense Manager (in-memory)
       │    backend/security/defenses.py::DefenseManager
       │    Toggles: bola, auth_hardening, schema_validation,
       │             rate_limit, rbac
       │
       ├─── Login Attempt Tracker (in-memory)
       │    backend/security/lockout.py::LoginAttemptTracker
       │    Per-username rolling window; lockout after threshold
       │
       ├─── Rate Limiter (in-memory)
       │    backend/security/rate_limiter.py::RateLimiter
       │    Fixed-window per user ID
       │
       ├─── Detection Engines (one per vulnerability)
       │    detection/bola.py    → API1:2023
       │    detection/auth.py    → API2:2023
       │    detection/bopla.py   → API3:2023
       │    detection/rate_limit.py → API4:2023
       │    detection/rbac.py    → API5:2023
       │    Each emits SecurityEvent via events.py
       │
       └─── SQLite Database
            backend/database.py (SQLAlchemy)
            Tables: users, items, security_events
```

## Component Descriptions

### Backend Application (`backend/`)

| Module | Purpose |
|---|---|
| `main.py` | FastAPI app factory, middleware wiring, router mounting |
| `config.py` | JWT secret loading, lab-mode flag, host/port config |
| `database.py` | SQLAlchemy engine, session factory, Base declaration |
| `auth/security.py` | bcrypt hashing, JWT creation/verification |
| `auth/deps.py` | `get_current_user()`, `require_admin()` FastAPI dependencies |
| `routes/auth.py` | `/auth/register`, `/auth/login` (with lockout integration) |
| `routes/items.py` | `/items/{item_id}` — BOLA + BOPLA experiment endpoint |
| `routes/admin.py` | `/admin/defenses`, `/admin/events`, `/admin/lab-mode` |
| `security/defenses.py` | `DefenseManager` — runtime boolean toggles |
| `security/lockout.py` | `LoginAttemptTracker` — brute-force tracking |
| `security/rate_limiter.py` | `RateLimiter` — fixed-window per-key limiter |
| `security/rate_limit_dep.py` | FastAPI dependency for rate-limit enforcement |
| `security/events.py` | `log_security_event()` — validated event persistence |
| `security/middleware.py` | `SecurityGatewayMiddleware` — latency measurement |
| `models/user.py` | `User` ORM model |
| `models/item.py` | `Item` ORM model (with BOPLA fields) |
| `models/event.py` | `SecurityEvent` ORM model |
| `seed.py` | Idempotent synthetic data seeder |

### Detection Layer (`detection/`)

Each detector:
1. Receives the request context (user, item, endpoint, defense state).
2. Determines `action`: `"detected"` (defense OFF) or `"blocked"` (defense ON).
3. Calls `log_security_event()` which persists to SQLite.
4. **Fails closed** — if event persistence fails, raises HTTP 500 to deny access rather than allow an unaudited operation.

### Attack Scripts (`attacks/`)

Each script:
1. Validates the target URL against `ALLOWED_HOSTS` / `ALLOWED_PORTS` **before any network call**.
2. Authenticates using synthetic test credentials (never logged).
3. Establishes an event-ID baseline before the attack.
4. Executes the controlled attack.
5. Verifies the correlated security event by ID, category, rule, endpoint, and user.
6. Reports `outcome` as one of: `vulnerability_exploited`, `attack_blocked`, `unverified_detection`, `unexpected`.
7. Writes a combined dual-run JSON result only after both runs are fully verified.

## Data Flow: Security Event Lifecycle

```
Route handler receives request
    → Defense toggle read from DefenseManager
    → Detection function called (always, regardless of defense state)
        → log_security_event() validates fields
        → SecurityEvent written to SQLite
        → Event returned with auto-assigned ID
    → If defense ON and attack detected: HTTP 4xx returned
    → If defense OFF and attack detected: request proceeds (monitor-only)
    → Admin reads /admin/events to retrieve and correlate events
```

## Trust Boundaries

| Boundary | Description |
|---|---|
| Network | API binds to `127.0.0.1:8000`. Docker uses internal network only. |
| Authentication | JWT Bearer tokens; `get_current_user()` verifies signature + expiry on every protected route. |
| Authorization | `require_admin()` enforces role=admin for defense/event management. |
| Lab mode | Vulnerable behavior is doubly gated: lab mode (startup env var) AND defense toggle (runtime). |
| Attack scripts | Target allowlist enforced before any network request; embedded credentials prohibited. |

## Defense Toggles

All defenses start **OFF** in lab mode (per SPEC.md §4).

| Toggle | Protects | Location |
|---|---|---|
| `bola` | BOLA ownership enforcement on `/items/{id}` | `routes/items.py` |
| `auth_hardening` | Login lockout after 5 failures in 5-minute window | `routes/auth.py` |
| `schema_validation` | BOPLA: restricts `internal_notes` / `is_confidential` to admins | `routes/items.py` |
| `rate_limit` | Per-user fixed-window rate limiting on `/items/{id}` | `security/rate_limit_dep.py` |
| `rbac` | BFLA: restricts `/admin/events` to admin role | `routes/admin.py` |

## Deployment Assumptions

- **Single process, single worker.** All in-memory state (DefenseManager, LoginAttemptTracker, RateLimiter) is consistent within one process. Multi-worker deployments would require shared state (Redis etc.) — not supported in this lab configuration.
- **SQLite with foreign key enforcement.** Foreign keys enabled via `PRAGMA foreign_keys=ON` on connection.
- **Secrets from environment.** `JWT_SECRET` from `.env` (git-ignored). Ephemeral random key generated if absent — triggers a startup WARNING.
- **Synthetic data only.** All users and items are seeded deterministically from `backend/seed.py`.
