# APIShield: SPEC

A controlled, reproducible platform for quantitatively evaluating detection and
mitigation of OWASP API Security Top 10 (2023) risks.

This file is the contract for the project. Every task must follow it.
If a task conflicts with this file, stop and ask before proceeding.

---

## 1. Goal

Build one local API containing intentionally vulnerable behavior, plus a
security gateway that can detect and block attacks. Defenses are toggleable at
runtime, so the SAME endpoint can be attacked with defenses OFF and then ON.
The project measures how effective and how costly each defense is.

Flow per vulnerability:

    attack -> detect -> defend -> verify (with metrics)

---

## 2. Safety rules (non-negotiable)

1. Everything binds to `127.0.0.1` or a Docker internal network. Never `0.0.0.0` on a real network.
2. Attack scripts in `attacks/` must check the target host against a hardcoded
   allowlist (`127.0.0.1`, `localhost`, and the Docker service name) and refuse
   to run otherwise.
3. Only synthetic data. No real names, emails, credentials, or personal data.
4. Secrets (JWT signing key etc.) come from environment variables or a `.env`
   file that is git-ignored. `.env.example` contains placeholders only.
5. Logs must never contain passwords, tokens, or full Authorization headers.
6. Vulnerable code is always clearly marked with a comment:
   `# VULNERABLE (OWASP APIx): <why>` and gated behind the relevant defense toggle.
7. Attack modules exist for demonstrating and testing this lab only.

---

## 3. Scope

| Tier | Modules |
|---|---|
| Core | API1 BOLA, API2 Broken Authentication, API3 BOPLA, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization |
| Stretch | API9 Improper Inventory, API8 Misconfiguration, API7 SSRF (local mock internal service only) |
| Optional | API6, API10, SQL injection (note: injection is not in the 2023 Top 10) |

Build order: finish one module completely (attack, detector, defense, tests,
metrics) before starting the next.

---

## 4. Architecture

    Attack scripts --HTTP--> Security Gateway (middleware) --> Route handlers --> SQLite
                                   |
                            Detection engine
                                   |
                              Events table --> Dashboard

- **One API, not two.** No duplicate `/vulnerable` and `/secure` route trees.
  Each defense has a toggle in a config object; the vulnerable behavior is what
  happens when the toggle is OFF.
- **Detection always runs**, even when blocking is OFF (monitor-only mode).
  This lets us measure "would have been detected" separately from "was blocked".
- **Middleware vs dependencies:** cross-cutting concerns (logging, rate limiting,
  detection hooks) live in middleware; per-route concerns (current user, role
  checks) use FastAPI dependencies.

### Defense toggles

    defenses = {
      "bola": bool,
      "auth_hardening": bool,   # lockout, short JWT expiry
      "schema_validation": bool,  # BOPLA
      "rate_limit": bool,
      "rbac": bool,
    }

Changeable at runtime through an admin-only endpoint. Default at startup: all OFF
in the lab profile.

---

## 5. Tech stack

- Backend: Python 3.11+, FastAPI, SQLAlchemy, Pydantic
- DB: SQLite (keep the DB layer swappable to PostgreSQL later)
- Auth: JWT, bcrypt password hashing
- Tests: pytest (+ httpx/TestClient)
- Load testing (M5): Locust or k6
- Frontend (M6): decided later
- Containers: Docker Compose (added once the app works locally)
- Version control: Git, one commit per milestone, tag `mN-name-complete`

---

## 6. Folder structure

    api-shield/
    |-- backend/
    |   |-- main.py            # app creation, middleware wiring
    |   |-- config.py          # settings + defense toggles
    |   |-- database.py
    |   |-- models/
    |   |-- routes/
    |   |-- auth/
    |   `-- security/          # gateway middleware and defenses
    |-- attacks/               # one script per vulnerability
    |-- detection/             # one detector per vulnerability + event logger
    |-- tests/
    |-- docs/
    |   `-- LEARNING_LOG.md
    |-- SPEC.md
    |-- README.md
    |-- .env.example
    `-- .gitignore

---

## 7. Module template

Every vulnerability is a module with exactly these five parts:

1. **Vulnerable behavior**, marked in code, active when its defense toggle is OFF
2. **Attack script** in `attacks/<name>.py`, outputting a JSON results file
3. **Detector** in `detection/<name>.py`, emitting security events
4. **Defense**, active when the toggle is ON
5. **Tests** proving: (a) exploit works with defense OFF, (b) exploit blocked with
   defense ON, (c) legitimate traffic still works with defense ON

Security event fields: timestamp, user id, endpoint, method, object id (if any),
OWASP category, severity, rule name, action (`detected` | `blocked`).

---

## 8. Metrics (definitions)

Let M = malicious requests, L = legitimate requests.

- **Attack success rate** = successful malicious requests / M
- **Detection rate** = malicious requests detected / M
- **Block rate** = malicious requests blocked / M
- **False positive rate** = legitimate requests flagged or blocked / L
- **Latency overhead** = p50 and p95 request latency with gateway defenses ON
  minus the same with defenses OFF

Every experiment: mixed traffic (M and L), fixed seed, at least 10 runs,
report mean and standard deviation. Results saved as JSON/CSV under `docs/results/`.

---

## 9. Coding conventions (for the AI coding agent)

- Prefer simple, explicit code over clever abstractions.
- Comments explain WHY, not just what.
- Small functions, type hints, no dead code.
- Never implement more than the current task asks.
- Every task ends with: write tests, run them, fix failures.
- After each task, give a short summary: files changed, and why each change was made.
- Before writing code, list planned files and their purpose, then wait for approval.

---

## 10. Milestones

| # | Deliverable |
|---|---|
| M0 | Repo skeleton, this spec, README, git init |
| M1 | FastAPI + SQLite + JWT + roles, seeded users and items, tests |
| M2 | Gateway middleware, defense toggles, event logging |
| M3 | BOLA end to end (attack, detector, defense, tests, first experiment) |
| M4 | Broken Auth, BOPLA, RBAC |
| M5 | Resource consumption + rate limiting + load tests |
| M6 | Dashboard |
| M7 | Stretch modules, ZAP/Postman baseline |
| M8 | Experiments, results, report or paper |