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

| # | Deliverable |
|---|---|
| **M0** | Repo skeleton, this spec, README, git init |
| **M1** | FastAPI + SQLite + JWT + roles, seeded users and items, tests |
| **M2** | Gateway middleware, defense toggles, event logging |
| **M3** | BOLA end to end (attack, detector, defense, tests, first experiment) |
| **M4** | Broken Auth, BOPLA, RBAC |
| **M5** | Resource consumption + rate limiting + load tests |
| **M6** | Dashboard |
| **M7** | Stretch modules, ZAP/Postman baseline |
| **M8** | Experiments, results, report or paper |

## How to Run

Implementation begins in M1.
