# APIShield Security Model

## Assets

| Asset | Description | Sensitivity |
|---|---|---|
| JWT signing secret (`JWT_SECRET`) | Signs and verifies all access tokens | Critical |
| User password hashes | bcrypt-hashed; never stored plaintext | High |
| `internal_notes`, `is_confidential` | Synthetic restricted item properties | Medium (lab data) |
| Security event log | Audit trail of detected/blocked events | High |
| Defense toggle state | Runtime configuration controlling vulnerability exposure | High |
| Lab mode flag | Startup-only; gates all intentional vulnerability exposure | Critical |

## Threat Model

### Attacker Capabilities (In-scope for this lab)
- Authenticated local API user (synthetic accounts: alice, bob).
- Can craft arbitrary API requests to the local endpoint.
- Knows the API structure (white-box lab environment).
- Can read their own JWT but cannot forge tokens without `JWT_SECRET`.

### Out-of-scope Threats
- Network-level attackers (API binds to loopback only).
- Attackers with filesystem access (not a threat in the intended lab context).
- Real credential compromise (all credentials are synthetic).
- Multi-worker race conditions (single-process deployment).
- Database-level attacks (SQLite on local filesystem, not network-exposed).

## Defenses by OWASP Category

### API1:2023 — Broken Object Level Authorization (BOLA)
- **Vulnerable behavior:** Non-owner can read another user's item when `bola` toggle is OFF and lab mode is ON.
- **Defense:** Ownership check (`item.owner_id == current_user.id`) always enforced outside lab mode. When defense ON: HTTP 403 for cross-user access in lab mode.
- **Detection:** `detect_bola()` always runs in lab mode, logging `"detected"` or `"blocked"` events.
- **Safe-mode guarantee:** Outside lab mode, cross-user access is always rejected regardless of toggle.

### API2:2023 — Broken Authentication
- **Vulnerable behavior:** Unlimited failed login attempts without lockout when `auth_hardening` is OFF.
- **Defense:** After 5 failed attempts in a 5-minute window, account is locked for 5 minutes. Returns HTTP 429 with `Retry-After` header.
- **Detection:** `detect_brute_force()` emits events for each failed attempt at/beyond threshold.
- **Safe-mode guarantee:** Failure tracking is always active (outside lab mode), but events only emitted in lab mode.

### API3:2023 — Broken Object Property Level Authorization (BOPLA)
- **Vulnerable behavior:** Non-admin can read `internal_notes` and `is_confidential` via `?include_internal=true` when `schema_validation` is OFF and lab mode is ON.
- **Defense:** HTTP 403 returned and response sanitized to `ItemResponse` (no internal fields) when defense is ON.
- **Detection:** `detect_bopla_read()` always runs in lab mode for non-admin requests with `include_internal=true`.
- **Safe-mode guarantee:** Outside lab mode, `?include_internal=true` from a non-admin always returns the sanitized `ItemResponse` — never exposes internal fields.

### API4:2023 — Unrestricted Resource Consumption
- **Vulnerable behavior:** No rate limiting when `rate_limit` is OFF; requests are served without bound.
- **Defense:** Fixed-window 20 requests/60 seconds per user. HTTP 429 with `Retry-After` header when exceeded.
- **Detection:** `detect_rate_limit_exceeded()` emits events when limit is exceeded, regardless of defense toggle.
- **Safe-mode guarantee:** Rate limit check runs in all modes; enforcement is gated by the toggle.

### API5:2023 — Broken Function Level Authorization (BFLA/RBAC)
- **Vulnerable behavior:** Non-admin user can read `/admin/events` (administrative endpoint) when `rbac` is OFF and lab mode is ON.
- **Defense:** HTTP 403 for non-admin users when defense is ON.
- **Detection:** `detect_bfla()` always runs in lab mode for non-admin access attempts.
- **Safe-mode guarantee:** Outside lab mode, non-admin access to `/admin/events` always returns HTTP 403.

## Known Limitations

1. **In-memory state is process-scoped.** Defense toggles, lockout state, and rate-limit windows are not persisted across restarts. Multi-worker deployments would have inconsistent state.

2. **Single-process rate limiting.** The `RateLimiter` is not distributed. In a real deployment with multiple workers, each worker would maintain an independent window.

3. **JWT expiry is per SPEC (30 minutes).** Short expiry is not enforced by `auth_hardening` in this implementation — the toggle focuses on brute-force protection only.

4. **No HTTPS in lab.** The server binds to `http://127.0.0.1:8000`. TLS is not required for a loopback-only lab but would be mandatory in any real deployment.

5. **Synthetic data only.** All experiments use deterministic fake accounts and items. No real personal data is involved.

6. **Lab mode is read-only over HTTP.** `APISHIELD_LAB_MODE` can only be set at process startup. It cannot be toggled via the API. This prevents adversarial re-enabling of lab mode during a production-like run.

7. **Detection accuracy.** Events are correlated by ID baseline + category + rule + endpoint + user. In high-traffic scenarios with concurrent requests, a very small window of correlation ambiguity exists. For the controlled single-attacker lab, this is negligible.

## Non-Goals

- This is NOT a production security system.
- APIShield does not claim to prevent all OWASP API risks in general deployments.
- The intentional vulnerabilities are research artifacts, not bugs.
- Coverage is limited to the five core OWASP modules implemented and tested.
