# APIShield Security Model

This document explains how APIShield decides whether a request is normal, suspicious, detected, or blocked. It is meant to be readable without prior security background.

---

## 1. Authentication — Who Are You?

Authentication is the process of verifying that a user is who they claim to be. APIShield uses two components: bcrypt for password verification and JWT for session management.

### Password Hashing with bcrypt

Passwords are never stored as plain text. When a user is created (via `backend/seed.py`), their password is processed by `hash_password()` in `backend/auth/security.py`:

```python
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
```

What this produces is a string like `$2b$12$...` that encodes the algorithm version, the cost factor (12), the salt, and the resulting hash. The original password is not recoverable from this string.

When a user logs in, the submitted password is verified with `verify_password()`:

```python
bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
```

`checkpw` extracts the salt from the stored hash and applies the same process to the submitted password. If the outputs match, the password is correct. This uses constant-time comparison internally, which prevents timing attacks — an attacker cannot determine how many characters of a guess are correct by measuring how long the check takes.

The `rounds=12` parameter makes bcrypt intentionally slow. Each additional round doubles the computation time. At 12 rounds, a single verification takes roughly 300–500 ms on modern hardware. This is acceptable for a login operation but makes large-scale offline brute-force attacks significantly more expensive.

### JWT (JSON Web Token)

After password verification succeeds, the server issues a JWT:

```
POST /auth/login  →  {"access_token": "eyJ...", "user": {"id": 1, "role": "user"}}
```

The token payload (from `create_access_token()` in `backend/auth/security.py`) contains:

| Claim | Example | Meaning |
|---|---|---|
| `sub` | `"1"` | User ID as a string (stable identity) |
| `iat` | `1729651200` | Issued-at timestamp (Unix) |
| `exp` | `1729652900` | Expiry timestamp (Unix, 30 minutes after `iat`) |
| `username` | `"alice"` | Username for display |
| `role` | `"user"` | Authorization role |

The token is signed using HS256 (HMAC-SHA256) with the `JWT_SECRET` from the environment. Anyone can decode the payload (it is Base64, not encrypted), but they cannot change it without the signature becoming invalid.

The client includes the token on subsequent requests:

```
Authorization: Bearer eyJ...
```

The `get_current_user()` dependency in `backend/auth/deps.py` validates the token on every protected request. If it is expired, malformed, or has an invalid signature, the request gets HTTP 401.

**Token expiry:** 30 minutes (`ACCESS_TOKEN_EXPIRE_MINUTES = 30` in `backend/config.py`). After expiry, the client must log in again.

**What is not in the token:** Passwords, hashes, secrets, or any sensitive data. The `role` claim is a convenience; authorization still queries the database for the actual user record on critical operations.

---

## 2. Authorization — What Are You Allowed to Do?

Authorization happens after authentication. It answers the question: given that I know who you are, is this action permitted for you?

APIShield implements two levels of authorization:

### Object-Level Authorization (BOLA, API1)

Applies to `GET /items/{item_id}`.

The rule is simple: you can read an item if you own it (`item.owner_id == current_user.id`) or if you are an admin. Any other combination is unauthorized.

```python
is_owner = item.owner_id == current_user.id
is_admin = current_user.role == "admin"

if not is_owner and not is_admin:
    # Cross-user access — evaluate based on lab mode and bola toggle
```

Outside lab mode, cross-user access always returns HTTP 403, regardless of the `bola` defense toggle. This is the safe default: the toggle only has effect when you have explicitly started the server in lab mode.

### Property-Level Authorization (BOPLA, API3)

Also applies to `GET /items/{item_id}`, but at a different level.

Even if you are allowed to read an item (you own it), you are not allowed to request the internal administrative fields (`internal_notes`, `is_confidential`). Those fields are admin-only.

The check gate is `?include_internal=true` in the request. If a non-admin sends that parameter:
- Outside lab mode: the parameter is silently ignored; the sanitized `ItemResponse` is returned.
- Inside lab mode with `schema_validation` off: the `ItemInternalResponse` is returned (vulnerable behavior).
- Inside lab mode with `schema_validation` on: HTTP 403.

### Function-Level Authorization (BFLA, API5)

Applies to admin-only endpoints like `GET /admin/events`, `GET /admin/defenses`, etc.

The `require_admin()` dependency in `backend/auth/deps.py` checks `current_user.role == "admin"`. It is applied as a FastAPI dependency to all admin routes.

The BFLA experiment makes an exception specifically for `GET /admin/events`: when the `rbac` toggle is off and lab mode is on, non-admin users can reach the event list. This is controlled locally in the route handler, not by modifying `require_admin()` itself, so all other admin routes remain protected.

---

## 3. Lab Mode

Lab mode (`APISHIELD_LAB_MODE=true`) is a startup-time environment variable read in `backend/config.py`. It cannot be changed over HTTP.

```python
STARTUP_LAB_MODE: bool = os.getenv("APISHIELD_LAB_MODE", "false").lower() in ("true", "1", "yes")
```

Its purpose is to gate all intentionally vulnerable behavior. Without lab mode, the vulnerable code paths in the route handlers are never reached, regardless of what the defense toggles are set to. This prevents a production server accidentally running vulnerable code.

**Lab mode OFF (default):** Cross-user item access always returns HTTP 403. `?include_internal=true` from non-admins is silently ignored. Non-admin access to `GET /admin/events` returns HTTP 403. The deprecated `/api/v0/...` routes return HTTP 404.

**Lab mode ON:** Vulnerable behavior becomes possible if the corresponding defense toggle is also off. This is the state required for running attack experiments.

**Lab mode and the defense toggles are independent.** You can be in lab mode with all defenses on (which looks the same as safe mode from an external perspective) or have a defense toggled off outside lab mode (the vulnerable code path is still unreachable).

---

## 4. Defense Toggles

The six runtime toggles are stored in `DefenseManager` in `backend/security/defenses.py`. All default to `False` at startup.

| Toggle | OWASP | Protects | Location |
|---|---|---|---|
| `bola` | API1 | Object ownership on `/items/{id}` | `routes/items.py` |
| `auth_hardening` | API2 | Login lockout after 5 failures | `routes/auth.py` |
| `schema_validation` | API3 | Restricted properties on `/items/{id}` | `routes/items.py` |
| `rate_limit` | API4 | Per-user request rate on `/items/{id}` | `security/rate_limit_dep.py` |
| `rbac` | API5 | Non-admin access to `/admin/events` | `routes/admin.py` |
| `deprecated_route_protection` | API9 | Access to `/api/v0/...` routes | `routes/inventory.py` |

Toggling via the admin API:

```
PATCH /admin/defenses
{"bola": true}
```

The `DefenseManager.update_defenses()` method rejects unknown toggle names and non-boolean values with a `ValueError`, which FastAPI converts to HTTP 422.

---

## 5. Security Event Detection

A security event is a structured database record that describes a suspicious or blocked action. It is created by the detection modules (`detection/bola.py`, `detection/bopla.py`, etc.) by calling `log_security_event()` in `backend/security/events.py`.

### Event Fields

| Field | Example | Description |
|---|---|---|
| `id` | `71` | Auto-increment primary key; used for correlation |
| `timestamp` | `2026-10-23T04:37:30Z` | UTC time of detection |
| `user_id` | `1` | Foreign key to the authenticated user |
| `endpoint` | `/items/3` | API path that triggered detection |
| `method` | `GET` | HTTP method |
| `object_id` | `"3"` | Target object ID as string |
| `owasp_category` | `API1:2023` | OWASP classification |
| `severity` | `HIGH` | LOW, MEDIUM, HIGH, or CRITICAL |
| `rule_name` | `bola_cross_tenant_access` | Machine-readable rule identifier |
| `action` | `detected` | Whether the defense intervened: `detected` or `blocked` |

The `CheckConstraint` on the model enforces that `action` can only be `"detected"` or `"blocked"` and `severity` can only be one of the four allowed values, at the database level.

### `detected` vs `blocked`

This distinction is important:

- **`detected`**: The detection engine ran and identified the suspicious action. The defense toggle was off, so the request proceeded (monitor-only mode). The event records what happened; it does not prevent it.
- **`blocked`**: The detection engine ran, identified the action, and the defense toggle was on. The request was rejected with an error response. The event records both the detection and the enforcement.

A request receiving HTTP 403 is not automatically evidence of detection. The route might have returned 403 for a different reason (wrong user, nonexistent item, lab mode off). Detection is only confirmed by finding the matching security event.

### Fail-Closed Behavior

If `log_security_event()` raises a `SecurityEventPersistenceError` (simulated in tests by patching the function to throw), the route handler returns HTTP 500 instead of proceeding. This is a deliberate design decision: the system refuses to allow an un-audited security-relevant action. An attack that coincides with a database failure does not get through un-noticed.

### How Attack Scripts Verify Events

Each attack script captures the highest event ID before making any malicious request:

```python
events_baseline = client.get("/admin/events?limit=1", headers=admin_headers)
latest_id_before = events_baseline.json()["events"][0].get("id", 0)
```

After the attack, it queries for events and accepts only those where:
- `id > latest_id_before` (created after the attack started)
- `owasp_category` matches the expected category
- `rule_name` matches the specific rule
- `endpoint` matches the attacked path
- `user_id` matches the attacker's ID
- `object_id` matches the target object
- `action` matches the expected action (`detected` or `blocked`)

All seven conditions must be met. This prevents accepting a stale event from a prior run as false evidence.

---

## 6. Known Limitations

**In-memory state.** `DefenseManager`, `LoginAttemptTracker`, and `RateLimiter` are process-level singletons. They reset on server restart. Multi-worker deployments would have inconsistent state across workers.

**Single-process rate limiting.** The `RateLimiter` does not share state across processes. In a multi-worker deployment, each worker would maintain an independent window, effectively multiplying the rate limit by the number of workers.

**No HTTPS in the lab.** The server uses `http://127.0.0.1:8000`. TLS is not needed for loopback-only development but would be mandatory in any real deployment.

**Synthetic data only.** All experiments use deterministic fake accounts and items. The security properties demonstrated here do not automatically apply to arbitrary APIs.

**Lab mode is read-only over HTTP.** You cannot enable lab mode via the API. This is intentional — it means a production server started without the environment variable can never be switched into vulnerable mode by an attacker hitting the API.

**Single attacker per experiment.** The attack scripts each use one synthetic user. Multi-attacker scenarios, concurrent attacks, and distributed request patterns are not tested.

**Non-goals.** This is not a production security system. APIShield does not claim to prevent OWASP API risks in general deployments. The vulnerabilities are research artifacts, not bugs.
