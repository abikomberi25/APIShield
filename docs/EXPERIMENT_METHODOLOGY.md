# Experiment Methodology

This document explains how the APIShield experiments are designed, executed, and verified. The goal is to describe each step clearly enough that someone else could reproduce the same results using the same codebase and a local server.

---

## Why Dual-Run?

The core challenge with security experiments is knowing whether a defense actually works, or whether the attack just happened to fail for unrelated reasons.

The dual-run design solves this by running the **same attack twice against the same target**, with only one thing changing between runs: the defense toggle. If the attack succeeds in Run 1 and is blocked in Run 2, and both outcomes are confirmed by security event correlation, we have controlled evidence that the defense caused the difference.

A single-run experiment (just check that the defended case blocks the attack) doesn't tell you whether the vulnerability was real to begin with. A dual-run experiment confirms both the vulnerability *and* the fix.

---

## Design Principles

### Controlled Variables

Everything that could affect the result — except the defense toggle — stays the same across both runs:

- Synthetic user accounts: alice, bob, admin (created by `backend/seed.py`)
- Target objects: fixed item IDs (assigned by seeding order)
- Same HTTP endpoint, method, and request body in both runs
- Same admin account for toggle management and event verification

### Independent Variable

One thing changes between Run 1 and Run 2:

- **Defense toggle state:** `false` (vulnerable) in Run 1, `true` (defended) in Run 2

### Measured Outcomes

- HTTP response status code
- Response body content (fields present/absent)
- Security event: emitted with matching attributes?
- Latency (rate limit module only)

---

## Lab Mode Requirement

All experiments require the server to be started with lab mode enabled:

```powershell
$env:APISHIELD_LAB_MODE = "true"
$env:JWT_SECRET = "<your secret, min 32 chars>"
.venv\Scripts\python.exe -m backend.seed
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Lab mode is a startup-time environment variable. It **cannot** be changed over HTTP while the server is running. This is intentional — it means the experiments can only run in the controlled local environment, not against production.

Without lab mode, the vulnerable behavior is never activated. Defense toggles can still be changed, but malicious-looking requests will not expose data or skip authorization checks. This is the fail-closed design.

---

## Target URL Validation

Every attack script validates the target URL against an allowlist **before making any network calls**:

- Allowed scheme: `http` only
- Allowed hosts: `127.0.0.1`, `localhost`, `api`
- Allowed port: `8000`

If the target doesn't match, the script exits immediately with an error. This prevents the scripts from being redirected at non-local targets.

---

## Dual-Run Protocol

```
1. Authenticate as admin
2. Verify lab mode is ON → abort if not
3. Capture original defense toggle value
4. set restoration_succeeded = False

5. Run 1 — Defense OFF (vulnerable):
   a. PATCH /admin/defenses with toggle = false
   b. Verify returned value is false (raises RuntimeError if not)
   c. Capture event ID baseline (highest existing event ID before attack)
   d. Run the attack
   e. Check HTTP status, response body, and event correlation
   f. verification_passed = all checks passed
   g. If not verification_passed → raise RuntimeError (do not write results)

6. Run 2 — Defense ON (defended):
   a. PATCH /admin/defenses with toggle = true
   b. Verify returned value is true
   c. Capture new event ID baseline
   d. Run same attack
   e. Check HTTP status, response body, and event correlation
   f. verification_passed = all checks passed
   g. If not verification_passed → raise RuntimeError

7. Finally block (always executes):
   a. PATCH /admin/defenses to restore original toggle value
   b. If HTTP 200 and returned value matches original → restoration_succeeded = True
   c. If anything goes wrong → print WARNING to stderr

8. After finally:
   a. If restoration_succeeded is False → raise RuntimeError, do not write results
   b. Build combined JSON: { vulnerable_run: {...}, defended_run: {...} }
   c. Write combined JSON to docs/results/<module>_results.json
```

The result file is only written when **both runs passed and the defense state was restored**. Partial results are never persisted.

---

## Event ID Baseline Correlation

Each run captures the highest existing event ID before the attack starts:

```python
events = client.get("/admin/events", headers=admin_headers).json()
baseline_id = max((e["id"] for e in events), default=0)
```

After the attack, the script looks for events where `id > baseline_id` and all of these match:

- `owasp_category` matches the module (e.g. `"API1:2023"`)
- `rule_name` matches the specific rule (e.g. `"bola_cross_tenant_access"`)
- `endpoint` matches the attacked URL path
- `user_id` matches the attacker's user ID
- `action` matches the expected value (`"detected"` for vulnerable run, `"blocked"` for defended run)
- `object_id` matches the target object (where applicable)

This prevents false correlation with events from earlier runs or unrelated activity.

---

## Traffic Design

### Malicious Requests

| Module | Malicious Request | Count per Run |
|--------|-------------------|---------------|
| BOLA | Cross-user item read (alice reads bob's item, ID 3) | 1 |
| BOPLA | `GET /items/1?include_internal=true` by non-admin owner alice | 1 |
| Broken Auth | Failed login with wrong password against alice's account | 7 |
| Rate Limit | Burst of `GET /items/1` requests at full speed | 25 |
| BFLA/RBAC | `GET /admin/events` by non-admin user alice | 1 |
| Inventory | `GET /api/v0/items/{id}` on deprecated route | 1 |

### Legitimate Requests

| Module | Legitimate Request | Expected Always |
|--------|--------------------|-----------------|
| BOLA | alice reads her own item (ID 1) | HTTP 200 |
| BOPLA | admin reads item with `include_internal=true` | HTTP 200 with internal fields |
| Broken Auth | Valid login (no prior failures) | HTTP 200 with token |
| Rate Limit | Requests within the 20-request window | HTTP 200 |
| BFLA/RBAC | Admin reads `/admin/events` | HTTP 200 |
| Inventory | `GET /admin/inventory` by admin | HTTP 200 with route list |

---

## Metric Definitions

Let M = number of malicious requests, L = number of legitimate requests per run.

### Attack Success Rate (ASR)
```
ASR = (malicious requests that succeeded from attacker's perspective) / M
```
"Succeeded" means:
- BOLA: HTTP 200 with another user's item data
- BOPLA: response includes `internal_notes` or `is_confidential`
- Broken Auth: account remains accessible (no lockout) after all attempts
- Rate Limit: requests return HTTP 200 (not 429)
- BFLA: HTTP 200 with event data

### Detection Rate (DR)
```
DR = (malicious requests that generated a correlated security event) / M
```
"Detected" means a matching SecurityEvent was found with `id > baseline_id` and all required fields matching.

### Block Rate (BR)
```
BR = (malicious requests rejected with an error response) / M
```
Blocked = HTTP 403, 429, or 401 (context-dependent per module).

### False Positive Rate (FPR)
```
FPR = (legitimate requests rejected or that generated a security event) / L
```
Admin access to admin-only endpoints is never a false positive.

### Latency Overhead (rate limit module only)
```
Overhead = p50(defense ON) - p50(defense OFF)
```
Measured with `time.perf_counter()` in milliseconds, inline in the attack script.

---

## Module-Specific Experiment Descriptions

### BOLA — API1:2023 Broken Object Level Authorization

**Vulnerability:** When the `bola` defense is OFF, the items endpoint does not check whether the requesting user owns the requested item. Any authenticated user can read any item by guessing its ID.

**Attacker:** alice (user ID 1)
**Target:** item ID 3 (owned by admin, not alice)

**Vulnerable run flow:**
1. Set `bola = false`
2. Alice authenticates, captures her user ID
3. `GET /items/3` with Alice's token
4. Expected: HTTP 200, item data returned, detection event with `action="detected"`
5. Outcome: `vulnerability_exploited`

**Defended run flow:**
1. Set `bola = true`
2. Same request: `GET /items/3` with Alice's token
3. Expected: HTTP 403, no item data, detection event with `action="blocked"`
4. Outcome: `attack_blocked`

**Verification fields checked:** `owasp_category="API1:2023"`, `rule_name="bola_cross_tenant_access"`, `object_id="3"`, `user_id=alice_id`, correct `action`

**Actual result:**
```
Vulnerable: HTTP 200, matched_event_id=70, outcome=vulnerability_exploited
Defended:   HTTP 403, matched_event_id=71, outcome=attack_blocked
```

---

### BOPLA — API3:2023 Broken Object Property Level Authorization

**Vulnerability:** When the `schema_validation` defense is OFF, the `?include_internal=true` query parameter causes the items endpoint to include `internal_notes` and `is_confidential` fields in the response, even for non-admin users.

**Attacker:** alice (owns item 1, but should not see its internal fields)
**Target:** item ID 1 with `?include_internal=true`

**Vulnerable run flow:**
1. Set `schema_validation = false`
2. `GET /items/1?include_internal=true` with Alice's token
3. Expected: HTTP 200, response includes `internal_notes` and `is_confidential`
4. Detection event with `action="detected"`
5. Outcome: `vulnerability_exploited`

**Defended run flow:**
1. Set `schema_validation = true`
2. Same request
3. Expected: HTTP 403, no internal fields in response
4. Detection event with `action="blocked"`
5. Outcome: `attack_blocked`

**Actual result:**
```
Vulnerable: HTTP 200, disclosed_internal_notes=true, matched_event_id=12, outcome=vulnerability_exploited
Defended:   HTTP 403, disclosed_internal_notes=false, matched_event_id=13, outcome=attack_blocked
```

---

### Broken Authentication — API2:2023

**Vulnerability:** When `auth_hardening` is OFF, an attacker can send unlimited failed login attempts against an account. The failed attempts are tracked internally and a detection event is emitted, but the account is never locked — the attacker can keep trying passwords indefinitely.

**Attack scenario:** 7 failed login attempts against alice's account (5 is the lockout threshold).

**Vulnerable run flow:**
1. Set `auth_hardening = false`
2. Reset login tracker for alice
3. Send 7 `POST /auth/login` requests with wrong password
4. Expected: all 7 return HTTP 401, no lockout (HTTP 429 never seen)
5. Detection event emitted after threshold exceeded, `action="detected"`
6. Try a valid login after the 7 failures → still works
7. Outcome: `vulnerability_exploited` (account accessible despite repeated failures)

**Defended run flow:**
1. Set `auth_hardening = true`
2. Reset login tracker
3. Send same 7 requests
4. Expected: first 5 return HTTP 401, then HTTP 429 (locked out)
5. Detection/blocked event with `action="blocked"`
6. Outcome: `attack_blocked`

**Actual result:**
```
Vulnerable: 7x HTTP 401, account accessible, matched_event_id=78, outcome=vulnerability_exploited
Defended:   5x HTTP 401, 2x HTTP 429, first_lockout_at_attempt=6, matched_event_id=86, outcome=attack_blocked
```

---

### Rate Limiting — API4:2023 Unrestricted Resource Consumption

**Vulnerability:** When `rate_limit` is OFF, there is no limit on how many requests a user can send in a time window. The attacker can send a burst of requests and get a 100% success rate.

**Attack scenario:** 25 requests to `GET /items/1` as fast as possible (limit is 20 per 60-second window).

**Vulnerable run flow:**
1. Set `rate_limit = false`
2. Reset rate limiter state for alice
3. Send 25 requests sequentially, measure latency per request
4. Expected: all 25 return HTTP 200
5. Detection event emitted, `action="detected"`
6. Outcome: `vulnerability_exploited`

**Defended run flow:**
1. Set `rate_limit = true`
2. Reset rate limiter
3. Send same 25 requests
4. Expected: all 25 return HTTP 429 (window was reset, so first request triggers limit check)

   > Note: in test mode with an in-memory client, the rate limiter window is per-user. With a full reset, the first burst immediately hits the limit because the window starts at 0 and all 25 requests are counted before any response is returned.

5. Blocked event with `action="blocked"`
6. Outcome: `attack_blocked`

**Latency is measured in this module:**

```
Vulnerable: p50=6.25ms, p95=19.17ms
Defended:   p50=14.53ms, p95=19.27ms
```

Latency overhead p50 = 14.53 − 6.25 = **8.28ms**. This is in-process latency (TestClient), not wall-clock network latency.

**Actual result:**
```
Vulnerable: 25x HTTP 200, attack_success_rate=1.0, block_rate=0.0, matched_event_id=33
Defended:   25x HTTP 429, attack_success_rate=0.0, block_rate=1.0, matched_event_id=58
```

---

### BFLA / RBAC — API5:2023 Broken Function Level Authorization

**Vulnerability:** When `rbac` is OFF, the admin-only `/admin/events` endpoint does not check whether the requesting user has the admin role. Any authenticated user can call it.

**Attacker:** alice (regular user, role="user")
**Target:** `GET /admin/events`

**Vulnerable run flow:**
1. Set `rbac = false`
2. Alice authenticates
3. `GET /admin/events` with Alice's token
4. Expected: HTTP 200, event list returned
5. Detection event with `action="detected"`
6. Outcome: `vulnerability_exploited`

**Defended run flow:**
1. Set `rbac = true`
2. Same request
3. Expected: HTTP 403
4. Blocked event with `action="blocked"`
5. Outcome: `attack_blocked`

**Actual result:**
```
Vulnerable: HTTP 200, matched_event_id=87, outcome=vulnerability_exploited
Defended:   HTTP 403, matched_event_id=88, outcome=attack_blocked
```

---

### Inventory — API9:2023 Improper Inventory Management

**Vulnerability:** When `deprecated_route_protection` is OFF, the deprecated route `/api/v0/items/{item_id}` is accessible. This simulates a situation where an old API version is still active and not listed in public documentation — an attacker who discovers it can bypass any controls that might be enforced only on the current route.

**Attacker:** alice (authenticated)
**Target:** `GET /api/v0/items/1` (deprecated v0 endpoint)

**Vulnerable run flow:**
1. Set `deprecated_route_protection = false`
2. Alice authenticates
3. `GET /api/v0/items/1` with Alice's token
4. Expected: HTTP 200, item data returned
5. Detection event with `action="detected"`
6. Outcome: `vulnerability_exploited`

**Defended run flow:**
1. Set `deprecated_route_protection = true`
2. Same request
3. Expected: HTTP 404 or 403 (deprecated route blocked)
4. Blocked event with `action="blocked"`
5. Outcome: `attack_blocked`

> The inventory results file was not saved from a live run. The module is fully tested via `tests/test_inventory.py` but `docs/results/inventory_results.json` does not exist yet. Running `attacks/inventory.py --target http://127.0.0.1:8000` against a live server will generate it.

---

## Experiment Result Schema

All results are stored as JSON in `docs/results/`.

### Common Fields
```json
{
  "experiment": "OWASP APIx:2023 <name>",
  "timestamp": "<ISO 8601 UTC>",
  "target": "http://127.0.0.1:8000",
  "attacker": "<synthetic username>",
  "vulnerable_run": { ... },
  "defended_run": { ... }
}
```

### Per-Run Fields
```json
{
  "defense_active": false,
  "outcome": "vulnerability_exploited | attack_blocked | unverified_detection | unexpected",
  "detection_verified": true,
  "matched_event_id": 12,
  "status_code": 200
}
```

Additional per-module fields:
- BOPLA: `disclosed_internal_notes`, `disclosed_is_confidential`
- Broken Auth: `failed_401`, `failed_429`, `account_accessible_after_attempts`, `first_lockout_at_attempt`
- Rate Limit: `results_200_allowed`, `results_429_limited`, `attack_success_rate`, `block_rate`, `latency_p50_ms`, `latency_p95_ms`

### Excluded Fields

Results never contain:
- Passwords or password hashes
- JWT access tokens
- Authorization header values
- Literal `internal_notes` text (only boolean disclosure flags)

---

## Reproducibility

### Deterministic Seed

`backend/seed.py` creates the same accounts and items on every run:

| Entity | ID | Details |
|--------|----|---------|
| alice | 1 | role=user, owns items 1 and 2 |
| bob | 2 | role=user, owns item 3 |
| admin | 3 | role=admin, owns item 4 |

Attack scripts hardcode the target item IDs (e.g. BOLA targets item 3, owned by bob).

### Event ID Baseline

Each run captures the current maximum event ID before starting. Only events with `id > baseline` are accepted as evidence. This prevents false positives from leftover events in earlier runs.

### Full Reproduction Steps

```powershell
# 1. Set environment
$env:APISHIELD_LAB_MODE = "true"
$env:JWT_SECRET = "<same value as original experiment>"

# 2. Seed the database (creates alice, bob, admin, items)
.venv\Scripts\python.exe -m backend.seed

# 3. Start the server
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 4. In a separate terminal, run the attack script
.venv\Scripts\python.exe attacks\bola.py --target http://127.0.0.1:8000
.venv\Scripts\python.exe attacks\bopla.py --target http://127.0.0.1:8000
.venv\Scripts\python.exe attacks\auth.py --target http://127.0.0.1:8000
.venv\Scripts\python.exe attacks\rate_limit.py --target http://127.0.0.1:8000
.venv\Scripts\python.exe attacks\rbac.py --target http://127.0.0.1:8000
.venv\Scripts\python.exe attacks\inventory.py --target http://127.0.0.1:8000
```

Each script writes a JSON file to `docs/results/`. Copy those files to `frontend/public/results/` and restart the frontend to see the updated dashboard.

```powershell
Copy-Item docs\results\*.json frontend\public\results\
```

---

## Limitations

1. **Single run per result file.** Each attack script produces one dual-run result. The SPEC describes ≥10 independent runs with mean and standard deviation. The `scripts/evaluate.py` evaluation script provides a `--runs N` option, but results files currently hold only one experiment. Future work: aggregate across N runs.

2. **In-process latency only.** The rate limit module measures latency using `time.perf_counter()` inside the same process (or via TestClient). This does not capture real network overhead. Latency numbers from live server runs will be higher.

3. **Single attacker per experiment.** Each experiment uses one synthetic attacker. Multi-attacker or distributed scenarios are not modeled.

4. **In-memory state across live runs.** Between live server runs, `login_tracker` and `rate_limiter` carry over state. The attack scripts reset the relevant state before each run (using the admin API or tracker methods), but a full server restart gives cleaner isolation.

5. **No request randomization.** Requests are sent sequentially, not randomized. For bounded lab experiments, this doesn't affect the measured outcomes, but it means timing-dependent behaviors (like race conditions) are not tested.

6. **`evaluation_summary.json` is a placeholder.** The file at `docs/results/evaluation_summary.json` was created as a placeholder because the evaluation script requires a live server. It records `runs_per_module=0`. Run `scripts/evaluate.py` against a live server to generate real aggregate data.
