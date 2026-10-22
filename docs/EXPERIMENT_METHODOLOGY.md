# APIShield Experiment Methodology

## Design Principles

All experiments in APIShield follow a consistent methodology to ensure reproducibility and comparability across vulnerability modules.

### Controlled Variables
- Fixed synthetic user accounts (alice, bob, admin)
- Fixed target items (IDs assigned by seeding order)
- Same HTTP endpoint, method, and request body for both defense states
- Same admin account for defense toggle management and event verification

### Independent Variables
- Defense toggle state: OFF (vulnerable) vs ON (defended)

### Measured Outcomes
- HTTP response status codes
- Presence/absence of restricted properties in responses
- Security event emission and action (`detected` vs `blocked`)
- Latency (where measured)

---

## Traffic Design

### Malicious Requests (M)
Requests that an attacker would use to exploit the vulnerability. For each module:

| Module | Malicious Request Type | Count per Run |
|---|---|---|
| BOLA | Cross-user item read (alice reading bob's item) | 1 per experiment |
| Broken Auth | Failed login attempts against synthetic account | 7 (exceeds 5-attempt threshold) |
| BOPLA | `?include_internal=true` from non-admin owner | 1 per experiment |
| Rate Limit | Burst requests exceeding the per-window limit | 25 (exceeds 20-request limit) |
| BFLA/RBAC | Non-admin read of `/admin/events` | 1 per experiment |

### Legitimate Requests (L)
Requests that should always succeed, used to measure false-positive rate:

| Module | Legitimate Request Type |
|---|---|
| BOLA | Owner reading their own item |
| Broken Auth | Valid login after no prior failures |
| BOPLA | Admin reading item with `include_internal=true` |
| Rate Limit | Requests within the per-window limit |
| BFLA/RBAC | Admin reading `/admin/events` |

---

## Metric Definitions (from SPEC.md §8)

Let M = number of malicious requests, L = number of legitimate requests per run.

### Attack Success Rate
```
ASR = (malicious requests that succeeded) / M
```
A request "succeeds" from the attacker's perspective when:
- BOLA: response is HTTP 200 with item data from another user
- Broken Auth: account remains accessible after all attempts
- BOPLA: response includes `internal_notes` or `is_confidential`
- Rate Limit: requests return HTTP 200 (not 429)
- BFLA: response is HTTP 200 with event data

### Detection Rate
```
DR = (malicious requests that generated a security event) / M
```
An event is "detected" when a `SecurityEvent` with the expected `owasp_category`, `rule_name`, `endpoint`, `user_id`, and `action` is found with `id > baseline_id`.

### Block Rate
```
BR = (malicious requests that were rejected with an error response) / M
```
Blocked requests return HTTP 403, 429, or 401 (context-dependent).

### False Positive Rate
```
FPR = (legitimate requests that generated a security event or were rejected) / L
```
A false positive is a legitimate request that either:
- Returns an error HTTP status, OR
- Produces a security event with `action="detected"` or `action="blocked"`

Admin access to restricted endpoints is never a false positive (admins are authorized).

### Latency Overhead
```
Overhead = p50(defenses_ON) - p50(defenses_OFF)
         = p95(defenses_ON) - p95(defenses_OFF)
```
Measured in milliseconds. Positive overhead means defense adds latency.

---

## Dual-Run Protocol

Every experiment uses a paired dual-run design:

```
1. Capture original defense toggle value
2. Run 1 — Defense OFF:
   a. Set toggle to False via PATCH /admin/defenses
   b. Verify toggle was set (check response body)
   c. Execute malicious and legitimate requests
   d. Verify security event correlation
   e. Record outcome, status codes, event IDs, latency
3. Run 2 — Defense ON:
   a. Set toggle to True
   b. Verify toggle was set
   c. Execute same requests
   d. Verify security event correlation
   e. Record outcome
4. Restore original toggle (finally block — always executes)
5. Write combined JSON result ONLY if both runs verified AND restoration confirmed
```

### Verification Requirements

A run is "verified" when ALL of the following hold:
- HTTP status matches expected (200 for exploit, 4xx for blocked)
- Response properties match expectations (fields present/absent)
- A correlated security event exists: `id > baseline`, correct category/rule/endpoint/user/action
- Toggle state confirmed via response body of PATCH

An unverified run does NOT write a result artifact.

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

### Excluded Fields
Results never contain:
- Passwords or password hashes
- JWT access tokens
- Authorization header values
- Literal `internal_notes` text (only boolean disclosure flags)

---

## Reproducibility

### Fixed Seed and Deterministic State
- Synthetic users and items are seeded deterministically from `backend/seed.py`.
- User IDs and item IDs are assigned by seeding order (alice→1, bob→2, admin→3; items 1–4).
- Attack scripts use the same synthetic accounts and item IDs on every run.

### Event ID Baseline
Each run captures the latest event ID before starting the attack. Only events with `id > baseline_id` are accepted as evidence, preventing false correlation with events from prior runs.

### Environment Requirements for Reproduction
```powershell
# Server must be started with lab mode enabled
$env:APISHIELD_LAB_MODE = "true"
$env:JWT_SECRET = "<same value as experiment>"
.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Seed the database
.venv\Scripts\python.exe -m backend.seed

# Run experiment script (example: BOPLA)
.venv\Scripts\python.exe attacks/bopla.py --target http://127.0.0.1:8000
```

---

## Limitations

1. **Single run per result file.** The current attack scripts produce one combined dual-run result. The SPEC requires ≥10 independent runs with mean/SD; a future evaluation script should loop and aggregate.

2. **No random seed for request ordering.** Requests are sent sequentially, not randomized. For the bounded experiments in this lab, request ordering does not affect the measured outcomes.

3. **Latency measured in-process.** The rate-limit attack script measures latency using `time.perf_counter()` within the same process as the target (via TestClient in tests). Wall-clock latency in a real deployment would include network overhead.

4. **Single attacker per experiment.** Each experiment uses one synthetic attacker identity. Multi-attacker scenarios are not tested.

5. **No cross-run state isolation for the live server.** Between runs against a live server, the `login_tracker` and `rate_limiter` state persists. The attack scripts do not automatically reset this state; manual server restart or a future `/admin/reset-experiment` endpoint would be needed for true independent runs.
