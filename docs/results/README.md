# Experiment Results

This directory contains JSON result files produced by the APIShield controlled-experiment attack scripts.
Each file captures the outcome of a dual-run experiment (vulnerable mode vs. defended mode)
for a specific OWASP API Security Top 10 category.

---

## File Index

| File | OWASP Category | Attack Module | Description |
|------|---------------|---------------|-------------|
| `bola_results.json` | API1:2023 | `attacks/bola.py` | Broken Object Level Authorization |
| `bfla_results.json` | API5:2023 | `attacks/bfla.py` | Broken Function Level Authorization |
| `bopla_read_results.json` | API3:2023 | `attacks/bopla.py` | Excessive Data Exposure (read) |
| `auth_results.json` | API2:2023 | `attacks/auth.py` | Broken Authentication (brute-force) |
| `rate_limit_results.json` | API4:2023 | `attacks/rate_limit.py` | Unrestricted Resource Consumption |
| `inventory_results.json` | API9:2023 | `attacks/inventory.py` | Improper Inventory Management |
| `evaluation_summary.json` | All | `scripts/evaluate.py` | Multi-run aggregate evaluation |
| `evaluation_summary.csv` | All | `scripts/evaluate.py` | CSV version of evaluation summary |

---

## Common Result Schema

All single-experiment result files share this top-level schema:

```jsonc
{
  "experiment": "<human-readable name>",
  "owasp_category": "<e.g. API1:2023>",
  "timestamp": "<ISO 8601 UTC timestamp>",
  "target": "http://127.0.0.1:8000",
  "runs": {
    "vulnerable": { /* see Run Object below */ },
    "defended":   { /* see Run Object below */ }
  },
  "summary": {
    "vulnerability_confirmed": true,  // vulnerable run produced expected outcome
    "defense_effective": true         // defended run produced expected outcome
  }
}
```

### Run Object

```jsonc
{
  "defense_active": false,           // whether the relevant defense was ON during this run
  "http_status": 200,                // HTTP status code from the attack request
  "attack_success": true,            // whether the attack achieved its goal
  "detection_verified": true,        // whether the expected security event was found in the DB
  "outcome": "vulnerability_exploited", // one of: vulnerability_exploited | attack_blocked | unverified_detection | unexpected
  "matched_event_id": 42             // ID of the correlated SecurityEvent (null if not verified)
}
```

### Outcome Values

| Value | Meaning |
|-------|---------|
| `vulnerability_exploited` | Vulnerable run: HTTP success + restricted data exposed + detection event verified |
| `attack_blocked` | Defended run: HTTP 403 + no data disclosed + blocked event verified |
| `unverified_detection` | Expected security event could not be found — experiment inconclusive |
| `unexpected` | Inconsistent HTTP status or response content |

---

## Evaluation Summary Schema (`evaluation_summary.json`)

```jsonc
{
  "evaluation_timestamp": "<ISO 8601 UTC>",
  "target": "http://127.0.0.1:8000",
  "total_modules": 6,
  "runs_per_module": 10,
  "overall_success_rate": 1.0,
  "modules": [
    {
      "module": "bola",
      "total_runs": 10,
      "successes": 10,
      "failures": 0,
      "success_rate": 1.0,
      "runs": [ /* array of per-run results */ ]
    }
  ],
  "note": "..."
}
```

The CSV variant (`evaluation_summary.csv`) contains one row per module with columns:
`module`, `total_runs`, `successes`, `failures`, `success_rate`.

---

## Generating Results

### Single experiment (requires live server)

```bash
# Start server with lab mode
APISHIELD_LAB_MODE=true uvicorn backend.main:app --reload

# Run a specific attack module
python attacks/bola.py
```

### Multi-run evaluation (requires live server)

```bash
# Evaluate all modules with 10 runs each
python scripts/evaluate.py --all --runs 10

# Evaluate a specific module
python scripts/evaluate.py --module bopla --runs 5
```

> **Note:** The evaluation script validates the target URL against an allowlist
> (`127.0.0.1:8000` / `localhost:8000`) before making any network calls.
> It never logs passwords, tokens, or Authorization headers.

---

## Security Properties

All result files are safe to commit:
- No credentials, passwords, or JWT tokens are stored
- No Authorization header values are logged
- Restricted property values (e.g. `internal_notes`) are not persisted in results
- Only security event IDs and outcome labels are recorded
