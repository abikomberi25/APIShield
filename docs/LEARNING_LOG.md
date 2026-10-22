# Learning Log

## M0 — Project Skeleton

### Prompt:
### What I predicted:
### What actually happened:
### What I learned:

## M1 — Core Foundation

### Prompt:
### What I predicted:
### What actually happened:
### What I learned:

## M2 — Gateway Middleware & Runtime Defenses

### Prompt:
### What I predicted:
### What actually happened:
### What I learned:

## M3 — OWASP API1:2023 BOLA Experiment

### Prompt:
Implement controlled BOLA attack, detection, and defense on GET /items/{item_id} with lab-mode containment.

### What I predicted:
Allowing cross-tenant access when a toggle is OFF might risk accidental exposure in production.

### What actually happened:
Enforcing dual containment via APISHIELD_LAB_MODE startup environment variable and in-memory defense toggles ensured default-safe behavior. The attack script strictly validated target URLs pre-flight.

### What I learned:
Vulnerable simulation must require explicit startup-level opt-in so servers started normally can never exhibit insecure behavior.

## M4-A — OWASP API5:2023 BFLA / RBAC Experiment

### Prompt:
Implement controlled Broken Function Level Authorization (BFLA / RBAC) attack, detection, and defense on GET /admin/events.

### What I predicted:
Modifying `require_admin` would be convenient for testing BFLA across admin endpoints.

### What actually happened:
Modifying `require_admin` would have broken cross-endpoint isolation by unintentionally weakening endpoints like /admin/defenses and /admin/lab-mode. Instead, the simulated vulnerability was strictly contained to GET /admin/events, preserving `require_admin` across all other administrative routes.

### What I learned:
Simulated vulnerabilities must be localized to specific target endpoints. Shared security dependencies should remain strict and globally invariant. Furthermore, attack scripts must use correlation baselines (e.g., pre-attack event ID snapshots) to reliably verify their own triggered events without accepting historical logs.

## M4-B — OWASP API3:2023 BOPLA Excessive Data Exposure

### Prompt:
Add synthetic internal properties (internal_notes, is_confidential) with safe SQLite schema migration, implement BOPLA read experiment on GET /items/{item_id}?include_internal=true, fix outcome reporting defects, verify event correlation, implement dual-run orchestration with state restoration, and add comprehensive failure-path tests.

### What I predicted:
Adding columns to the SQLAlchemy model would automatically migrate SQLite databases with create_all(). A simple outcome string would be sufficient for verification. Event correlation could rely on basic category matching.

### What actually happened:
SQLite's create_all() is a no-op if the table already exists. To prevent crashing existing development databases without introducing destructive commands, we implemented a non-destructive column inspection check (PRAGMA table_info(items)) that runs ALTER TABLE items ADD COLUMN ... only when missing. The initial BOPLA runner could report success even when detection verification failed because outcome strings were ambiguous. We added a `verification_passed` boolean field for programmatic consumption without string parsing. Event correlation was strengthened to use 7 criteria (ID > baseline, owasp_category, rule_name, endpoint, user_id, object_id, action) to reject unrelated events. The dual-run orchestration captures the original defense state and restores it on every exit path via a finally block. Failure-path tests now cover defense bypass scenarios where the toggle is ON but properties are still disclosed.

### What I learned:
Database schema additions must be backward-compatible with pre-existing local databases without destructive resets. In property-level authorization, distinguishing between legitimate public reads and unauthorized administrative property probes prevents false positive alerts while reliably measuring excessive data exposure. Verification outcomes must be explicit and programmatic (boolean flags) rather than string-based to prevent false success reporting. Event correlation requires multiple field matching to avoid accepting unrelated events. Defense state manipulation in experiments must always include robust restoration in finally blocks to prevent leaving the system in an unintended configuration.
