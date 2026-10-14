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
