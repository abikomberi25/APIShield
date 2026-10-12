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
