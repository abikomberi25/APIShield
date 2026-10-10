"""Security event logging service for APIShield."""

from datetime import datetime, timezone
import logging
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent

logger = logging.getLogger(__name__)

VALID_ACTIONS: frozenset[str] = frozenset({"detected", "blocked"})
VALID_SEVERITIES: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


class SecurityEventError(Exception):
    """Base exception for security event operations."""

    pass


class SecurityEventPersistenceError(SecurityEventError):
    """Exception raised when a security event fails to persist to the database."""

    pass


def log_security_event(
    db: Session,
    *,
    endpoint: str,
    method: str,
    owasp_category: str,
    severity: str,
    rule_name: str,
    action: str,
    user_id: Optional[int] = None,
    object_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> SecurityEvent:
    """Validate and persist a security event to the SQLite security_events table.

    Enforces dual validation (service-level validation + SQLite check constraints).
    Safely handles database failures with transaction rollback and error containment.
    Never logs passwords, tokens, or raw Authorization headers.
    """
    # 1. Service-level attribute validation
    if action not in VALID_ACTIONS:
        raise ValueError(
            f"Invalid action '{action}'. Action must be strictly 'detected' or 'blocked'."
        )

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity '{severity}'. Severity must be one of: {sorted(VALID_SEVERITIES)}."
        )

    if not endpoint or not endpoint.strip():
        raise ValueError("Field 'endpoint' must be a non-empty string.")

    if not method or not method.strip():
        raise ValueError("Field 'method' must be a non-empty string.")

    if not owasp_category or not owasp_category.strip():
        raise ValueError("Field 'owasp_category' must be a non-empty string.")

    if not rule_name or not rule_name.strip():
        raise ValueError("Field 'rule_name' must be a non-empty string.")

    # 2. Construct event model instance
    event = SecurityEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        user_id=user_id,
        endpoint=endpoint.strip(),
        method=method.strip().upper(),
        object_id=str(object_id).strip() if object_id is not None else None,
        owasp_category=owasp_category.strip(),
        severity=severity,
        rule_name=rule_name.strip(),
        action=action,
    )

    # 3. Safe database persistence with rollback and error containment
    try:
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Failed to persist security event: %s", exc)
        raise SecurityEventPersistenceError(
            "Failed to persist security event due to database error."
        ) from exc
