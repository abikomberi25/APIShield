"""OWASP API4:2023 Unrestricted Resource Consumption detection engine for APIShield."""

import logging
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_rate_limit_exceeded(
    db: Session,
    *,
    endpoint: str,
    method: str,
    defense_active: bool,
    user_id: Optional[int] = None,
    key: str = "unknown",
) -> Optional[SecurityEvent]:
    """Detect and log rate-limit violations (OWASP API4:2023).

    Emits a SecurityEvent when a client exceeds the configured request rate.
    - action="detected" when defense is OFF (monitor-only mode)
    - action="blocked" when defense is ON (requests rejected with HTTP 429)

    Fails closed if event persistence fails — raises HTTP 500 to prevent
    unaudited rate-limit bypass.
    """
    action = "blocked" if defense_active else "detected"

    try:
        event = log_security_event(
            db=db,
            endpoint=endpoint,
            method=method,
            owasp_category="API4:2023",
            severity="MEDIUM",
            rule_name="rate_limit_exceeded",
            action=action,
            user_id=user_id,
            object_id=None,
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("Rate-limit security event persistence failed: %s", exc)
        # Fail-closed: deny if security audit fails
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security event logging failed; access denied",
        ) from exc
