"""OWASP API9:2023 Improper Inventory Management detection engine for APIShield."""

import logging
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_deprecated_route_access(
    db: Session,
    *,
    path: str,
    method: str,
    user_id: Optional[int] = None,
    defense_active: bool,
    action: str,
) -> Optional[SecurityEvent]:
    """Detect and log access to deprecated/unlisted API routes (OWASP API9:2023).

    Emits a SecurityEvent for improper inventory management:
    - action='detected' when defense is OFF (monitor-only, access permitted in lab mode)
    - action='blocked' when defense is ON (access denied)

    Fails closed if security event persistence fails, raising HTTP 500 to prevent
    un-audited access.
    """
    try:
        event = log_security_event(
            db=db,
            endpoint=path,
            method=method.upper(),
            owasp_category="API9:2023",
            severity="MEDIUM",
            rule_name="deprecated_route_access",
            action=action,
            user_id=user_id,
            object_id=None,
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("API9 security event persistence failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security event logging failed; access denied",
        ) from exc
