"""BOPLA (OWASP API3:2023) detection engine for APIShield."""

import logging
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.models.item import Item
from backend.models.user import User
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_bopla_read(
    db: Session,
    *,
    current_user: User,
    item: Item,
    defense_active: bool,
) -> Optional[SecurityEvent]:
    """Detect and log excessive data exposure attempts (OWASP API3:2023).

    Identifies when an authenticated non-admin user attempts to read restricted
    internal object properties (such as internal_notes and is_confidential).
    Emits a real SecurityEvent:
    - action="detected" when defense is OFF (monitor-only mode)
    - action="blocked" when defense is ON (mitigation mode)

    Legitimate administrators (role == "admin") are never flagged.

    Fails closed if security event persistence fails, raising HTTP 500 to prevent
    un-audited disclosure of restricted properties.
    """
    # 1. Legitimate admin access checks (never flagged as BOPLA)
    if current_user.role == "admin":
        return None

    # 2. Determine action based on defense toggle
    action = "blocked" if defense_active else "detected"

    # 3. Persist security event to database
    try:
        event = log_security_event(
            db=db,
            endpoint=f"/items/{item.id}",
            method="GET",
            owasp_category="API3:2023",
            severity="MEDIUM",
            rule_name="bopla_excessive_data_exposure",
            action=action,
            user_id=current_user.id,
            object_id=str(item.id),
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("BOPLA security event persistence failed: %s", exc)
        # Fail-closed: Deny access if security event cannot be audited
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security event logging failed; access denied",
        ) from exc
