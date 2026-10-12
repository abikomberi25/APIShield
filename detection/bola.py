"""BOLA (OWASP API1:2023) detection engine for APIShield."""

import logging
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.models.item import Item
from backend.models.user import User
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_bola(
    db: Session,
    *,
    current_user: User,
    item: Item,
    defense_active: bool,
) -> Optional[SecurityEvent]:
    """Detect and log cross-user object access attempts (OWASP API1:2023).

    Evaluates whether an authenticated non-admin user is attempting to access an
    item owned by someone else. Emits a real SecurityEvent:
    - action="detected" when defense is OFF (monitor-only mode)
    - action="blocked" when defense is ON (mitigation mode)

    Fails closed if security event persistence fails, raising HTTP 500 to prevent
    un-audited access.
    """
    # 1. Legitimate access checks (never flagged as BOLA)
    if current_user.role == "admin" or item.owner_id == current_user.id:
        return None

    # 2. Determine action based on defense toggle
    action = "blocked" if defense_active else "detected"

    # 3. Persist security event to database
    try:
        event = log_security_event(
            db=db,
            endpoint=f"/items/{item.id}",
            method="GET",
            owasp_category="API1:2023",
            severity="HIGH",
            rule_name="bola_cross_tenant_access",
            action=action,
            user_id=current_user.id,
            object_id=str(item.id),
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("BOLA security event persistence failed: %s", exc)
        # Fail-closed: Deny access if security event cannot be audited
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security event logging failed; access denied",
        ) from exc
