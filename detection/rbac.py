"""BFLA / RBAC (OWASP API5:2023) detection engine for APIShield."""

import logging
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.models.user import User
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_bfla(
    db: Session,
    *,
    current_user: User,
    endpoint: str,
    method: str,
    defense_active: bool,
) -> Optional[SecurityEvent]:
    """Detect and log unauthorized function access attempts (OWASP API5:2023).

    Identifies when an authenticated non-admin user attempts to access an endpoint
    reserved for administrators. Emits a real SecurityEvent:
    - action="detected" when defense is OFF (monitor-only mode)
    - action="blocked" when defense is ON (mitigation mode)

    Fails closed if security event persistence fails, raising HTTP 500 to prevent
    un-audited administrative access.
    """
    # 1. Legitimate admin access checks (never flagged as BFLA)
    if current_user.role == "admin":
        return None

    # 2. Determine action based on defense toggle
    action = "blocked" if defense_active else "detected"

    # 3. Persist security event to database
    try:
        event = log_security_event(
            db=db,
            endpoint=endpoint,
            method=method.upper(),
            owasp_category="API5:2023",
            severity="HIGH",
            rule_name="bfla_unauthorized_function_access",
            action=action,
            user_id=current_user.id,
            object_id=None,
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("BFLA security event persistence failed: %s", exc)
        # Fail-closed: Deny access if security event cannot be audited
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Security event logging failed; access denied",
        ) from exc
