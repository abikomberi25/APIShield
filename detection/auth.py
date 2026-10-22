"""OWASP API2:2023 Broken Authentication detection engine for APIShield."""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from backend.models.event import SecurityEvent
from backend.security.events import SecurityEventPersistenceError, log_security_event

logger = logging.getLogger(__name__)


def detect_brute_force(
    db: Session,
    *,
    username: str,
    endpoint: str,
    method: str,
    defense_active: bool,
    action: str,
    user_id: Optional[int] = None,
) -> Optional[SecurityEvent]:
    """Detect and log brute-force/credential-stuffing attempts (OWASP API2:2023).

    Emits a SecurityEvent for failed login attempts that exceed the threshold.
    action="detected" when defense is OFF (monitor-only)
    action="blocked" when defense is ON (lockout enforced)
    Fails closed if event persistence fails.
    Never logs passwords, tokens, or Authorization headers.
    """
    try:
        event = log_security_event(
            db=db,
            endpoint=endpoint,
            method=method,
            owasp_category="API2:2023",
            severity="HIGH",
            rule_name="auth_brute_force",
            action=action,
            user_id=user_id,
            object_id=username,
        )
        return event
    except SecurityEventPersistenceError as exc:
        logger.error("Broken Authentication security event persistence failed: %s", exc)
        return None
