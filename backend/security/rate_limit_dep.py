"""Rate-limit enforcement dependency for APIShield FastAPI routes.

Provides a FastAPI dependency that checks the in-memory rate limiter
and rejects excess requests with HTTP 429 when rate_limit defense is ON.
Detection always runs (monitor-only when defense is OFF).
"""

import logging
from typing import Annotated, Optional
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.auth.deps import get_current_user
from backend.database import get_db
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.rate_limiter import rate_limiter
from detection.rate_limit import detect_rate_limit_exceeded

logger = logging.getLogger(__name__)

# Requests per window before rate-limiting triggers
RATE_LIMIT_THRESHOLD = 20
RATE_LIMIT_WINDOW_SECONDS = 60


async def check_rate_limit(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> None:
    """FastAPI dependency that enforces rate limiting on protected routes.

    Keys by authenticated user ID to ensure per-user isolation.
    When rate_limit defense is ON: rejects excess requests with HTTP 429.
    When rate_limit defense is OFF: monitors only (logs detected event, allows request).
    Detection always runs before blocking — ensures monitor-only mode works correctly.
    """
    defense_active = defense_manager.get_defenses().get("rate_limit", False)
    key = f"user:{current_user.id}"

    allowed, remaining = rate_limiter.check_and_record(key)

    if not allowed:
        # Rate limit exceeded — detect regardless of defense toggle
        try:
            detect_rate_limit_exceeded(
                db=db,
                endpoint=request.url.path,
                method=request.method,
                defense_active=defense_active,
                user_id=current_user.id,
                key=key,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Rate-limit detection failed: %s", exc)

        if defense_active:
            retry_after = rate_limiter.get_window_reset_seconds(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Too many requests.",
                headers={"Retry-After": str(retry_after)},
            )
        # VULNERABLE (OWASP API4): rate limit exceeded but defense is OFF — allow request
