"""Admin management endpoints for APIShield defenses and security events."""

from datetime import datetime
import logging
from typing import Annotated, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.auth.deps import get_current_user, require_admin
from backend.config import is_lab_mode
from backend.database import get_db
from backend.models.event import SecurityEvent
from backend.models.user import User
from backend.security.defenses import defense_manager
from detection.rbac import detect_bfla

logger = logging.getLogger(__name__)

router = APIRouter()


class DefensesResponse(BaseModel):
    """Response containing all runtime defense toggle states."""

    defenses: dict[str, bool]


class DefenseUpdate(BaseModel):
    """Payload for updating runtime defense toggles.

    Rejects unknown fields, non-boolean types, and empty payloads with HTTP 422.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    bola: Optional[bool] = None
    auth_hardening: Optional[bool] = None
    schema_validation: Optional[bool] = None
    rate_limit: Optional[bool] = None
    rbac: Optional[bool] = None

    @model_validator(mode="after")
    def validate_payload(self) -> "DefenseUpdate":
        dumped = self.model_dump(exclude_unset=True)
        if not dumped:
            raise ValueError(
                "Request body must not be empty. At least one defense toggle must be provided."
            )
        for key, val in dumped.items():
            if val is None:
                raise ValueError(f"Defense flag '{key}' cannot be null.")
        return self


class DefenseUpdateResponse(BaseModel):
    """Response returned upon successfully updating defense toggles."""

    message: str
    defenses: dict[str, bool]


class SecurityEventResponse(BaseModel):
    """Safe serialized view of a security event."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    user_id: Optional[int] = None
    endpoint: str
    method: str
    object_id: Optional[str] = None
    owasp_category: str
    severity: str
    rule_name: str
    action: str


class PaginatedEventsResponse(BaseModel):
    """Paginated security events response."""

    total: int
    limit: int
    offset: int
    events: list[SecurityEventResponse]


@router.get(
    "/lab-mode",
    status_code=status.HTTP_200_OK,
    summary="Inspect startup lab mode status (Admin only)",
)
def get_lab_mode_status(
    current_user: Annotated[User, Depends(require_admin)],
) -> dict[str, bool]:
    """Inspect whether the server process is currently running with lab mode enabled.

    Read-only: cannot be enabled over HTTP if the server was started with APISHIELD_LAB_MODE=false.
    Strictly protected by require_admin in all modes.
    """
    return {"lab_mode": is_lab_mode()}


@router.get(
    "/defenses",
    response_model=DefensesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get runtime defense toggle statuses (Admin only)",
)
def get_defenses(
    current_user: Annotated[User, Depends(require_admin)],
) -> DefensesResponse:
    """Retrieve the current state of all runtime defense toggles.

    Strictly protected by require_admin in all modes.
    """
    return DefensesResponse(defenses=defense_manager.get_defenses())


@router.patch(
    "/defenses",
    response_model=DefenseUpdateResponse,
    status_code=status.HTTP_200_OK,
    summary="Update runtime defense toggle statuses (Admin only)",
)
def patch_defenses(
    updates: DefenseUpdate,
    current_user: Annotated[User, Depends(require_admin)],
) -> DefenseUpdateResponse:
    """Update one or more runtime defense toggle states.

    Strictly protected by require_admin in all modes.
    """
    update_dict = updates.model_dump(exclude_unset=True)
    try:
        updated_state = defense_manager.update_defenses(update_dict)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    return DefenseUpdateResponse(
        message="Defenses updated successfully",
        defenses=updated_state,
    )


@router.get(
    "/events",
    response_model=PaginatedEventsResponse,
    status_code=status.HTTP_200_OK,
    summary="List audit security events with bounded pagination",
)
def get_security_events(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[
        int, Query(ge=1, le=100, description="Max events to return (1-100)")
    ] = 50,
    offset: Annotated[int, Query(ge=0, description="Pagination offset")] = 0,
    action: Annotated[
        Optional[Literal["detected", "blocked"]],
        Query(description="Filter events by action"),
    ] = None,
) -> PaginatedEventsResponse:
    """Query persisted security events with bounded pagination and optional filtering.

    Designated BFLA (OWASP API5:2023) Experiment Endpoint:
    1. Authentication (JWT verification) is required in all modes via get_current_user.
    2. Legitimate administrators (role == 'admin') access events without generating BFLA events.
    3. Non-admin users (role != 'admin'):
       - Outside lab mode (is_lab_mode() is False): strictly rejected with HTTP 403 Forbidden.
       - Inside lab mode (APISHIELD_LAB_MODE=true at boot):
         * Evaluates defense toggle (defenses['rbac']).
         * BFLA detector runs unconditionally (action='detected' if OFF, action='blocked' if ON).
         * If defenses['rbac'] is ON: strictly rejected with HTTP 403 Forbidden.
         * If defenses['rbac'] is OFF: allows the read to demonstrate BFLA vulnerability.
    """
    # 1. Legitimate admin access checks (never flagged as BFLA)
    if current_user.role == "admin":
        pass
    else:
        # Non-admin user attempting administrative events access
        if not is_lab_mode():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        defense_active = defense_manager.get_defenses().get("rbac", False)

        # BFLA detector runs unconditionally (identifies unauthorized function access and logs real event)
        detect_bfla(
            db=db,
            current_user=current_user,
            endpoint="/admin/events",
            method="GET",
            defense_active=defense_active,
        )

        if defense_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required",
            )

        # VULNERABLE (OWASP API5): BFLA active on GET /admin/events only when APISHIELD_LAB_MODE=true and defenses['rbac'] is OFF

    try:
        query = db.query(SecurityEvent)
        if action is not None:
            query = query.filter(SecurityEvent.action == action)

        total = query.count()
        events = (
            query.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        return PaginatedEventsResponse(
            total=total,
            limit=limit,
            offset=offset,
            events=events,
        )
    except SQLAlchemyError as exc:
        logger.error("Failed to query security events: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security events due to database error",
        )
