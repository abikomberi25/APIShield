"""Admin management endpoints for APIShield defenses and security events."""

from datetime import datetime
import logging
from typing import Annotated, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.auth.deps import require_admin
from backend.database import get_db
from backend.models.event import SecurityEvent
from backend.models.user import User
from backend.security.defenses import defense_manager

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
    "/defenses",
    response_model=DefensesResponse,
    status_code=status.HTTP_200_OK,
    summary="Get runtime defense toggle statuses (Admin only)",
)
def get_defenses(
    current_user: Annotated[User, Depends(require_admin)],
) -> DefensesResponse:
    """Retrieve the current state of all runtime defense toggles."""
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
    """Update one or more runtime defense toggle states."""
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
    summary="List audit security events with bounded pagination (Admin only)",
)
def get_security_events(
    current_user: Annotated[User, Depends(require_admin)],
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
    """Query persisted security events with bounded pagination and optional filtering."""
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
