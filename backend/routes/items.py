"""Item resource routes for APIShield."""

from typing import Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.auth.deps import get_current_user
from backend.config import is_lab_mode
from backend.database import get_db
from backend.models.item import Item
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.rate_limit_dep import check_rate_limit
from detection.bola import detect_bola
from detection.bopla import detect_bopla_read

router = APIRouter()


class ItemResponse(BaseModel):
    """Safe public item representation (sanitized schema)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    owner_id: int


class ItemInternalResponse(ItemResponse):
    """Internal item representation including restricted administrative properties."""

    internal_notes: Optional[str]
    is_confidential: bool


@router.get(
    "/{item_id}",
    response_model=Union[ItemInternalResponse, ItemResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve an item by ID (Protected)",
    dependencies=[Depends(check_rate_limit)],
)
def get_item(
    item_id: int,
    include_internal: bool = Query(
        False,
        description="Request internal administrative properties (BOPLA experiment probe)",
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Union[ItemInternalResponse, ItemResponse]:
    """Retrieve an item by its ID.

    Authorization and Security Experiment Flow:
    1. Unknown items return HTTP 404 immediately.
    2. BOLA Ownership Authorization:
       - Item owner (item.owner_id == current_user.id) -> proceeds to property checks.
       - Admin (current_user.role == "admin") -> proceeds to property checks.
       - Cross-user access attempt:
         * Outside lab mode: strictly rejected with HTTP 403 (BOLA protection).
         * Inside lab mode: evaluated under BOLA defense toggle.
    3. Property Authorization (OWASP API3:2023 BOPLA Excessive Data Exposure):
       - If current_user is admin:
         * Always authorized to view internal properties if requested (zero events).
       - If current_user is normal owner:
         * include_internal is False: returns sanitized ItemResponse (zero events).
         * include_internal is True:
           - Outside lab mode: returns sanitized ItemResponse (zero events).
           - Inside lab mode:
             * Evaluates defenses['schema_validation'].
             * detect_bopla_read() runs unconditionally, logging real SecurityEvent.
             * If schema_validation is ON: raises HTTP 403 Forbidden.
             * If schema_validation is OFF: returns ItemInternalResponse (# VULNERABLE OWASP API3).
    """
    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found",
        )

    # 1. BOLA Ownership Authorization Check (preserves M1 & M3 invariants)
    is_owner = item.owner_id == current_user.id
    is_admin = current_user.role == "admin"

    if not is_owner and not is_admin:
        # Cross-user access attempt
        if not is_lab_mode():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this item",
            )

        # Lab mode active: evaluate BOLA defense toggle
        bola_active = defense_manager.get_defenses().get("bola", False)
        detect_bola(
            db=db,
            current_user=current_user,
            item=item,
            defense_active=bola_active,
        )

        if bola_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this item",
            )

        # VULNERABLE (OWASP API1: BOLA): return sanitized public representation
        return ItemResponse.model_validate(item)

    # 2. Property Authorization Check (OWASP API3:2023 BOPLA Excessive Data Exposure)
    if is_admin:
        # Legitimate administrator access
        if include_internal:
            return ItemInternalResponse.model_validate(item)
        return ItemResponse.model_validate(item)

    # Normal owner access
    if not include_internal:
        # Ordinary owner read: return standard public representation
        return ItemResponse.model_validate(item)

    # Non-admin owner requesting restricted properties
    if not is_lab_mode():
        # Default safe baseline: sanitize response outside explicit lab mode
        return ItemResponse.model_validate(item)

    # Lab mode active: evaluate schema_validation defense toggle
    defense_active = defense_manager.get_defenses().get("schema_validation", False)

    # Detector runs unconditionally (identifies unauthorized property read and logs real event)
    detect_bopla_read(
        db=db,
        current_user=current_user,
        item=item,
        defense_active=defense_active,
    )

    if defense_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized property access: internal fields restricted to administrators",
        )

    # VULNERABLE (OWASP API3: Excessive Data Exposure): active only when APISHIELD_LAB_MODE=true and defenses['schema_validation'] is OFF
    return ItemInternalResponse.model_validate(item)
