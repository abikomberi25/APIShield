"""Item resource routes for APIShield."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from backend.auth.deps import get_current_user
from backend.config import is_lab_mode
from backend.database import get_db
from backend.models.item import Item
from backend.models.user import User
from backend.security.defenses import defense_manager
from detection.bola import detect_bola

router = APIRouter()


class ItemResponse(BaseModel):
    """Safe item representation."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: Optional[str] = None
    owner_id: int


@router.get(
    "/{item_id}",
    response_model=ItemResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve an item by ID (Protected)",
)
def get_item(
    item_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Item:
    """Retrieve an item by its ID.

    Baseline Security Rule:
    - Normal users are authorized ONLY if they own the item (item.owner_id == current_user.id).
    - Admins have baseline administrative access across all items (current_user.role == "admin").
      (Explicit architectural note: This is an intentional role-based authorization rule,
      NOT a BOLA defense bypass).
    - In M3, this ownership check will be hooked into defenses['bola'] to demonstrate BOLA.
    """
    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Item not found",
        )

    # Object-level authorization check
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

    return item
