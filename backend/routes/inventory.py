"""OWASP API9:2023 Improper Inventory Management routes for APIShield.

Exposes:
  GET  /admin/inventory       — admin-only route listing all API endpoints including deprecated ones
  GET  /api/v0/items/{item_id} — synthetic deprecated route (lab-mode demonstration)
"""

from typing import Any, Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.auth.deps import get_current_user, require_admin
from backend.config import is_lab_mode
from backend.database import get_db
from backend.models.user import User
from backend.security.defenses import defense_manager
from detection.inventory import detect_deprecated_route_access

router = APIRouter(tags=["admin-inventory"])

# Canonical list of all API routes for inventory reporting
API_INVENTORY = [
    {"path": "/auth/login", "method": "POST", "status": "active", "auth": "none", "version": "v1"},
    {"path": "/items/", "method": "GET", "status": "active", "auth": "user", "version": "v1"},
    {"path": "/items/{item_id}", "method": "GET", "status": "active", "auth": "user", "version": "v1"},
    {"path": "/admin/defenses", "method": "GET", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/admin/defenses/{name}", "method": "PATCH", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/admin/lab-mode", "method": "GET", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/admin/lab-mode", "method": "POST", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/admin/events", "method": "GET", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/admin/inventory", "method": "GET", "status": "active", "auth": "admin", "version": "v1"},
    {"path": "/health", "method": "GET", "status": "active", "auth": "none", "version": "v1"},
    # Deprecated route — still reachable in lab mode
    {
        "path": "/api/v0/items/{item_id}",
        "method": "GET",
        "status": "deprecated",
        "auth": "user",
        "version": "v0",
        "note": "Superseded by /items/{item_id}. Should be decommissioned.",
    },
]


@router.get("/admin/inventory")
def get_inventory(
    current_user: Annotated[User, Depends(require_admin)],
) -> Any:
    """Return the full API route inventory including deprecated endpoints.

    Admin-only. Lists all known API routes, their status (active/deprecated),
    authentication requirements, and version. Demonstrates that deprecated
    routes are still discoverable — the API9:2023 risk.
    """
    return {
        "total": len(API_INVENTORY),
        "lab_mode": is_lab_mode(),
        "deprecated_route_protection": defense_manager.get_defenses().get(
            "deprecated_route_protection", False
        ),
        "routes": API_INVENTORY,
    }


@router.get("/api/v0/items/{item_id}")
def deprecated_get_item(
    item_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    """Deprecated v0 items endpoint — demonstrates API9:2023 Improper Inventory Management.

    In safe mode (lab_mode=False): always returns 404 (route effectively decommissioned).
    In lab mode + deprecated_route_protection=OFF: returns item data, emits 'detected' event.
    In lab mode + deprecated_route_protection=ON: returns 403, emits 'blocked' event.

    This synthetic endpoint simulates a real-world scenario where an old API version
    is forgotten but still reachable, exposing the same data as the current endpoint.
    """
    if not is_lab_mode():
        # Safe mode: route appears non-existent outside the lab
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    defenses = defense_manager.get_defenses()
    protection_active = defenses.get("deprecated_route_protection", False)
    action = "blocked" if protection_active else "detected"

    # Always emit a security event when accessed in lab mode
    detect_deprecated_route_access(
        db,
        path=f"/api/v0/items/{item_id}",
        method="GET",
        user_id=current_user.id,
        defense_active=protection_active,
        action=action,
    )

    if protection_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Deprecated route access blocked by defense policy.",
        )

    # Defense OFF: return item data (vulnerable — same as active route, no extra checks)
    from backend.models.item import Item

    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

    return {
        "id": item.id,
        "title": item.title,
        "description": item.description,
        "owner_id": item.owner_id,
        "_deprecated": True,
        "_warning": "This endpoint is deprecated. Use /items/{item_id} instead.",
    }
