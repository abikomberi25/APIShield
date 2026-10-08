"""Tests for protected Item endpoint and JWT authorization (Milestone M1-D)."""

from datetime import timedelta
import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token
from backend.config import JWT_ALGORITHM, JWT_SECRET
from backend.models.item import Item
from backend.models.user import User


def test_get_item_missing_token(client: TestClient) -> None:
    """Verify accessing protected item without token returns HTTP 401."""
    response = client.get("/items/1")
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"
    assert response.json()["detail"] == "Not authenticated"


def test_get_item_malformed_token(client: TestClient) -> None:
    """Verify malformed token returns HTTP 401."""
    headers = {"Authorization": "Bearer malformed.token.value"}
    response = client.get("/items/1", headers=headers)
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"
    assert response.json()["detail"] == "Could not validate credentials"


def test_get_item_invalid_signature_token(client: TestClient, db_session: Session) -> None:
    """Verify token signed with a different secret returns HTTP 401."""
    # Create a user
    user = User(username="sig_user", hashed_password="dummy", role="user")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Token signed with wrong secret
    tampered_token = jwt.encode(
        {"sub": str(user.id), "username": user.username, "role": user.role, "exp": 9999999999},
        "wrong-secret-key-that-is-at-least-32-bytes-long",
        algorithm=JWT_ALGORITHM,
    )
    headers = {"Authorization": f"Bearer {tampered_token}"}
    response = client.get("/items/1", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


def test_get_item_expired_token(client: TestClient, db_session: Session) -> None:
    """Verify expired token returns HTTP 401."""
    user = User(username="expired_user", hashed_password="dummy", role="user")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    expired_token = create_access_token(
        subject=str(user.id),
        claims={"username": user.username, "role": user.role},
        expires_delta=timedelta(seconds=-10),
    )
    headers = {"Authorization": f"Bearer {expired_token}"}
    response = client.get("/items/1", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] == "Token expired"


def test_get_own_item_success(client: TestClient, db_session: Session) -> None:
    """Verify authenticated user can access their own item (HTTP 200)."""
    # Create user
    user = User(username="owner_user", hashed_password="dummy", role="user")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Create item owned by this user
    item = Item(title="Owner Private Item", description="Confidential", owner_id=user.id)
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)

    token = create_access_token(subject=str(user.id), claims={"username": user.username, "role": user.role})
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get(f"/items/{item.id}", headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == item.id
    assert data["title"] == "Owner Private Item"
    assert data["owner_id"] == user.id


def test_get_other_user_item_forbidden(client: TestClient, db_session: Session) -> None:
    """Verify normal user cannot access another user's item (HTTP 403)."""
    # Create user A (owner)
    user_a = User(username="user_a", hashed_password="dummy", role="user")
    db_session.add(user_a)
    db_session.commit()
    db_session.refresh(user_a)

    # Create user B (attacker/other user)
    user_b = User(username="user_b", hashed_password="dummy", role="user")
    db_session.add(user_b)
    db_session.commit()
    db_session.refresh(user_b)

    # Create item owned by User A
    item_a = Item(title="User A Secret Item", description="Secrets of A", owner_id=user_a.id)
    db_session.add(item_a)
    db_session.commit()
    db_session.refresh(item_a)

    # User B requests User A's item
    token_b = create_access_token(subject=str(user_b.id), claims={"username": user_b.username, "role": user_b.role})
    headers_b = {"Authorization": f"Bearer {token_b}"}

    response = client.get(f"/items/{item_a.id}", headers=headers_b)
    assert response.status_code == 403
    assert response.json()["detail"] == "Not authorized to access this item"


def test_admin_can_access_other_user_item(client: TestClient, db_session: Session) -> None:
    """Verify admin user can access items owned by other users as baseline RBAC rule (HTTP 200)."""
    # Create normal user
    regular_user = User(username="regular_user", hashed_password="dummy", role="user")
    db_session.add(regular_user)

    # Create admin user
    admin_user = User(username="admin_sys", hashed_password="dummy", role="admin")
    db_session.add(admin_user)
    db_session.commit()
    db_session.refresh(regular_user)
    db_session.refresh(admin_user)

    # Create item owned by regular user
    item = Item(title="Regular User Item", description="Some note", owner_id=regular_user.id)
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)

    # Admin requests regular user's item
    token_admin = create_access_token(
        subject=str(admin_user.id),
        claims={"username": admin_user.username, "role": admin_user.role},
    )
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    response = client.get(f"/items/{item.id}", headers=headers_admin)
    assert response.status_code == 200
    assert response.json()["id"] == item.id
    assert response.json()["owner_id"] == regular_user.id


def test_get_nonexistent_item_not_found(client: TestClient, db_session: Session) -> None:
    """Verify requesting nonexistent item returns HTTP 404."""
    user = User(username="any_user", hashed_password="dummy", role="user")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(subject=str(user.id), claims={"username": user.username, "role": user.role})
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/items/99999", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Item not found"
