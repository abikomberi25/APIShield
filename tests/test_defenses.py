"""Tests for runtime defense toggle manager and admin endpoints."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token, hash_password
from backend.models.user import User
from backend.security.defenses import DEFAULT_DEFENSES, DefenseManager, defense_manager


@pytest.fixture
def test_users(db_session: Session) -> dict[str, str]:
    """Create a normal user and an admin user, returning access tokens."""
    normal_user = User(
        username="alice",
        hashed_password=hash_password("Pass123!"),
        role="user",
    )
    admin_user = User(
        username="admin",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
    )
    db_session.add(normal_user)
    db_session.add(admin_user)
    db_session.commit()
    db_session.refresh(normal_user)
    db_session.refresh(admin_user)

    alice_token = create_access_token(
        subject=str(normal_user.id),
        claims={"username": normal_user.username, "role": normal_user.role},
    )
    admin_token = create_access_token(
        subject=str(admin_user.id),
        claims={"username": admin_user.username, "role": admin_user.role},
    )

    return {
        "alice_token": alice_token,
        "admin_token": admin_token,
    }


def test_defense_manager_defaults() -> None:
    """Verify that DefenseManager initializes with all flags set to False."""
    dm = DefenseManager()
    defenses = dm.get_defenses()
    assert defenses == {
        "bola": False,
        "auth_hardening": False,
        "schema_validation": False,
        "rate_limit": False,
        "rbac": False,
        "deprecated_route_protection": False,
    }


def test_defense_manager_validation_errors() -> None:
    """Verify that DefenseManager rejects unknown keys and non-boolean values."""
    dm = DefenseManager()
    with pytest.raises(ValueError, match="Unknown defense flag: invalid_toggle"):
        dm.update_defenses({"invalid_toggle": True})

    with pytest.raises(ValueError, match="expected bool"):
        dm.update_defenses({"bola": "true"})  # type: ignore[dict-item]


def test_admin_get_defenses_default(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that an admin can retrieve defense statuses (all False by default)."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    response = client.get("/admin/defenses", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "defenses" in data
    assert data["defenses"] == DEFAULT_DEFENSES


def test_admin_patch_defenses_success(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that an admin can update defense toggles."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    patch_response = client.patch(
        "/admin/defenses",
        json={"bola": True, "rate_limit": True},
        headers=headers,
    )
    assert patch_response.status_code == 200
    patch_data = patch_response.json()
    assert patch_data["message"] == "Defenses updated successfully"
    assert patch_data["defenses"]["bola"] is True
    assert patch_data["defenses"]["rate_limit"] is True
    assert patch_data["defenses"]["auth_hardening"] is False

    # Check GET reflects the change
    get_response = client.get("/admin/defenses", headers=headers)
    assert get_response.status_code == 200
    assert get_response.json()["defenses"]["bola"] is True


def test_admin_patch_defenses_rejects_empty_body(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify requirement 1: PATCH /admin/defenses rejects an empty JSON object with HTTP 422."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    response = client.patch("/admin/defenses", json={}, headers=headers)
    assert response.status_code == 422


def test_admin_patch_defenses_rejects_unknown_field(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that unknown defense flags are rejected with HTTP 422."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    response = client.patch(
        "/admin/defenses",
        json={"nonexistent_flag": True},
        headers=headers,
    )
    assert response.status_code == 422


def test_admin_patch_defenses_rejects_non_boolean_values(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that non-boolean values or null are rejected with HTTP 422."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    
    # String value
    res1 = client.patch("/admin/defenses", json={"bola": "true"}, headers=headers)
    assert res1.status_code == 422

    # Integer value
    res2 = client.patch("/admin/defenses", json={"bola": 1}, headers=headers)
    assert res2.status_code == 422

    # Null value
    res3 = client.patch("/admin/defenses", json={"bola": None}, headers=headers)
    assert res3.status_code == 422


def test_normal_user_cannot_read_or_update_defenses(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that a non-admin user receives 403 Forbidden for GET and PATCH."""
    headers = {"Authorization": f"Bearer {test_users['alice_token']}"}
    
    get_res = client.get("/admin/defenses", headers=headers)
    assert get_res.status_code == 403
    assert get_res.json()["detail"] == "Admin access required"

    patch_res = client.patch("/admin/defenses", json={"bola": True}, headers=headers)
    assert patch_res.status_code == 403
    assert patch_res.json()["detail"] == "Admin access required"


def test_unauthenticated_cannot_access_defenses(client: TestClient) -> None:
    """Verify that unauthenticated requests receive 401 Unauthorized."""
    get_res = client.get("/admin/defenses")
    assert get_res.status_code == 401

    patch_res = client.patch("/admin/defenses", json={"bola": True})
    assert patch_res.status_code == 401
