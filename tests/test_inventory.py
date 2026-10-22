"""Tests for OWASP API9:2023 Improper Inventory Management (M7).

Covers:
  - Inventory endpoint requires admin authentication
  - Inventory lists all routes including deprecated ones
  - Deprecated route access in lab mode + defense OFF (vulnerability exploited)
  - Deprecated route access in lab mode + defense ON (blocked)
  - Deprecated route always 404 in safe mode (outside lab)
  - Attack script allowlist validation
  - Security event emitted for deprecated route access
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.config import set_lab_mode
from backend.security.defenses import defense_manager
from attacks.inventory import _validate_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_users(db: Session) -> None:
    """Seed admin and a regular user for tests."""
    import bcrypt
    from backend.models.user import User

    admin_hash = bcrypt.hashpw(b"adminpassword", bcrypt.gensalt()).decode()
    user_hash = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode()

    db.add(User(username="admin", hashed_password=admin_hash, role="admin"))
    db.add(User(username="alice", hashed_password=user_hash, role="user"))
    db.commit()


def _seed_item(db: Session, owner_id: int) -> int:
    from backend.models.item import Item

    item = Item(title="Secret Widget", description="Sensitive item", owner_id=owner_id)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item.id


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.json()["access_token"]  # type: ignore[return-value]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _set_defense(client: TestClient, admin_token: str, name: str, value: bool) -> None:
    resp = client.patch("/admin/defenses", json={name: value}, headers=_auth(admin_token))
    assert resp.status_code == 200


def _get_events(client: TestClient, admin_token: str) -> list[dict]:
    resp = client.get("/admin/events", headers=_auth(admin_token))
    assert resp.status_code == 200
    return resp.json().get("events", [])  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Inventory endpoint tests
# ---------------------------------------------------------------------------

class TestInventoryEndpoint:
    def test_inventory_requires_auth(self, client: TestClient) -> None:
        """Unauthenticated request to inventory returns 401."""
        resp = client.get("/admin/inventory")
        assert resp.status_code == 401

    def test_inventory_requires_admin(self, client: TestClient, db_session: Session) -> None:
        """Regular user cannot access inventory — returns 403."""
        _seed_users(db_session)
        token = _login(client, "alice", "password123")
        resp = client.get("/admin/inventory", headers=_auth(token))
        assert resp.status_code == 403

    def test_inventory_returns_routes_list(self, client: TestClient, db_session: Session) -> None:
        """Admin can retrieve the route inventory."""
        _seed_users(db_session)
        token = _login(client, "admin", "adminpassword")
        resp = client.get("/admin/inventory", headers=_auth(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "routes" in data
        assert "total" in data
        assert data["total"] == len(data["routes"])

    def test_inventory_includes_deprecated_route(self, client: TestClient, db_session: Session) -> None:
        """Inventory explicitly includes the deprecated /api/v0/items route."""
        _seed_users(db_session)
        token = _login(client, "admin", "adminpassword")
        resp = client.get("/admin/inventory", headers=_auth(token))
        assert resp.status_code == 200
        routes = resp.json()["routes"]
        deprecated = [r for r in routes if r.get("status") == "deprecated"]
        assert len(deprecated) >= 1
        deprecated_paths = [r["path"] for r in deprecated]
        assert any("/api/v0/items" in p for p in deprecated_paths)

    def test_inventory_shows_lab_mode_status(self, client: TestClient, db_session: Session) -> None:
        """Inventory response includes lab_mode flag."""
        _seed_users(db_session)
        token = _login(client, "admin", "adminpassword")
        resp = client.get("/admin/inventory", headers=_auth(token))
        assert resp.status_code == 200
        data = resp.json()
        assert "lab_mode" in data
        assert data["lab_mode"] is False  # safe mode by default


# ---------------------------------------------------------------------------
# Deprecated route — safe mode (outside lab)
# ---------------------------------------------------------------------------

class TestDeprecatedRouteSafeMode:
    def test_deprecated_route_not_found_outside_lab(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Outside lab mode, the deprecated route always returns 404."""
        _seed_users(db_session)
        user_token = _login(client, "alice", "password123")
        # lab mode is OFF by default
        resp = client.get("/api/v0/items/1", headers=_auth(user_token))
        assert resp.status_code == 404

    def test_deprecated_route_not_found_outside_lab_no_event(
        self, client: TestClient, db_session: Session
    ) -> None:
        """No security event is emitted when accessing deprecated route outside lab."""
        _seed_users(db_session)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")
        client.get("/api/v0/items/1", headers=_auth(user_token))
        events = _get_events(client, admin_token)
        api9_events = [e for e in events if e.get("owasp_category") == "API9:2023"]
        assert len(api9_events) == 0


# ---------------------------------------------------------------------------
# Deprecated route — lab mode, defense OFF (vulnerable)
# ---------------------------------------------------------------------------

class TestDeprecatedRouteVulnerable:
    def test_deprecated_route_returns_data_lab_defense_off(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Lab mode + defense OFF: deprecated route returns item data (vulnerability exploited)."""
        _seed_users(db_session)
        set_lab_mode(True)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")

        # Get alice's user id
        from backend.models.user import User
        alice = db_session.query(User).filter(User.username == "alice").first()
        item_id = _seed_item(db_session, alice.id)

        _set_defense(client, admin_token, "deprecated_route_protection", False)
        resp = client.get(f"/api/v0/items/{item_id}", headers=_auth(user_token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == item_id
        assert data["_deprecated"] is True

    def test_deprecated_route_emits_detected_event_lab_defense_off(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Lab mode + defense OFF: accessing deprecated route emits 'detected' event."""
        _seed_users(db_session)
        set_lab_mode(True)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")

        from backend.models.user import User
        alice = db_session.query(User).filter(User.username == "alice").first()
        item_id = _seed_item(db_session, alice.id)

        _set_defense(client, admin_token, "deprecated_route_protection", False)
        client.get(f"/api/v0/items/{item_id}", headers=_auth(user_token))

        events = _get_events(client, admin_token)
        api9 = [e for e in events if e.get("owasp_category") == "API9:2023"]
        assert len(api9) == 1
        assert api9[0]["action"] == "detected"
        assert api9[0]["rule_name"] == "deprecated_route_access"


# ---------------------------------------------------------------------------
# Deprecated route — lab mode, defense ON (defended)
# ---------------------------------------------------------------------------

class TestDeprecatedRouteDefended:
    def test_deprecated_route_blocked_lab_defense_on(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Lab mode + defense ON: deprecated route returns 403 (attack blocked)."""
        _seed_users(db_session)
        set_lab_mode(True)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")

        _set_defense(client, admin_token, "deprecated_route_protection", True)
        resp = client.get("/api/v0/items/1", headers=_auth(user_token))
        assert resp.status_code == 403

    def test_deprecated_route_emits_blocked_event_lab_defense_on(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Lab mode + defense ON: accessing deprecated route emits 'blocked' event."""
        _seed_users(db_session)
        set_lab_mode(True)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")

        _set_defense(client, admin_token, "deprecated_route_protection", True)
        client.get("/api/v0/items/1", headers=_auth(user_token))

        events = _get_events(client, admin_token)
        api9 = [e for e in events if e.get("owasp_category") == "API9:2023"]
        assert len(api9) == 1
        assert api9[0]["action"] == "blocked"
        assert api9[0]["rule_name"] == "deprecated_route_access"

    def test_deprecated_route_no_data_disclosed_when_blocked(
        self, client: TestClient, db_session: Session
    ) -> None:
        """When defense is ON, no item data is returned in the 403 response."""
        _seed_users(db_session)
        set_lab_mode(True)
        admin_token = _login(client, "admin", "adminpassword")
        user_token = _login(client, "alice", "password123")

        from backend.models.user import User
        alice = db_session.query(User).filter(User.username == "alice").first()
        _seed_item(db_session, alice.id)

        _set_defense(client, admin_token, "deprecated_route_protection", True)
        resp = client.get("/api/v0/items/1", headers=_auth(user_token))
        assert resp.status_code == 403
        data = resp.json()
        # No item fields in error response
        assert "title" not in data
        assert "description" not in data
        assert "owner_id" not in data

    def test_deprecated_route_unauthenticated_returns_401(
        self, client: TestClient, db_session: Session
    ) -> None:
        """Unauthenticated access to deprecated route returns 401 (auth happens first)."""
        set_lab_mode(True)
        resp = client.get("/api/v0/items/1")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Attack script allowlist validation
# ---------------------------------------------------------------------------

class TestInventoryAttackAllowlist:
    def test_allowlist_blocks_external_host(self) -> None:
        """Attack script rejects non-allowlisted hosts."""
        with pytest.raises(ValueError, match="Disallowed target"):
            _validate_target("http://evil.example.com:8000")

    def test_allowlist_blocks_wrong_port(self) -> None:
        """Attack script rejects correct host with wrong port."""
        with pytest.raises(ValueError, match="Disallowed target"):
            _validate_target("http://127.0.0.1:9999")

    def test_allowlist_permits_localhost(self) -> None:
        """Attack script allows localhost:8000."""
        _validate_target("http://localhost:8000")  # should not raise

    def test_allowlist_permits_127_0_0_1(self) -> None:
        """Attack script allows 127.0.0.1:8000."""
        _validate_target("http://127.0.0.1:8000")  # should not raise
