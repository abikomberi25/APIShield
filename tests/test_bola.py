"""Tests for OWASP API1:2023 (BOLA) attack, detection, defense, and verification."""

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from attacks.bola import run_bola_attack, validate_target_url
from backend.auth.security import create_access_token, hash_password
from backend.models.event import SecurityEvent
from backend.models.item import Item
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.events import SecurityEventPersistenceError


@pytest.fixture
def seeded_db(db_session: Session) -> dict[str, Any]:
    """Seed synthetic users (Alice, Bob, Admin) and items for testing."""
    alice = User(
        username="alice",
        hashed_password=hash_password("AliceSyntheticPass123!"),
        role="user",
    )
    bob = User(
        username="bob",
        hashed_password=hash_password("BobSyntheticPass123!"),
        role="user",
    )
    admin = User(
        username="admin",
        hashed_password=hash_password("AdminSyntheticPass123!"),
        role="admin",
    )
    db_session.add_all([alice, bob, admin])
    db_session.commit()
    db_session.refresh(alice)
    db_session.refresh(bob)
    db_session.refresh(admin)

    item1 = Item(title="Alice Doc 1", description="Private", owner_id=alice.id)
    item2 = Item(title="Alice Doc 2", description="Private", owner_id=alice.id)
    item3 = Item(title="Bob Doc 1", description="Bob Secret", owner_id=bob.id)
    item4 = Item(title="Bob Doc 2", description="Bob Secret", owner_id=bob.id)
    db_session.add_all([item1, item2, item3, item4])
    db_session.commit()
    db_session.refresh(item1)
    db_session.refresh(item2)
    db_session.refresh(item3)
    db_session.refresh(item4)

    alice_token = create_access_token(
        subject=str(alice.id), claims={"username": alice.username, "role": alice.role}
    )
    bob_token = create_access_token(
        subject=str(bob.id), claims={"username": bob.username, "role": bob.role}
    )
    admin_token = create_access_token(
        subject=str(admin.id), claims={"username": admin.username, "role": admin.role}
    )

    return {
        "alice": alice,
        "bob": bob,
        "admin": admin,
        "item1": item1,
        "item3": item3,
        "alice_token": alice_token,
        "bob_token": bob_token,
        "admin_token": admin_token,
    }


def test_auth_baseline_in_lab_mode(client: TestClient, lab_mode_enabled: None) -> None:
    """Verify that authentication baseline (HTTP 401) is preserved even with lab mode active."""
    # Missing token
    res1 = client.get("/items/3")
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Not authenticated"

    # Malformed token
    res2 = client.get("/items/3", headers={"Authorization": "Bearer malformed.jwt.token"})
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Could not validate credentials"

    # Expired token
    expired = create_access_token(
        subject="1", claims={"username": "alice", "role": "user"}, expires_delta=timedelta(seconds=-10)
    )
    res3 = client.get("/items/3", headers={"Authorization": f"Bearer {expired}"})
    assert res3.status_code == 401
    assert res3.json()["detail"] == "Token expired"


def test_owner_access_no_bola_event(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify legitimate owner access returns HTTP 200 with zero security events."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    res = client.get(f"/items/{seeded_db['item1'].id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["id"] == seeded_db["item1"].id
    assert res.json()["owner_id"] == seeded_db["alice"].id

    # Verify no BOLA event was generated
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_admin_access_no_bola_event(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify legitimate administrative access returns HTTP 200 with zero security events."""
    headers = {"Authorization": f"Bearer {seeded_db['admin_token']}"}
    res = client.get(f"/items/{seeded_db['item3'].id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["id"] == seeded_db["item3"].id
    assert res.json()["owner_id"] == seeded_db["bob"].id

    # Verify no BOLA event was generated
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_nonexistent_item_no_bola_event(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify nonexistent object returns HTTP 404 with zero security events."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    res = client.get("/items/99999", headers=headers)
    assert res.status_code == 404
    assert res.json()["detail"] == "Item not found"

    # Verify no BOLA event was generated
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_default_safe_mode_outside_lab_mode(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any]
) -> None:
    """Verify that outside lab mode, cross-user access is strictly rejected with HTTP 403."""
    # Note: lab_mode_enabled fixture is NOT used here; STARTUP_LAB_MODE is False
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Even if defenses['bola'] is False, default safe mode blocks cross-user read
    assert defense_manager.get_defenses()["bola"] is False
    res = client.get(f"/items/{seeded_db['item3'].id}", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "Not authorized to access this item"

    # Zero security events logged outside lab mode
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bola_vulnerable_mode_exploit_and_detection(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify that with lab mode active and defense OFF, BOLA exploit succeeds and is detected."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    assert defense_manager.get_defenses()["bola"] is False

    # Alice requests Bob's item (Item 3)
    res = client.get(f"/items/{seeded_db['item3'].id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == seeded_db["item3"].id
    assert data["owner_id"] == seeded_db["bob"].id

    # Real security event must be logged with action="detected"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API1:2023"
    assert event.rule_name == "bola_cross_tenant_access"
    assert event.severity == "HIGH"
    assert event.action == "detected"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id == str(seeded_db["item3"].id)
    assert event.endpoint == f"/items/{seeded_db['item3'].id}"
    assert event.method == "GET"


def test_bola_defended_mode_block_and_detection(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify that with lab mode active and defense ON, BOLA exploit is blocked and detected."""
    defense_manager.update_defenses({"bola": True})
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Alice requests Bob's item (Item 3)
    res = client.get(f"/items/{seeded_db['item3'].id}", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "Not authorized to access this item"

    # Real security event must be logged with action="blocked"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API1:2023"
    assert event.rule_name == "bola_cross_tenant_access"
    assert event.severity == "HIGH"
    assert event.action == "blocked"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id == str(seeded_db["item3"].id)


def test_fail_closed_on_event_persistence_failure(
    client: TestClient, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify fail-closed behavior: if event logging fails, access is denied with HTTP 500."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    with patch("detection.bola.log_security_event") as mock_log:
        mock_log.side_effect = SecurityEventPersistenceError("Simulated DB write failure")
        res = client.get(f"/items/{seeded_db['item3'].id}", headers=headers)
        assert res.status_code == 500
        assert res.json()["detail"] == "Security event logging failed; access denied"


def test_admin_lab_mode_endpoint(client: TestClient, seeded_db: dict[str, Any]) -> None:
    """Verify GET /admin/lab-mode endpoint access controls and read-only behavior."""
    admin_headers = {"Authorization": f"Bearer {seeded_db['admin_token']}"}
    alice_headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Admin reads status
    res = client.get("/admin/lab-mode", headers=admin_headers)
    assert res.status_code == 200
    assert "lab_mode" in res.json()
    assert res.json()["lab_mode"] is False

    # Normal user rejected with 403
    res_alice = client.get("/admin/lab-mode", headers=alice_headers)
    assert res_alice.status_code == 403

    # Unauthenticated rejected with 401
    res_unauth = client.get("/admin/lab-mode")
    assert res_unauth.status_code == 401


def test_attack_script_pre_flight_allowlist_validation() -> None:
    """Verify that validate_target_url rejects external hosts, schemes, ports, and malformed URLs."""
    # Valid targets
    assert validate_target_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert validate_target_url("http://localhost:8000") == "http://localhost:8000"
    assert validate_target_url("http://api:8000") == "http://api:8000"

    # Disallowed external host
    with pytest.raises(ValueError, match="Disallowed target host 'example.com'"):
        validate_target_url("http://example.com:8000")

    # Disallowed scheme
    with pytest.raises(ValueError, match="Disallowed scheme 'https'"):
        validate_target_url("https://127.0.0.1:8000")

    # Disallowed port
    with pytest.raises(ValueError, match="Disallowed or missing port '9000'"):
        validate_target_url("http://127.0.0.1:9000")

    # Missing port
    with pytest.raises(ValueError, match="Disallowed or missing port"):
        validate_target_url("http://127.0.0.1")

    # Embedded credentials
    with pytest.raises(ValueError, match="Embedded credentials"):
        validate_target_url("http://alice:secret@127.0.0.1:8000")

    # Query string
    with pytest.raises(ValueError, match="query strings"):
        validate_target_url("http://127.0.0.1:8000/path?key=value")


def test_attack_script_reproduces_both_modes(
    client: TestClient, seeded_db: dict[str, Any], lab_mode_enabled: None, tmp_path: Path
) -> None:
    """Verify attack script runner against TestClient reproducing exploit and defense."""
    custom_results_path = tmp_path / "test_bola_results.json"

    # 1. Run attack with defense OFF
    defense_manager.reset()
    res_off = run_bola_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_off["status_code"] == 200
    assert res_off["attack_success"] is True
    assert res_off["blocked"] is False
    assert res_off["outcome"] == "vulnerability_exploited"
    assert res_off["detection_verified"] is True

    # 2. Run attack with defense ON
    defense_manager.update_defenses({"bola": True})
    res_on = run_bola_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_on["status_code"] == 403
    assert res_on["attack_success"] is False
    assert res_on["blocked"] is True
    assert res_on["outcome"] == "attack_blocked"
    assert res_on["detection_verified"] is True
