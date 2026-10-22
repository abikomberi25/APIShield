import sqlite3
from datetime import timedelta
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from attacks.bopla import main as bopla_main, run_bopla_read_attack, validate_target_url
from backend.auth.security import create_access_token, hash_password
from backend.models.event import SecurityEvent
from backend.models.item import Item
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.events import SecurityEventPersistenceError, log_security_event
from backend.seed import seed_database


@pytest.fixture
def seeded_db(db_session: Session) -> dict[str, Any]:
    """Seed synthetic users (Alice, Bob, Admin) and items with internal properties."""
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

    item1 = Item(
        title="Alice Doc 1",
        description="Private notes",
        owner_id=alice.id,
        internal_notes="Synthetic internal note: risk score 42/100",
        is_confidential=False,
    )
    item2 = Item(
        title="Alice Doc 2",
        description="Private plan",
        owner_id=alice.id,
        internal_notes="Synthetic compliance note: pending audit",
        is_confidential=True,
    )
    item3 = Item(
        title="Bob Doc 1",
        description="Bob Secret",
        owner_id=bob.id,
        internal_notes="Synthetic internal note: budget reserve",
        is_confidential=True,
    )
    db_session.add_all([item1, item2, item3])
    db_session.commit()
    db_session.refresh(item1)
    db_session.refresh(item2)
    db_session.refresh(item3)

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
        "item2": item2,
        "item3": item3,
        "alice_token": alice_token,
        "bob_token": bob_token,
        "admin_token": admin_token,
    }


def test_bopla_read_unauthenticated_rejected(
    client: TestClient, db_session: Session, lab_mode_enabled: None
) -> None:
    """Verify unauthenticated requests with or without include_internal return HTTP 401."""
    # Missing token
    res1 = client.get("/items/1?include_internal=true")
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Not authenticated"

    # Malformed token
    res2 = client.get(
        "/items/1?include_internal=true",
        headers={"Authorization": "Bearer malformed.jwt.token"},
    )
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Could not validate credentials"

    # Expired token
    expired = create_access_token(
        subject="1",
        claims={"username": "alice", "role": "user"},
        expires_delta=timedelta(seconds=-10),
    )
    res3 = client.get(
        "/items/1?include_internal=true",
        headers={"Authorization": f"Bearer {expired}"},
    )
    assert res3.status_code == 401
    assert res3.json()["detail"] == "Token expired"

    # Zero security events logged
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bopla_read_owner_normal_no_events(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify normal owner read (without include_internal) returns sanitized schema with zero events."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    res = client.get(f"/items/{seeded_db['item1'].id}", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Public fields present
    assert data["id"] == seeded_db["item1"].id
    assert data["title"] == "Alice Doc 1"
    assert data["owner_id"] == seeded_db["alice"].id

    # Restricted properties must NOT appear in response
    assert "internal_notes" not in data
    assert "is_confidential" not in data

    # Zero security events logged
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bopla_read_admin_authorized_no_events(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify legitimate admin read with include_internal returns full internal properties with zero events."""
    headers = {"Authorization": f"Bearer {seeded_db['admin_token']}"}
    res = client.get(
        f"/items/{seeded_db['item1'].id}?include_internal=true", headers=headers
    )
    assert res.status_code == 200
    data = res.json()

    # Both public and internal fields present
    assert data["id"] == seeded_db["item1"].id
    assert data["internal_notes"] == "Synthetic internal note: risk score 42/100"
    assert data["is_confidential"] is False

    # Legitimate admin access must never be flagged
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bopla_read_default_safe_mode(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any]
) -> None:
    """Verify outside lab mode, owner requesting include_internal receives sanitized response and 0 events."""
    # Note: lab_mode_enabled fixture NOT used; STARTUP_LAB_MODE is False
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    assert defense_manager.get_defenses()["schema_validation"] is False

    res = client.get(
        f"/items/{seeded_db['item1'].id}?include_internal=true", headers=headers
    )
    assert res.status_code == 200
    data = res.json()

    # Public fields present, restricted properties strictly sanitized
    assert data["id"] == seeded_db["item1"].id
    assert "internal_notes" not in data
    assert "is_confidential" not in data

    # Zero security events logged
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bopla_read_vulnerable_mode(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify in lab mode with schema_validation OFF, unauthorized internal properties are disclosed and logged."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    assert defense_manager.get_defenses()["schema_validation"] is False

    res = client.get(
        f"/items/{seeded_db['item1'].id}?include_internal=true", headers=headers
    )
    assert res.status_code == 200
    data = res.json()

    # Vulnerability demonstrated: internal properties disclosed
    assert data["id"] == seeded_db["item1"].id
    assert data["internal_notes"] == "Synthetic internal note: risk score 42/100"
    assert data["is_confidential"] is False

    # Real security event logged with action="detected"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API3:2023"
    assert event.rule_name == "bopla_excessive_data_exposure"
    assert event.severity == "MEDIUM"
    assert event.action == "detected"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id == str(seeded_db["item1"].id)
    assert event.endpoint == f"/items/{seeded_db['item1'].id}"
    assert event.method == "GET"


def test_bopla_read_defended_mode(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify in lab mode with schema_validation ON, unauthorized internal properties are blocked with HTTP 403."""
    defense_manager.update_defenses({"schema_validation": True})
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    res = client.get(
        f"/items/{seeded_db['item1'].id}?include_internal=true", headers=headers
    )
    assert res.status_code == 403
    data = res.json()
    assert (
        data["detail"]
        == "Unauthorized property access: internal fields restricted to administrators"
    )

    # Restricted properties must never appear in error response
    assert "internal_notes" not in data
    assert "is_confidential" not in data

    # Real security event logged with action="blocked"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API3:2023"
    assert event.rule_name == "bopla_excessive_data_exposure"
    assert event.severity == "MEDIUM"
    assert event.action == "blocked"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id == str(seeded_db["item1"].id)


def test_bopla_defense_on_disclosure_failure(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify that when defense is ON but properties are still disclosed, verification fails."""
    defense_manager.update_defenses({"schema_validation": True})
    custom_results_path = tmp_path / "defense_leak.json"

    # Mock the GET request to simulate a defense bypass bug (return 200 with internal fields)
    original_get = client.get

    def mock_get(url, *args, **kwargs):
        # Only mock the attack request, not the event query
        if url.endswith("/items/1?include_internal=true") and "Authorization" in kwargs.get("headers", {}):
            from httpx import Response
            # Simulate defense failure: return 200 with internal fields
            return Response(
                status_code=200,
                json={
                    "id": seeded_db["item1"].id,
                    "title": "Alice Doc 1",
                    "description": "Private notes",
                    "owner_id": seeded_db["alice"].id,
                    "internal_notes": "Synthetic internal note: risk score 42/100",
                    "is_confidential": False,
                },
            )
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_bopla_read_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    # Should fail verification: attack_success but not blocked
    assert res["status_code"] == 200
    assert res["attack_success"] is True
    assert res["blocked"] is False
    assert res["disclosed_internal_notes"] is True
    assert res["disclosed_is_confidential"] is True
    # Note: detection_verified may be True or False depending on whether the event was logged
    # The key is that verification_passed is False because outcome is not attack_blocked
    assert res["outcome"] != "attack_blocked"
    assert res["verification_passed"] is False
    assert not custom_results_path.exists()


def test_bopla_read_fail_closed_persistence_failure(
    client: TestClient, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify fail-closed behavior: persistence failure returns HTTP 500 without disclosing properties."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    with patch("detection.bopla.log_security_event") as mock_log:
        mock_log.side_effect = SecurityEventPersistenceError(
            "Simulated DB write failure"
        )
        res = client.get(
            f"/items/{seeded_db['item1'].id}?include_internal=true", headers=headers
        )
        assert res.status_code == 500
        data = res.json()
        assert (
            data["detail"] == "Security event logging failed; access denied"
        )
        # Ensure restricted properties are never leaked in fail-closed response
        assert "internal_notes" not in data
        assert "is_confidential" not in data


def test_bopla_read_bola_cross_user_precedence(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify BOLA ownership authorization check takes precedence over BOPLA checks on other users' items."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Alice attempts to read Bob's Item 3 with include_internal=true
    # When bola defense is ON (or default safe mode), BOLA blocks access with 403
    defense_manager.update_defenses({"bola": True, "schema_validation": False})
    res = client.get(
        f"/items/{seeded_db['item3'].id}?include_internal=true", headers=headers
    )
    assert res.status_code == 403
    assert res.json()["detail"] == "Not authorized to access this item"

    # Event logged must be BOLA (API1:2023), NOT BOPLA (API3:2023)
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    assert events[0].owasp_category == "API1:2023"
    assert events[0].rule_name == "bola_cross_tenant_access"


def test_bopla_attack_script_allowlist_validation() -> None:
    """Verify validate_target_url rejects external hosts, disallowed ports, schemes, credentials, query strings."""
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


def test_bopla_attack_script_reproduces_both_modes(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify attack script runner reproduces both vulnerability exploit and defense block."""
    custom_results_path = tmp_path / "test_bopla_read_results.json"

    # 1. Run attack with defense OFF
    defense_manager.reset()
    res_off = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_off["status_code"] == 200
    assert res_off["attack_success"] is True
    assert res_off["blocked"] is False
    assert res_off["disclosed_internal_notes"] is True
    assert res_off["outcome"] == "vulnerability_exploited"
    assert res_off["detection_verified"] is True
    assert res_off["verification_passed"] is True
    assert isinstance(res_off["matched_event_id"], int)

    # 2. Run attack with defense ON
    defense_manager.update_defenses({"schema_validation": True})
    res_on = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_on["status_code"] == 403
    assert res_on["attack_success"] is False
    assert res_on["blocked"] is True
    assert res_on["disclosed_internal_notes"] is False
    assert res_on["outcome"] == "attack_blocked"
    assert res_on["detection_verified"] is True
    assert res_on["verification_passed"] is True
    assert isinstance(res_on["matched_event_id"], int)


def test_bopla_attack_event_correlation_ignores_past_events(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify event correlation ignores events generated prior to the attack run."""
    custom_results_path = tmp_path / "test_bopla_correlation_results.json"

    # Seed an old event from a prior run
    log_security_event(
        db=db_session,
        endpoint="/items/1",
        method="GET",
        owasp_category="API3:2023",
        severity="MEDIUM",
        rule_name="bopla_excessive_data_exposure",
        action="detected",
        user_id=seeded_db["alice"].id,
        object_id=str(seeded_db["item1"].id),
    )

    # Now enable defense and run attack
    defense_manager.update_defenses({"schema_validation": True})
    res = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )

    # Must verify the newly generated 'blocked' event, not the pre-existing 'detected' event
    assert res["status_code"] == 403
    assert res["detection_verified"] is True
    assert res["matched_event_id"] is not None
    assert res["matched_event_id"] > 1


def test_bopla_attack_event_correlation_rejects_unrelated_events(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify event correlation rejects events with mismatched fields even if they occur after the baseline."""
    custom_results_path = tmp_path / "test_bopla_unrelated_correlation.json"

    defense_manager.update_defenses({"schema_validation": True})

    # Mock the event query to return an unrelated event (different endpoint)
    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if "/admin/events?limit=20" in url:
            from httpx import Response
            # Return an event with correct category/rule but wrong endpoint
            return Response(
                status_code=200,
                json={
                    "events": [
                        {
                            "id": 999,
                            "timestamp": "2026-10-14T00:00:00+00:00",
                            "owasp_category": "API3:2023",
                            "rule_name": "bopla_excessive_data_exposure",
                            "endpoint": "/items/999",  # Wrong endpoint
                            "method": "GET",
                            "user_id": seeded_db["alice"].id,
                            "object_id": "999",
                            "action": "blocked",
                        }
                    ],
                    "total": 1,
                },
            )
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_bopla_read_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    # Should reject the unrelated event
    assert res["status_code"] == 403
    assert res["detection_verified"] is False
    assert res["matched_event_id"] is None
    assert res["outcome"] == "unverified_detection"
    assert not custom_results_path.exists()


def test_seed_database_fresh_initialization(tmp_path: Path) -> None:
    """Verify that a fresh database is initialized with correct users, items, and internal properties."""
    db_file = tmp_path / "fresh_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db, target_engine=engine)

        users = db.query(User).all()
        assert len(users) == 3
        items = db.query(Item).all()
        assert len(items) == 4

        item1 = db.query(Item).filter(Item.title == "Alice Private Document").first()
        item2 = db.query(Item).filter(Item.title == "Alice Project Plan").first()
        assert item1 is not None
        assert item2 is not None
        assert item1.internal_notes == "Internal audit: synthetic risk score 42/100"
        assert item1.is_confidential is False
        assert item2.internal_notes == "Internal compliance: pending security review"
        assert item2.is_confidential is True
    finally:
        db.close()
        engine.dispose()


def test_seed_database_preserves_customized_internal_properties(tmp_path: Path) -> None:
    """Verify that rerunning seed_database does not overwrite customized internal_notes or is_confidential."""
    db_file = tmp_path / "preserve_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db, target_engine=engine)

        item1 = db.query(Item).filter(Item.title == "Alice Private Document").first()
        item2 = db.query(Item).filter(Item.title == "Alice Project Plan").first()
        assert item1 is not None and item2 is not None

        # Customize both items: flip boolean values and customize notes
        item1.is_confidential = True  # flipped from default False to True
        item1.internal_notes = "Customized audit note for Item 1"
        item2.is_confidential = False  # flipped from default True to False
        item2.internal_notes = "Customized compliance note for Item 2"
        db.commit()

        # Re-run seed_database
        seed_database(db, target_engine=engine)
        db.expire_all()

        reloaded_item1 = db.query(Item).filter(Item.title == "Alice Private Document").first()
        reloaded_item2 = db.query(Item).filter(Item.title == "Alice Project Plan").first()
        assert reloaded_item1 is not None and reloaded_item2 is not None

        # Verify customized values were preserved and not clobbered
        assert reloaded_item1.is_confidential is True, "is_confidential was clobbered by seed!"
        assert reloaded_item1.internal_notes == "Customized audit note for Item 1", "internal_notes clobbered!"
        assert reloaded_item2.is_confidential is False, "is_confidential was clobbered by seed!"
        assert reloaded_item2.internal_notes == "Customized compliance note for Item 2", "internal_notes clobbered!"
    finally:
        db.close()
        engine.dispose()


def test_seed_database_repeated_seeding_idempotence(tmp_path: Path) -> None:
    """Verify that multiple consecutive seed executions produce no errors, duplicates, or value drift."""
    db_file = tmp_path / "idempotence_test.db"
    engine = create_engine(f"sqlite:///{db_file}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        # Initial seed
        seed_database(db, target_engine=engine)

        # Customize an item
        item = db.query(Item).filter(Item.title == "Bob Strategy Memo").first()
        assert item is not None
        item.is_confidential = True  # seed default is False
        item.internal_notes = "Custom strategy notes"
        db.commit()

        # Run 3 consecutive seed cycles
        for _ in range(3):
            seed_database(db, target_engine=engine)

        db.expire_all()
        assert db.query(User).count() == 3
        assert db.query(Item).count() == 4

        reloaded = db.query(Item).filter(Item.title == "Bob Strategy Memo").first()
        assert reloaded is not None
        assert reloaded.is_confidential is True
        assert reloaded.internal_notes == "Custom strategy notes"
    finally:
        db.close()
        engine.dispose()


def test_seed_database_legacy_schema_migration_and_backfill(tmp_path: Path) -> None:
    """Verify safe migration and backfill from original pre-M4-B schema without data loss or clobbering.

    Preserves existing users, items, ownership relationships, and security audit events.
    """
    db_file = tmp_path / "legacy_test.db"

    # Step 1: Create a genuine legacy database using raw SQLite DDL matching M1-M4-A schema
    # (Notice: no internal_notes and no is_confidential columns on items table)
    conn = sqlite3.connect(str(db_file))
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    """)
    conn.execute("""
        CREATE TABLE security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            user_id INTEGER,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            object_id TEXT,
            owasp_category TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            action TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Populate legacy users
    conn.execute("INSERT INTO users (id, username, hashed_password, role) VALUES (1, 'alice', 'hash_alice', 'user')")
    conn.execute("INSERT INTO users (id, username, hashed_password, role) VALUES (2, 'bob', 'hash_bob', 'user')")

    # Populate legacy items
    conn.execute("INSERT INTO items (id, title, description, owner_id) VALUES (1, 'Alice Private Document', 'Notes', 1)")
    conn.execute("INSERT INTO items (id, title, description, owner_id) VALUES (2, 'Alice Project Plan', 'Plan', 1)")
    conn.execute("INSERT INTO items (id, title, description, owner_id) VALUES (10, 'Custom Legacy Item', 'Non-seed', 1)")

    # Populate legacy audit security events from previous milestones
    conn.execute("""
        INSERT INTO security_events (id, timestamp, user_id, endpoint, method, object_id, owasp_category, severity, rule_name, action)
        VALUES (101, '2026-10-01 12:00:00', 1, '/items/2', 'GET', '2', 'API1:2023', 'HIGH', 'bola_cross_tenant_access', 'detected')
    """)
    conn.execute("""
        INSERT INTO security_events (id, timestamp, user_id, endpoint, method, object_id, owasp_category, severity, rule_name, action)
        VALUES (102, '2026-10-02 14:00:00', 2, '/admin/events', 'GET', NULL, 'API5:2023', 'HIGH', 'bfla_unauthorized_function_access', 'blocked')
    """)
    conn.commit()
    conn.close()

    # Step 2: Run seed_database against the legacy database
    engine = create_engine(f"sqlite:///{db_file}")
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db, target_engine=engine)

        # Verify existing users preserved
        alice = db.query(User).filter(User.username == "alice").first()
        bob = db.query(User).filter(User.username == "bob").first()
        admin = db.query(User).filter(User.username == "admin").first()
        assert alice is not None and alice.id == 1 and alice.hashed_password == "hash_alice"
        assert bob is not None and bob.id == 2 and bob.hashed_password == "hash_bob"
        assert admin is not None and admin.role == "admin"

        # Verify existing security events 100% preserved
        events = db.query(SecurityEvent).all()
        assert len(events) == 2
        assert events[0].id == 101 and events[0].rule_name == "bola_cross_tenant_access"
        assert events[1].id == 102 and events[1].rule_name == "bfla_unauthorized_function_access"

        # Verify items and ownership relationships preserved
        item1 = db.query(Item).filter(Item.id == 1).first()
        item2 = db.query(Item).filter(Item.id == 2).first()
        item10 = db.query(Item).filter(Item.id == 10).first()

        assert item1 is not None and item1.owner_id == alice.id
        assert item2 is not None and item2.owner_id == alice.id
        assert item10 is not None and item10.owner_id == alice.id

        # Backfilled seed properties
        assert item1.internal_notes == "Internal audit: synthetic risk score 42/100"
        assert item1.is_confidential is False
        assert item2.internal_notes == "Internal compliance: pending security review"
        assert item2.is_confidential is True

        # Non-seed item safely defaulted without error
        assert item10.is_confidential is False
        assert item10.internal_notes is None

        # Step 3: Customize properties on migrated items (including custom False)
        item1.is_confidential = True
        item1.internal_notes = "Updated after migration"
        item2.is_confidential = False  # Custom False: must survive repeated seeding!
        db.commit()

        # Step 4: Re-run seed on migrated database repeatedly (idempotence verification)
        for _ in range(2):
            seed_database(db, target_engine=engine)
        db.expire_all()

        reloaded_item1 = db.query(Item).filter(Item.id == 1).first()
        reloaded_item2 = db.query(Item).filter(Item.id == 2).first()
        assert reloaded_item1 is not None
        assert reloaded_item1.is_confidential is True
        assert reloaded_item1.internal_notes == "Updated after migration"
        assert reloaded_item2 is not None
        assert reloaded_item2.is_confidential is False, "Custom False was clobbered by seed!"

        # Re-verify events and users remained untouched
        assert db.query(SecurityEvent).count() == 2
        assert db.query(User).count() == 3
    finally:
        db.close()
        engine.dispose()


def test_run_bopla_read_attack_unverified_detection_when_vulnerable_events_do_not_match(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_bopla_read_attack sets outcome='unverified_detection' and does not write results file when vulnerable detection cannot be verified."""
    custom_results_path = tmp_path / "unverified_vulnerable.json"
    defense_manager.reset()

    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if "/admin/events?limit=20" in url:
            from httpx import Response
            return Response(status_code=200, json={"events": [], "total": 0})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_bopla_read_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    assert res["status_code"] == 200
    assert res["attack_success"] is True
    assert res["detection_verified"] is False
    assert res["matched_event_id"] is None
    assert res["outcome"] == "unverified_detection"
    assert not custom_results_path.exists()


def test_run_bopla_read_attack_unverified_detection_when_blocked_events_do_not_match(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_bopla_read_attack sets outcome='unverified_detection' and does not write results file when blocked detection cannot be verified."""
    custom_results_path = tmp_path / "unverified_defended.json"
    defense_manager.update_defenses({"schema_validation": True})

    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if "/admin/events?limit=20" in url:
            from httpx import Response
            return Response(status_code=200, json={"events": [], "total": 0})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_bopla_read_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    assert res["status_code"] == 403
    assert res["blocked"] is True
    assert res["detection_verified"] is False
    assert res["matched_event_id"] is None
    assert res["outcome"] == "unverified_detection"
    assert not custom_results_path.exists()


def test_run_bopla_read_attack_unexpected_outcome_on_unexpected_status(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_bopla_read_attack sets outcome='unexpected' and does not write results file on unexpected HTTP status."""
    custom_results_path = tmp_path / "unexpected_bopla.json"
    defense_manager.reset()

    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if url.endswith("/items/1?include_internal=true") and "Authorization" in kwargs.get("headers", {}):
            from httpx import Response
            return Response(status_code=502, json={"detail": "Bad Gateway"})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_bopla_read_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    assert res["status_code"] == 502
    assert res["attack_success"] is False
    assert res["blocked"] is False
    assert res["detection_verified"] is False
    assert res["outcome"] == "unexpected"
    assert not custom_results_path.exists()


def test_run_bopla_read_attack_verified_outcomes_persist_result_file(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_bopla_read_attack persists result file only when outcome is verified."""
    vuln_path = tmp_path / "verified_vulnerable.json"
    defense_manager.reset()

    res_off = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=vuln_path,
        client=client,
    )
    assert res_off["status_code"] == 200
    assert res_off["attack_success"] is True
    assert res_off["outcome"] == "vulnerability_exploited"
    assert res_off["detection_verified"] is True
    assert res_off["verification_passed"] is True
    assert vuln_path.exists()
    saved_off = json.loads(vuln_path.read_text(encoding="utf-8"))
    assert saved_off["outcome"] == "vulnerability_exploited"
    assert saved_off["status_code"] == 200
    assert saved_off["verification_passed"] is True

    defended_path = tmp_path / "verified_defended.json"
    defense_manager.update_defenses({"schema_validation": True})

    res_on = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=defended_path,
        client=client,
    )
    assert res_on["status_code"] == 403
    assert res_on["blocked"] is True
    assert res_on["outcome"] == "attack_blocked"
    assert res_on["detection_verified"] is True
    assert res_on["verification_passed"] is True
    assert defended_path.exists()
    saved_on = json.loads(defended_path.read_text(encoding="utf-8"))
    assert saved_on["outcome"] == "attack_blocked"
    assert saved_on["status_code"] == 403
    assert saved_on["verification_passed"] is True


def test_run_bopla_read_attack_results_path_false_suppresses_persistence(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify run_bopla_read_attack with results_path=False suppresses writing to default result file."""
    defense_manager.reset()
    default_artifact = (
        Path(__file__).resolve().parent.parent
        / "docs"
        / "results"
        / "bopla_read_results.json"
    )
    orig_bytes = default_artifact.read_bytes() if default_artifact.exists() else None

    res = run_bopla_read_attack(
        target_url="http://127.0.0.1:8000",
        results_path=False,
        client=client,
    )
    assert res["status_code"] == 200
    assert res["outcome"] == "vulnerability_exploited"
    assert res["detection_verified"] is True

    # Artifact must remain completely unchanged
    if orig_bytes is not None:
        assert default_artifact.read_bytes() == orig_bytes


# ---------------------------------------------------------------------------
# Dual-run orchestration tests (bopla_main)
# ---------------------------------------------------------------------------


def test_main_orchestration_success_both_modes(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() writes combined results after both runs succeed."""
    results_file = tmp_path / "combined_bopla_results.json"
    defense_manager.reset()

    bopla_main(
        target_url="http://127.0.0.1:8000",
        results_path=results_file,
        client=client,
        raise_on_failure=True,
    )

    assert results_file.exists()
    data = json.loads(results_file.read_text(encoding="utf-8"))

    # Top-level fields present
    assert data["experiment"] == "OWASP API3:2023 BOPLA Excessive Data Exposure"
    assert data["attacker"] == "alice"
    # disclosed_internal_notes is a boolean flag (key is fine), but literal note text must not appear
    raw = results_file.read_text(encoding="utf-8")
    assert "synthetic risk score" not in raw
    assert "pending security review" not in raw

    # Vulnerable run assertions
    vr = data["vulnerable_run"]
    assert vr["status_code"] == 200
    assert vr["attack_success"] is True
    assert vr["blocked"] is False
    assert vr["detection_verified"] is True
    assert vr["outcome"] == "vulnerability_exploited"
    assert isinstance(vr["matched_event_id"], int)

    # Defended run assertions
    dr = data["defended_run"]
    assert dr["status_code"] == 403
    assert dr["attack_success"] is False
    assert dr["blocked"] is True
    assert dr["detection_verified"] is True
    assert dr["outcome"] == "attack_blocked"
    assert isinstance(dr["matched_event_id"], int)

    # Defense restored to original (False) after both runs
    assert defense_manager.get_defenses()["schema_validation"] is False


def test_main_orchestration_restores_original_toggle_off(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() restores schema_validation=False (original) after both runs."""
    results_file = tmp_path / "combined_bopla_off.json"
    defense_manager.reset()  # schema_validation starts at False

    bopla_main(
        target_url="http://127.0.0.1:8000",
        results_path=results_file,
        client=client,
        raise_on_failure=True,
    )

    # Must be restored to its original False state
    assert defense_manager.get_defenses()["schema_validation"] is False


def test_main_orchestration_restores_original_toggle_on(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() restores schema_validation=True (original) after both runs."""
    results_file = tmp_path / "combined_bopla_on.json"
    defense_manager.update_defenses({"schema_validation": True})

    bopla_main(
        target_url="http://127.0.0.1:8000",
        results_path=results_file,
        client=client,
        raise_on_failure=True,
    )

    # Must be restored to its original True state
    assert defense_manager.get_defenses()["schema_validation"] is True


def test_main_lab_mode_disabled_aborts_experiment(
    client: TestClient,
    seeded_db: dict[str, Any],
    tmp_path: Path,
) -> None:
    """Verify bopla_main() aborts without any experiment if lab mode is disabled."""
    results_file = tmp_path / "lab_mode_disabled.json"
    defense_manager.reset()

    # lab_mode_enabled fixture NOT used; APISHIELD_LAB_MODE is False
    with pytest.raises(RuntimeError, match="Lab mode is not enabled"):
        bopla_main(
            target_url="http://127.0.0.1:8000",
            results_path=results_file,
            client=client,
            raise_on_failure=True,
        )

    assert not results_file.exists()


def test_main_allowlist_rejection_before_network(
    tmp_path: Path,
) -> None:
    """Verify bopla_main() rejects disallowed targets before any network activity."""
    results_file = tmp_path / "allowlist_rejected.json"

    with pytest.raises(ValueError, match="Disallowed target host"):
        bopla_main(
            target_url="http://evil.example.com:8000",
            results_path=results_file,
            raise_on_failure=True,
        )

    assert not results_file.exists()


def test_main_vulnerable_run_unverified_no_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() aborts without writing results if vulnerable run is unverified."""
    results_file = tmp_path / "unverified_vuln.json"
    defense_manager.reset()

    mock_run_result = {
        "status_code": 200,
        "attack_success": True,
        "blocked": False,
        "outcome": "unverified_detection",
        "detection_verified": False,
        "verification_passed": False,
        "defense_active": False,
        "matched_event_id": None,
        "disclosed_internal_notes": True,
        "disclosed_is_confidential": False,
        "target_item_id": 1,
        "target": "http://127.0.0.1:8000",
        "timestamp": "2026-10-14T00:00:00+00:00",
        "experiment": "OWASP API3:2023 BOPLA Excessive Data Exposure",
        "attacker": "alice",
    }

    with patch("attacks.bopla.run_bopla_read_attack", return_value=mock_run_result):
        with pytest.raises(RuntimeError, match="Run 1.*failed verification.*verification_passed"):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    assert not results_file.exists()


def test_main_defended_run_unverified_no_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() aborts without writing results if defended run is unverified."""
    results_file = tmp_path / "unverified_def.json"
    defense_manager.reset()

    call_count = 0

    def mock_run(target_url, results_path, client):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Run 1 succeeds
            return {
                "status_code": 200,
                "attack_success": True,
                "blocked": False,
                "outcome": "vulnerability_exploited",
                "detection_verified": True,
                "verification_passed": True,
                "defense_active": False,
                "matched_event_id": 1,
                "disclosed_internal_notes": True,
                "disclosed_is_confidential": False,
                "target_item_id": 1,
                "target": "http://127.0.0.1:8000",
                "timestamp": "2026-10-14T00:00:00+00:00",
                "experiment": "OWASP API3:2023 BOPLA Excessive Data Exposure",
                "attacker": "alice",
            }
        # Run 2 unverified
        return {
            "status_code": 403,
            "attack_success": False,
            "blocked": True,
            "outcome": "unverified_detection",
            "detection_verified": False,
            "verification_passed": False,
            "defense_active": True,
            "matched_event_id": None,
            "disclosed_internal_notes": False,
            "disclosed_is_confidential": False,
            "target_item_id": 1,
            "target": "http://127.0.0.1:8000",
            "timestamp": "2026-10-14T00:00:00+00:00",
            "experiment": "OWASP API3:2023 BOPLA Excessive Data Exposure",
            "attacker": "alice",
        }

    with patch("attacks.bopla.run_bopla_read_attack", side_effect=mock_run):
        with pytest.raises(RuntimeError, match="Run 2.*failed verification"):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    assert not results_file.exists()


def test_main_toggle_patch_failure_aborts(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() aborts with RuntimeError if toggle PATCH fails."""
    results_file = tmp_path / "patch_fail.json"
    defense_manager.reset()

    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        json_body = kwargs.get("json", {})
        # Fail only when setting schema_validation=False (Run 1)
        if "/admin/defenses" in url and json_body.get("schema_validation") is False:
            from httpx import Response
            return Response(status_code=500, json={"detail": "Simulated patch failure"})
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        with pytest.raises(
            RuntimeError,
            match="Failed to set schema_validation defense toggle to OFF",
        ):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    assert not results_file.exists()


def test_main_restoration_failure_warns_no_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Verify bopla_main() warns on stderr and does not write combined report if restoration fails."""
    results_file = tmp_path / "restore_fail.json"
    defense_manager.reset()

    patch_count = 0
    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        nonlocal patch_count
        if "/admin/defenses" in url:
            patch_count += 1
            # 3rd PATCH is the restoration — make it fail
            if patch_count == 3:
                from httpx import Response
                return Response(status_code=500, json={"detail": "Simulated restore failure"})
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        with pytest.raises(SystemExit):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=False,
            )

    captured = capsys.readouterr()
    assert (
        "The server's BOPLA schema_validation defense state may be unresolved."
        in captured.err
    )
    assert not results_file.exists()


def test_main_restoration_mismatch_warns_no_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Verify bopla_main() warns if restoration PATCH returns mismatched schema_validation and does not write results."""
    results_file = tmp_path / "restore_mismatch.json"
    defense_manager.reset()  # original = False

    patch_count = 0
    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        nonlocal patch_count
        if "/admin/defenses" in url:
            patch_count += 1
            # 3rd PATCH: restore returns 200 but wrong schema_validation value
            if patch_count == 3:
                from httpx import Response
                return Response(
                    status_code=200,
                    json={
                        "message": "Defenses updated successfully",
                        "defenses": {"schema_validation": True},
                    },
                )
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        with pytest.raises(SystemExit):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=False,
            )

    captured = capsys.readouterr()
    assert (
        "The server's BOPLA schema_validation defense state may be unresolved."
        in captured.err
    )
    assert "schema_validation=True, expected=False" in captured.err
    assert not results_file.exists()


def test_main_no_credentials_or_restricted_values_in_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify combined report never contains passwords, JWTs, Authorization headers, or internal_notes text."""
    results_file = tmp_path / "no_creds.json"
    defense_manager.reset()

    bopla_main(
        target_url="http://127.0.0.1:8000",
        results_path=results_file,
        client=client,
        raise_on_failure=True,
    )

    assert results_file.exists()
    raw = results_file.read_text(encoding="utf-8")

    # Credential and token material must not appear
    assert "AliceSyntheticPass123!" not in raw
    assert "AdminSyntheticPass123!" not in raw
    assert "Authorization" not in raw
    assert "Bearer " not in raw
    assert "access_token" not in raw

    # Literal internal_notes values must not be stored (only boolean flags)
    assert "synthetic risk score" not in raw
    assert "pending security review" not in raw


# ---------------------------------------------------------------------------
# Gap-closure tests: orchestration edge cases identified in security review
# ---------------------------------------------------------------------------


def test_main_attack_exception_restores_original_defense_state(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() restores original schema_validation when run_bopla_read_attack raises.

    Gap covered: attack exception during the vulnerable run triggers the inner finally block,
    which must attempt restoration before propagating the original exception.
    """
    results_file = tmp_path / "attack_exc.json"
    # Start with original = True so a state change is visible if restoration is skipped
    defense_manager.update_defenses({"schema_validation": True})

    with patch(
        "attacks.bopla.run_bopla_read_attack",
        side_effect=RuntimeError("Simulated attack error"),
    ):
        with pytest.raises(RuntimeError, match="Simulated attack error"):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    # Original schema_validation=True must be restored by the inner finally
    assert defense_manager.get_defenses()["schema_validation"] is True
    # Combined report must not be written
    assert not results_file.exists()


def test_main_second_toggle_patch_failure_aborts_and_restoration_attempted(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify bopla_main() aborts when the Run-2 toggle PATCH (schema_validation=True) fails.

    Gap covered: only the Run-1 toggle failure was previously tested. This exercises the
    symmetric failure path for the Run-2 toggle PATCH, and confirms that the inner finally
    still attempts restoration (PATCH #3) even though PATCH #2 failed.
    """
    results_file = tmp_path / "patch_on_fail.json"
    defense_manager.reset()  # original schema_validation = False

    patch_count = 0
    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        nonlocal patch_count
        if "/admin/defenses" in url:
            patch_count += 1
            # PATCH #1: set schema_validation=False for Run 1  → real call, succeeds
            # PATCH #2: set schema_validation=True for Run 2   → intercepted, fails 500
            # PATCH #3: restore to original                     → real call, succeeds
            if patch_count == 2:
                from httpx import Response
                return Response(
                    status_code=500,
                    json={"detail": "Simulated Run-2 toggle failure"},
                )
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        with pytest.raises(
            RuntimeError,
            match="Failed to set schema_validation defense toggle to ON",
        ):
            bopla_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    # PATCH #3 (restoration) must have been attempted: total PATCH calls == 3
    assert patch_count == 3, (
        f"Expected 3 PATCH calls (set-OFF, set-ON-fail, restore), got {patch_count}"
    )
    # Combined report must not be written
    assert not results_file.exists()
    # Defense restored to original (False) by PATCH #3
    assert defense_manager.get_defenses()["schema_validation"] is False


def test_main_results_path_false_suppresses_combined_report(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify bopla_main() does not write the combined report when results_path=False.

    Gap covered: results_path=False is supported by run_bopla_read_attack() (tested separately),
    but was not verified for the dual-run bopla_main() orchestrator. This test confirms that
    passing False skips the combined write even after both runs are fully verified.
    """
    defense_manager.reset()

    # Record the current state of the default artifact so we can confirm it is unchanged
    default_artifact = (
        Path(__file__).resolve().parent.parent
        / "docs"
        / "results"
        / "bopla_read_results.json"
    )
    orig_bytes = default_artifact.read_bytes() if default_artifact.exists() else None

    bopla_main(
        target_url="http://127.0.0.1:8000",
        results_path=False,
        client=client,
        raise_on_failure=True,
    )

    # Default artifact must remain completely unchanged
    if orig_bytes is not None:
        assert default_artifact.read_bytes() == orig_bytes
    else:
        assert not default_artifact.exists()
