"""Tests for OWASP API2:2023 Broken Authentication — lockout defense and attack script."""

from typing import Any
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from attacks.auth import main as auth_main, run_auth_attack, validate_target_url
from backend.auth.security import hash_password
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.lockout import LoginAttemptTracker, login_tracker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_db(db_session: Session) -> dict[str, Any]:
    """Seed synthetic users for auth hardening tests."""
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
    return {"alice": alice, "bob": bob, "admin": admin}


# ---------------------------------------------------------------------------
# LoginAttemptTracker unit tests
# ---------------------------------------------------------------------------


def test_tracker_no_lockout_initially() -> None:
    """Fresh tracker: no user is locked out."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    assert not tracker.is_locked_out("alice")


def test_tracker_lockout_after_threshold() -> None:
    """After max_attempts failures, is_locked_out returns True."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure("alice")
    assert tracker.is_locked_out("alice")


def test_tracker_success_clears_lockout() -> None:
    """record_success() clears failure counter and active lockout."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure("alice")
    assert tracker.is_locked_out("alice")
    tracker.record_success("alice")
    assert not tracker.is_locked_out("alice")


def test_tracker_user_isolation() -> None:
    """Alice locked does not affect Bob."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure("alice")
    assert tracker.is_locked_out("alice")
    assert not tracker.is_locked_out("bob")


def test_tracker_reset_user() -> None:
    """reset_user() clears state for that user only."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure("alice")
    tracker.record_failure("bob")
    tracker.reset_user("alice")
    assert not tracker.is_locked_out("alice")
    # bob's state is unaffected
    assert not tracker.is_locked_out("bob")


def test_tracker_reset_all() -> None:
    """reset_all() clears all state."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure("alice")
    tracker.reset_all()
    assert not tracker.is_locked_out("alice")


def test_tracker_lockout_remaining_nonzero_when_locked() -> None:
    """get_lockout_remaining returns positive seconds when locked."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=300)
    for _ in range(3):
        tracker.record_failure("alice")
    remaining = tracker.get_lockout_remaining("alice")
    assert remaining is not None and remaining > 0


def test_tracker_lockout_remaining_zero_when_not_locked() -> None:
    """get_lockout_remaining returns None when not locked."""
    tracker = LoginAttemptTracker(max_attempts=3, window_seconds=60, lockout_seconds=60)
    assert tracker.get_lockout_remaining("alice") is None


# ---------------------------------------------------------------------------
# Integration tests: login endpoint behavior
# ---------------------------------------------------------------------------


def test_login_success_outside_lab_no_event(
    client: TestClient,
    seeded_db: dict[str, Any],
) -> None:
    """Valid login outside lab mode: succeeds, no security events, no lockout."""
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["username"] == "alice"


def test_login_failure_outside_lab_returns_401(
    client: TestClient,
    seeded_db: dict[str, Any],
) -> None:
    """Failed login outside lab mode: 401, no lockout enforced regardless of attempts."""
    for _ in range(7):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "WrongPassword"},
        )
        assert resp.status_code == 401
    # Correct login still works outside lab mode (defense OFF, not in lab)
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 200


def test_login_failure_lab_defense_off_emits_detected_event(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    db_session: Session,
) -> None:
    """Failed login with auth_hardening OFF in lab mode: 401 + detected event, no lockout enforced."""
    from backend.models.event import SecurityEvent

    defense_manager.update_defenses({"auth_hardening": False})

    # Fire enough failures to exceed the tracker threshold
    for _ in range(6):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "WrongPassword"},
        )
        assert resp.status_code == 401

    # Account not locked even after threshold exceeded (defense OFF = monitor-only)
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 200

    # Security event must have been emitted
    events = db_session.query(SecurityEvent).filter(
        SecurityEvent.owasp_category == "API2:2023",
        SecurityEvent.rule_name == "auth_brute_force",
        SecurityEvent.action == "detected",
    ).all()
    assert len(events) >= 1


def test_login_lockout_defense_on_lab_mode(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    db_session: Session,
) -> None:
    """With auth_hardening ON in lab mode: lockout enforced after 5 failures → HTTP 429."""
    from backend.models.event import SecurityEvent

    defense_manager.update_defenses({"auth_hardening": True})
    login_tracker.reset_all()

    # 5 failures hit the lockout threshold
    for i in range(5):
        resp = client.post(
            "/auth/login",
            json={"username": "alice", "password": "WrongPassword"},
        )
        assert resp.status_code == 401, f"Expected 401 on attempt {i+1}"

    # 6th attempt: account now locked → 429
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "WrongPassword"},
    )
    assert resp.status_code == 429
    assert "locked" in resp.json()["detail"].lower()
    assert "Retry-After" in resp.headers

    # Correct password also gets 429 while locked
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 429

    # At least one blocked event emitted
    events = db_session.query(SecurityEvent).filter(
        SecurityEvent.owasp_category == "API2:2023",
        SecurityEvent.rule_name == "auth_brute_force",
        SecurityEvent.action == "blocked",
    ).all()
    assert len(events) >= 1


def test_login_bob_not_affected_by_alice_lockout(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Alice's lockout does not affect Bob."""
    defense_manager.update_defenses({"auth_hardening": True})
    login_tracker.reset_all()

    # Lock alice
    for _ in range(5):
        client.post("/auth/login", json={"username": "alice", "password": "WrongPassword"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "WrongPassword"})
    assert resp.status_code == 429

    # Bob can still log in
    resp = client.post(
        "/auth/login",
        json={"username": "bob", "password": "BobSyntheticPass123!"},
    )
    assert resp.status_code == 200


def test_login_success_resets_failure_counter(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Successful login clears failure counter so subsequent failures start fresh."""
    defense_manager.update_defenses({"auth_hardening": True})
    login_tracker.reset_all()

    # 4 failures (one below threshold)
    for _ in range(4):
        client.post("/auth/login", json={"username": "alice", "password": "WrongPassword"})

    # Successful login clears counter
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 200

    # 4 more failures after reset — should not lock yet
    for _ in range(4):
        resp = client.post("/auth/login", json={"username": "alice", "password": "WrongPassword"})
        assert resp.status_code == 401

    # Still accessible
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    assert resp.status_code == 200


def test_no_credentials_in_security_events(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    db_session: Session,
) -> None:
    """Security events must not contain passwords, tokens, or Authorization headers."""
    from backend.models.event import SecurityEvent
    import json as _json

    defense_manager.update_defenses({"auth_hardening": False})
    client.post("/auth/login", json={"username": "alice", "password": "WrongPassword"})

    events = db_session.query(SecurityEvent).filter(
        SecurityEvent.owasp_category == "API2:2023"
    ).all()
    for ev in events:
        ev_str = _json.dumps({
            "endpoint": ev.endpoint,
            "rule_name": ev.rule_name,
            "object_id": ev.object_id,
        })
        assert "WrongPassword" not in ev_str
        assert "AliceSyntheticPass123" not in ev_str
        assert "Bearer " not in ev_str
        assert "Authorization" not in ev_str


# ---------------------------------------------------------------------------
# Attack script tests
# ---------------------------------------------------------------------------


def test_auth_attack_allowlist_validation() -> None:
    """Attack script rejects disallowed targets before any network activity."""
    with pytest.raises(ValueError, match="Disallowed host"):
        validate_target_url("http://evil.example.com:8000")

    with pytest.raises(ValueError, match="Disallowed port"):
        validate_target_url("http://127.0.0.1:9999")

    with pytest.raises(ValueError, match="Disallowed scheme"):
        validate_target_url("https://127.0.0.1:8000")


def test_auth_attack_vulnerable_run(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path,
) -> None:
    """run_auth_attack() with defense OFF: all attempts 401, account accessible, detected event."""
    defense_manager.update_defenses({"auth_hardening": False})
    login_tracker.reset_all()

    result = run_auth_attack(
        target_url="http://127.0.0.1:8000",
        attempt_count=6,
        results_path=False,
        client=client,
    )
    assert result["outcome"] == "vulnerability_exploited"
    assert result["failed_401"] == 6
    assert result["account_accessible_after_attempts"] is True
    assert result["detection_verified"] is True


def test_auth_attack_defended_run(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path,
) -> None:
    """run_auth_attack() with defense ON: lockout triggered, account locked, blocked event."""
    defense_manager.update_defenses({"auth_hardening": True})
    login_tracker.reset_all()

    result = run_auth_attack(
        target_url="http://127.0.0.1:8000",
        attempt_count=7,
        results_path=False,
        client=client,
    )
    assert result["outcome"] == "attack_blocked"
    assert result["failed_429"] > 0
    assert result["account_locked_after_attempts"] is True
    assert result["detection_verified"] is True


def test_auth_attack_results_path_false_suppresses_file(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path,
) -> None:
    """results_path=False suppresses file write even on verified outcome."""
    defense_manager.update_defenses({"auth_hardening": False})
    login_tracker.reset_all()

    results_file = tmp_path / "should_not_exist.json"
    run_auth_attack(
        target_url="http://127.0.0.1:8000",
        attempt_count=6,
        results_path=False,
        client=client,
    )
    assert not results_file.exists()


def test_auth_main_allowlist_rejection_before_network(tmp_path) -> None:
    """auth_main() rejects disallowed target before any network call."""
    results_file = tmp_path / "allowlist_rejected.json"
    with pytest.raises(ValueError, match="Disallowed host"):
        auth_main(
            target_url="http://evil.example.com:8000",
            results_path=results_file,
            raise_on_failure=True,
        )
    assert not results_file.exists()
