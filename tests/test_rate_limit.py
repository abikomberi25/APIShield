"""Tests for OWASP API4:2023 Unrestricted Resource Consumption — rate limiting."""

from typing import Any
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from attacks.rate_limit import validate_target_url, run_rate_limit_attack
from backend.auth.security import hash_password
from backend.models.item import Item
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.rate_limiter import RateLimiter, rate_limiter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_db(db_session: Session) -> dict[str, Any]:
    """Seed synthetic users and items for rate-limit tests."""
    alice = User(
        username="alice",
        hashed_password=hash_password("AliceSyntheticPass123!"),
        role="user",
    )
    admin = User(
        username="admin",
        hashed_password=hash_password("AdminSyntheticPass123!"),
        role="admin",
    )
    db_session.add_all([alice, admin])
    db_session.commit()
    db_session.refresh(alice)
    db_session.refresh(admin)

    item = Item(
        title="Alice Doc",
        description="Test",
        owner_id=alice.id,
        internal_notes="note",
        is_confidential=False,
    )
    db_session.add(item)
    db_session.commit()
    return {"alice": alice, "admin": admin}


# ---------------------------------------------------------------------------
# RateLimiter unit tests
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_within_limit() -> None:
    """Requests within the limit are allowed."""
    limiter = RateLimiter(requests_per_window=5, window_seconds=60)
    for i in range(5):
        allowed, remaining = limiter.check_and_record("user:1")
        assert allowed, f"Request {i+1} should be allowed"


def test_rate_limiter_blocks_after_limit() -> None:
    """Requests exceeding the limit are rejected."""
    limiter = RateLimiter(requests_per_window=3, window_seconds=60)
    for _ in range(3):
        limiter.check_and_record("user:1")
    allowed, remaining = limiter.check_and_record("user:1")
    assert not allowed
    assert remaining == 0


def test_rate_limiter_independent_keys() -> None:
    """Different keys have independent limits."""
    limiter = RateLimiter(requests_per_window=2, window_seconds=60)
    for _ in range(2):
        limiter.check_and_record("user:1")
    # user:1 is at limit
    allowed_1, _ = limiter.check_and_record("user:1")
    assert not allowed_1
    # user:2 is still under limit
    allowed_2, _ = limiter.check_and_record("user:2")
    assert allowed_2


def test_rate_limiter_reset_key() -> None:
    """reset_key() clears the window for a specific key."""
    limiter = RateLimiter(requests_per_window=2, window_seconds=60)
    for _ in range(2):
        limiter.check_and_record("user:1")
    limiter.reset_key("user:1")
    allowed, _ = limiter.check_and_record("user:1")
    assert allowed


def test_rate_limiter_reset_all() -> None:
    """reset_all() clears all windows."""
    limiter = RateLimiter(requests_per_window=2, window_seconds=60)
    for _ in range(2):
        limiter.check_and_record("user:1")
    limiter.reset_all()
    allowed, _ = limiter.check_and_record("user:1")
    assert allowed


def test_rate_limiter_window_reset_seconds() -> None:
    """get_window_reset_seconds returns positive value for active key."""
    limiter = RateLimiter(requests_per_window=5, window_seconds=60)
    limiter.check_and_record("user:1")
    remaining = limiter.get_window_reset_seconds("user:1")
    assert 0 < remaining <= 60


def test_rate_limiter_remaining_count_decreases() -> None:
    """requests_remaining decreases with each call."""
    limiter = RateLimiter(requests_per_window=5, window_seconds=60)
    _, rem1 = limiter.check_and_record("user:1")
    _, rem2 = limiter.check_and_record("user:1")
    assert rem2 < rem1


# ---------------------------------------------------------------------------
# Integration tests: rate-limit dependency on /items/{item_id}
# ---------------------------------------------------------------------------


def test_items_below_rate_limit_succeed(
    client: TestClient,
    seeded_db: dict[str, Any],
) -> None:
    """Requests within the rate limit always succeed (defense ON or OFF)."""
    defense_manager.update_defenses({"rate_limit": True})
    rate_limiter.reset_all()

    # Get alice's token
    login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # First 5 requests should all succeed (well within the 20-request limit)
    for _ in range(5):
        resp = client.get("/items/1", headers=headers)
        assert resp.status_code == 200


def test_items_rate_limited_after_threshold_defense_on(
    client: TestClient,
    seeded_db: dict[str, Any],
) -> None:
    """With rate_limit ON: requests beyond threshold return HTTP 429."""
    defense_manager.update_defenses({"rate_limit": True})
    rate_limiter.reset_all()

    login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    token = login.json()["access_token"]
    alice_id = login.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Exhaust the limit
    key = f"user:{alice_id}"
    # Fill up to the limit
    from backend.security.rate_limiter import DEFAULT_REQUESTS_PER_WINDOW
    for _ in range(DEFAULT_REQUESTS_PER_WINDOW):
        rate_limiter.check_and_record(key)

    # Next request should be rate-limited
    resp = client.get("/items/1", headers=headers)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_items_rate_limit_monitor_only_defense_off(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    db_session: Session,
) -> None:
    """With rate_limit OFF: excess requests still allowed (monitor-only), detected event emitted."""
    from backend.models.event import SecurityEvent
    from backend.security.rate_limiter import DEFAULT_REQUESTS_PER_WINDOW

    defense_manager.update_defenses({"rate_limit": False})
    rate_limiter.reset_all()

    login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    token = login.json()["access_token"]
    alice_id = login.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Exhaust the limit via direct tracker manipulation
    key = f"user:{alice_id}"
    for _ in range(DEFAULT_REQUESTS_PER_WINDOW):
        rate_limiter.check_and_record(key)

    # Request should succeed (defense OFF = no blocking)
    resp = client.get("/items/1", headers=headers)
    assert resp.status_code == 200

    # Detected event emitted
    events = db_session.query(SecurityEvent).filter(
        SecurityEvent.owasp_category == "API4:2023",
        SecurityEvent.rule_name == "rate_limit_exceeded",
        SecurityEvent.action == "detected",
    ).all()
    assert len(events) >= 1


def test_rate_limit_different_users_independent(
    client: TestClient,
    seeded_db: dict[str, Any],
) -> None:
    """Rate limits are per-user: alice's limit doesn't affect admin."""
    from backend.security.rate_limiter import DEFAULT_REQUESTS_PER_WINDOW

    defense_manager.update_defenses({"rate_limit": True})
    rate_limiter.reset_all()

    alice_login = client.post(
        "/auth/login",
        json={"username": "alice", "password": "AliceSyntheticPass123!"},
    )
    alice_id = alice_login.json()["user"]["id"]
    alice_headers = {"Authorization": f"Bearer {alice_login.json()['access_token']}"}

    admin_login = client.post(
        "/auth/login",
        json={"username": "admin", "password": "AdminSyntheticPass123!"},
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

    # Exhaust alice's limit
    alice_key = f"user:{alice_id}"
    for _ in range(DEFAULT_REQUESTS_PER_WINDOW):
        rate_limiter.check_and_record(alice_key)

    # Alice is rate-limited
    resp = client.get("/items/1", headers=alice_headers)
    assert resp.status_code == 429

    # Admin has their own window — first request is fine
    resp = client.get("/items/1", headers=admin_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Attack script tests
# ---------------------------------------------------------------------------


def test_rate_limit_attack_allowlist_validation() -> None:
    """Attack script rejects disallowed targets before any network activity."""
    with pytest.raises(ValueError, match="Disallowed"):
        validate_target_url("http://evil.example.com:8000")

    with pytest.raises(ValueError, match="Disallowed"):
        validate_target_url("http://127.0.0.1:9999")

    with pytest.raises(ValueError, match="Disallowed"):
        validate_target_url("https://127.0.0.1:8000")


def test_rate_limit_attack_burst_count_safety_limit() -> None:
    """run_rate_limit_attack raises ValueError if burst_count exceeds MAX_ATTEMPTS."""
    from attacks.rate_limit import MAX_BURST_REQUESTS
    with pytest.raises(ValueError, match="exceeds safety limit"):
        run_rate_limit_attack(
            target_url="http://127.0.0.1:8000",
            burst_count=MAX_BURST_REQUESTS + 1,
        )
