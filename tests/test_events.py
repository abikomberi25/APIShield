"""Tests for security event logging and admin query endpoints."""

from datetime import datetime, timezone
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token, hash_password
from backend.models.event import SecurityEvent
from backend.models.user import User
from backend.security.events import (
    SecurityEventPersistenceError,
    log_security_event,
)


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
        "alice_id": normal_user.id,
    }


def test_log_security_event_success(db_session: Session, test_users: dict[str, str]) -> None:
    """Verify logging a security event successfully persists all attributes."""
    event = log_security_event(
        db=db_session,
        endpoint="/items/1",
        method="GET",
        owasp_category="API1:2023",
        severity="HIGH",
        rule_name="bola_cross_tenant_access",
        action="blocked",
        user_id=test_users["alice_id"],
        object_id="1",
    )

    assert event.id is not None
    assert event.endpoint == "/items/1"
    assert event.method == "GET"
    assert event.owasp_category == "API1:2023"
    assert event.severity == "HIGH"
    assert event.rule_name == "bola_cross_tenant_access"
    assert event.action == "blocked"
    assert event.user_id == test_users["alice_id"]
    assert event.object_id == "1"
    assert event.timestamp is not None

    # Verify retrieval from DB session
    fetched = db_session.query(SecurityEvent).filter(SecurityEvent.id == event.id).first()
    assert fetched is not None
    assert fetched.action == "blocked"


def test_log_security_event_unauthenticated_user(db_session: Session) -> None:
    """Verify logging an event with user_id=None succeeds (e.g. unauthenticated attack)."""
    event = log_security_event(
        db=db_session,
        endpoint="/auth/login",
        method="POST",
        owasp_category="API2:2023",
        severity="MEDIUM",
        rule_name="credential_stuffing_attempt",
        action="detected",
        user_id=None,
    )

    assert event.id is not None
    assert event.user_id is None
    assert event.action == "detected"


def test_log_security_event_service_validation_errors(db_session: Session) -> None:
    """Verify service-level validation rejects invalid action, severity, or empty fields."""
    # Invalid action
    with pytest.raises(ValueError, match="Invalid action 'ignored'"):
        log_security_event(
            db=db_session,
            endpoint="/items/1",
            method="GET",
            owasp_category="API1:2023",
            severity="HIGH",
            rule_name="rule1",
            action="ignored",
        )

    # Invalid severity
    with pytest.raises(ValueError, match="Invalid severity 'LOWEST'"):
        log_security_event(
            db=db_session,
            endpoint="/items/1",
            method="GET",
            owasp_category="API1:2023",
            severity="LOWEST",
            rule_name="rule1",
            action="blocked",
        )

    # Empty required endpoint
    with pytest.raises(ValueError, match="Field 'endpoint' must be a non-empty string"):
        log_security_event(
            db=db_session,
            endpoint="",
            method="GET",
            owasp_category="API1:2023",
            severity="HIGH",
            rule_name="rule1",
            action="blocked",
        )


def test_db_check_constraints_enforced(db_session: Session) -> None:
    """Verify SQLite table check constraints reject invalid action and severity values."""
    # Direct model insertion bypassing service validation to test DB check constraint
    invalid_action_event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        endpoint="/items/1",
        method="GET",
        owasp_category="API1:2023",
        severity="HIGH",
        rule_name="rule1",
        action="invalid_action",
    )
    db_session.add(invalid_action_event)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()

    invalid_severity_event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        endpoint="/items/1",
        method="GET",
        owasp_category="API1:2023",
        severity="SUPER_HIGH",
        rule_name="rule1",
        action="blocked",
    )
    db_session.add(invalid_severity_event)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_log_security_event_db_failure_handled_safely() -> None:
    """Verify database failures trigger safe rollback and SecurityEventPersistenceError."""
    mock_db = MagicMock(spec=Session)
    mock_db.commit.side_effect = SQLAlchemyError("Simulated connection failure")

    with pytest.raises(SecurityEventPersistenceError, match="database error"):
        log_security_event(
            db=mock_db,
            endpoint="/items/1",
            method="GET",
            owasp_category="API1:2023",
            severity="HIGH",
            rule_name="rule1",
            action="blocked",
        )

    # Ensure rollback was safely invoked
    mock_db.rollback.assert_called_once()


def test_admin_get_events_empty(client: TestClient, test_users: dict[str, str]) -> None:
    """Verify that an empty security_events table returns total 0 and empty list."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}
    response = client.get("/admin/events", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["limit"] == 50
    assert data["offset"] == 0
    assert data["events"] == []


def test_admin_get_events_pagination_and_filtering(
    client: TestClient, db_session: Session, test_users: dict[str, str]
) -> None:
    """Verify bounded pagination, offset, and action filtering on GET /admin/events."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}

    # Populate 5 distinct events
    for i in range(1, 6):
        log_security_event(
            db=db_session,
            endpoint=f"/items/{i}",
            method="GET",
            owasp_category="API1:2023",
            severity="HIGH",
            rule_name="bola_check",
            action="blocked" if i % 2 == 0 else "detected",
            object_id=str(i),
        )

    # 1. Page 1: limit 2, offset 0
    res1 = client.get("/admin/events?limit=2&offset=0", headers=headers)
    assert res1.status_code == 200
    data1 = res1.json()
    assert data1["total"] == 5
    assert len(data1["events"]) == 2
    assert data1["limit"] == 2
    assert data1["offset"] == 0

    # 2. Page 2: limit 2, offset 2
    res2 = client.get("/admin/events?limit=2&offset=2", headers=headers)
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["total"] == 5
    assert len(data2["events"]) == 2
    assert data2["offset"] == 2

    # Events in page 1 and page 2 must not overlap
    ids_page1 = {e["id"] for e in data1["events"]}
    ids_page2 = {e["id"] for e in data2["events"]}
    assert ids_page1.isdisjoint(ids_page2)

    # 3. Filtering by action="blocked" (2 events: i=2, 4)
    res_blocked = client.get("/admin/events?action=blocked", headers=headers)
    assert res_blocked.status_code == 200
    data_blocked = res_blocked.json()
    assert data_blocked["total"] == 2
    assert all(e["action"] == "blocked" for e in data_blocked["events"])

    # 4. Filtering by action="detected" (3 events: i=1, 3, 5)
    res_detected = client.get("/admin/events?action=detected", headers=headers)
    assert res_detected.status_code == 200
    data_detected = res_detected.json()
    assert data_detected["total"] == 3
    assert all(e["action"] == "detected" for e in data_detected["events"])


def test_admin_get_events_bounded_validation(
    client: TestClient, test_users: dict[str, str]
) -> None:
    """Verify that pagination bounds and invalid actions are rejected with 422."""
    headers = {"Authorization": f"Bearer {test_users['admin_token']}"}

    # limit > 100 rejected
    res_limit_high = client.get("/admin/events?limit=101", headers=headers)
    assert res_limit_high.status_code == 422

    # limit < 1 rejected
    res_limit_low = client.get("/admin/events?limit=0", headers=headers)
    assert res_limit_low.status_code == 422

    # offset < 0 rejected
    res_offset_neg = client.get("/admin/events?offset=-1", headers=headers)
    assert res_offset_neg.status_code == 422

    # invalid action filter rejected
    res_invalid_action = client.get("/admin/events?action=allowed", headers=headers)
    assert res_invalid_action.status_code == 422


def test_normal_user_cannot_access_events(
    client: TestClient, test_users: dict[str, str]
) -> None:
    """Verify that non-admin users receive 403 Forbidden on GET /admin/events."""
    headers = {"Authorization": f"Bearer {test_users['alice_token']}"}
    res = client.get("/admin/events", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "Admin access required"


def test_unauthenticated_cannot_access_events(client: TestClient) -> None:
    """Verify that unauthenticated requests receive 401 Unauthorized on GET /admin/events."""
    res = client.get("/admin/events")
    assert res.status_code == 401
