"""Tests for OWASP API5:2023 (BFLA / RBAC) attack, detection, defense, and verification."""

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from attacks.rbac import main as rbac_main, run_rbac_attack, validate_target_url
from backend.auth.security import create_access_token, hash_password
from backend.models.event import SecurityEvent
from backend.models.user import User
from backend.security.defenses import defense_manager
from backend.security.events import SecurityEventPersistenceError, log_security_event


@pytest.fixture
def seeded_db(db_session: Session) -> dict[str, Any]:
    """Seed synthetic users (Alice, Bob, Admin) for testing."""
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
        "alice_token": alice_token,
        "bob_token": bob_token,
        "admin_token": admin_token,
    }


def test_unauthenticated_access_denied(
    client: TestClient, db_session: Session, lab_mode_enabled: None
) -> None:
    """Verify that unauthenticated requests to GET /admin/events are rejected with HTTP 401."""
    # Missing token
    res1 = client.get("/admin/events")
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Not authenticated"

    # Malformed token
    res2 = client.get(
        "/admin/events", headers={"Authorization": "Bearer malformed.jwt.token"}
    )
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Could not validate credentials"

    # Expired token
    expired = create_access_token(
        subject="1",
        claims={"username": "alice", "role": "user"},
        expires_delta=timedelta(seconds=-10),
    )
    res3 = client.get("/admin/events", headers={"Authorization": f"Bearer {expired}"})
    assert res3.status_code == 401
    assert res3.json()["detail"] == "Token expired"

    # Zero security events logged
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_legitimate_admin_access_allowed_and_no_event(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify legitimate admin access returns HTTP 200 with zero BFLA security events."""
    headers = {"Authorization": f"Bearer {seeded_db['admin_token']}"}
    res = client.get("/admin/events", headers=headers)
    assert res.status_code == 200
    assert "events" in res.json()
    assert "total" in res.json()

    # Admin access must never be flagged as BFLA
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_default_safe_mode_outside_lab_mode(
    client: TestClient, db_session: Session, seeded_db: dict[str, Any]
) -> None:
    """Verify that outside lab mode, normal user access to /admin/events is strictly rejected with HTTP 403."""
    # Note: lab_mode_enabled fixture is NOT used here; STARTUP_LAB_MODE is False
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Even if rbac defense is False, default safe mode rejects non-admin
    assert defense_manager.get_defenses()["rbac"] is False
    res = client.get("/admin/events", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "Admin access required"

    # Zero security events logged outside lab mode
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 0


def test_bfla_vulnerable_mode_exploit_and_detection(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify that with lab mode active and rbac OFF, BFLA exploit succeeds and is detected."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}
    assert defense_manager.get_defenses()["rbac"] is False

    # Alice requests administrative events
    res = client.get("/admin/events", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "total" in data

    # Real security event must be logged with action="detected"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API5:2023"
    assert event.rule_name == "bfla_unauthorized_function_access"
    assert event.severity == "HIGH"
    assert event.action == "detected"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id is None
    assert event.endpoint == "/admin/events"
    assert event.method == "GET"


def test_bfla_defended_mode_block_and_detection(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify that with lab mode active and rbac ON, BFLA exploit is blocked and detected."""
    defense_manager.update_defenses({"rbac": True})
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # Alice requests administrative events
    res = client.get("/admin/events", headers=headers)
    assert res.status_code == 403
    assert res.json()["detail"] == "Admin access required"

    # Real security event must be logged with action="blocked"
    events = db_session.query(SecurityEvent).all()
    assert len(events) == 1
    event = events[0]
    assert event.owasp_category == "API5:2023"
    assert event.rule_name == "bfla_unauthorized_function_access"
    assert event.severity == "HIGH"
    assert event.action == "blocked"
    assert event.user_id == seeded_db["alice"].id
    assert event.object_id is None
    assert event.endpoint == "/admin/events"
    assert event.method == "GET"


def test_cross_endpoint_admin_isolation(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
) -> None:
    """Verify all other administrative endpoints remain strictly protected even in vulnerable mode."""
    # Lab mode is enabled, and rbac is OFF
    assert defense_manager.get_defenses()["rbac"] is False
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    # GET /admin/defenses must return 403 Forbidden
    res_def_get = client.get("/admin/defenses", headers=headers)
    assert res_def_get.status_code == 403
    assert res_def_get.json()["detail"] == "Admin access required"

    # PATCH /admin/defenses must return 403 Forbidden
    res_def_patch = client.patch(
        "/admin/defenses", json={"rbac": True}, headers=headers
    )
    assert res_def_patch.status_code == 403
    assert res_def_patch.json()["detail"] == "Admin access required"

    # GET /admin/lab-mode must return 403 Forbidden
    res_lab = client.get("/admin/lab-mode", headers=headers)
    assert res_lab.status_code == 403
    assert res_lab.json()["detail"] == "Admin access required"


def test_fail_closed_on_security_event_persistence_failure(
    client: TestClient, seeded_db: dict[str, Any], lab_mode_enabled: None
) -> None:
    """Verify fail-closed behavior: if event logging fails, access is denied with HTTP 500."""
    headers = {"Authorization": f"Bearer {seeded_db['alice_token']}"}

    with patch("detection.rbac.log_security_event") as mock_log:
        mock_log.side_effect = SecurityEventPersistenceError(
            "Simulated DB write failure"
        )
        res = client.get("/admin/events", headers=headers)
        assert res.status_code == 500
        assert res.json()["detail"] == "Security event logging failed; access denied"


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
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify attack script runner reproduces both vulnerability exploit and defense block."""
    custom_results_path = tmp_path / "test_rbac_results.json"

    # 1. Run attack with defense OFF
    defense_manager.reset()
    res_off = run_rbac_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_off["status_code"] == 200
    assert res_off["attack_success"] is True
    assert res_off["blocked"] is False
    assert res_off["outcome"] == "vulnerability_exploited"
    assert res_off["detection_verified"] is True
    assert isinstance(res_off["matched_event_id"], int)

    # 2. Run attack with defense ON
    defense_manager.update_defenses({"rbac": True})
    res_on = run_rbac_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )
    assert res_on["status_code"] == 403
    assert res_on["attack_success"] is False
    assert res_on["blocked"] is True
    assert res_on["outcome"] == "attack_blocked"
    assert res_on["detection_verified"] is True
    assert isinstance(res_on["matched_event_id"], int)


def test_attack_script_event_correlation_ignores_past_events(
    client: TestClient,
    db_session: Session,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify that event correlation strictly ignores events generated prior to the attack run."""
    custom_results_path = tmp_path / "test_rbac_correlation_results.json"

    # Seed an old event from a prior run
    log_security_event(
        db=db_session,
        endpoint="/admin/events",
        method="GET",
        owasp_category="API5:2023",
        severity="HIGH",
        rule_name="bfla_unauthorized_function_access",
        action="detected",
        user_id=seeded_db["alice"].id,
        object_id=None,
    )

    # Now enable defense and run attack
    defense_manager.update_defenses({"rbac": True})
    res = run_rbac_attack(
        target_url="http://127.0.0.1:8000",
        results_path=custom_results_path,
        client=client,
    )

    # Must verify the newly generated 'blocked' event, not the pre-existing 'detected' event
    assert res["status_code"] == 403
    assert res["detection_verified"] is True
    assert res["matched_event_id"] is not None
    # Verify matched event is indeed the blocked one (id > 1)
    assert res["matched_event_id"] > 1


def test_main_orchestration_success_both_modes(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify rbac_main() successfully executes both modes, restores defense, and writes combined results."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()
    assert defense_manager.get_defenses()["rbac"] is False

    rbac_main(
        target_url="http://127.0.0.1:8000",
        results_path=results_file,
        client=client,
        raise_on_failure=True,
    )

    assert results_file.exists()
    import json
    data = json.loads(results_file.read_text(encoding="utf-8"))
    assert data["experiment"] == "OWASP API5:2023 BFLA/RBAC"
    assert data["vulnerable_run"]["status_code"] == 200
    assert data["vulnerable_run"]["outcome"] == "vulnerability_exploited"
    assert data["vulnerable_run"]["detection_verified"] is True
    assert data["vulnerable_run"]["defense_active"] is False

    assert data["defended_run"]["status_code"] == 403
    assert data["defended_run"]["outcome"] == "attack_blocked"
    assert data["defended_run"]["detection_verified"] is True
    assert data["defended_run"]["defense_active"] is True

    # Defense state must be restored to original (False)
    assert defense_manager.get_defenses()["rbac"] is False


def test_main_failure_to_fetch_initial_defense_aborts_before_changing(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify rbac_main() aborts if initial GET /admin/defenses fails, without mutating defense toggles."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()
    defense_manager.update_defenses({"rbac": True})

    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if "/admin/defenses" in url:
            from httpx import Response
            return Response(status_code=500, json={"detail": "Simulated error"})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        with pytest.raises(RuntimeError, match="Failed to fetch initial defense states"):
            rbac_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    # State must remain True (untouched)
    assert defense_manager.get_defenses()["rbac"] is True
    assert not results_file.exists()


def test_main_failure_to_apply_toggle_aborts_and_reports(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify rbac_main() aborts if toggle PATCH fails, and restores defense state."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()

    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        json_body = kwargs.get("json", {})
        if "/admin/defenses" in url and json_body.get("rbac") is False:
            from httpx import Response
            return Response(status_code=500, json={"detail": "Simulated patch failure"})
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        with pytest.raises(RuntimeError, match="Failed to set rbac defense toggle to OFF"):
            rbac_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    assert not results_file.exists()
    assert defense_manager.get_defenses()["rbac"] is False


def test_main_restores_defense_state_after_attack_failure(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify rbac_main() restores original defense state even if an attack run raises an exception."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.update_defenses({"rbac": True})

    with patch("attacks.rbac.run_rbac_attack", side_effect=RuntimeError("Simulated attack error")):
        with pytest.raises(RuntimeError, match="Simulated attack error"):
            rbac_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    # Must be restored to True
    assert defense_manager.get_defenses()["rbac"] is True
    assert not results_file.exists()


def test_main_restoration_failure_explicitly_reported(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Verify rbac_main() warns explicitly on stderr if restoration PATCH fails."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()

    patch_count = 0
    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        nonlocal patch_count
        if "/admin/defenses" in url:
            patch_count += 1
            # 1st patch: set OFF (200)
            # 2nd patch: set ON (200)
            # 3rd patch: restore (500 error)
            if patch_count == 3:
                from httpx import Response
                return Response(status_code=500, json={"detail": "Simulated restore failure"})
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        rbac_main(
            target_url="http://127.0.0.1:8000",
            results_path=results_file,
            client=client,
            raise_on_failure=False,
        )

    captured = capsys.readouterr()
    assert "The server's RBAC defense state may be unresolved." in captured.err


def test_main_results_file_write_failure_does_not_report_success(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Verify rbac_main() handles results write failure by reporting failure and not claiming success."""
    # Use a directory path as the results file path to force write failure
    bad_results_path = tmp_path / "a_directory"
    bad_results_path.mkdir()

    with pytest.raises(Exception):
        rbac_main(
            target_url="http://127.0.0.1:8000",
            results_path=bad_results_path,
            client=client,
            raise_on_failure=True,
        )

    captured = capsys.readouterr()
    assert "Results written to" not in captured.out


def test_main_unverified_detection_does_not_write_combined_results(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify rbac_main() aborts without writing results if an attack run lacks verified detection."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()

    # Mock run_rbac_attack to return detection_verified=False
    mock_run_result = {
        "status_code": 200,
        "attack_success": True,
        "blocked": False,
        "outcome": "unverified_detection",
        "detection_verified": False,
        "defense_active": False,
        "matched_event_id": None,
    }

    with patch("attacks.rbac.run_rbac_attack", return_value=mock_run_result):
        with pytest.raises(RuntimeError, match="failed verification"):
            rbac_main(
                target_url="http://127.0.0.1:8000",
                results_path=results_file,
                client=client,
                raise_on_failure=True,
            )

    assert not results_file.exists()

def test_main_restoration_mismatch_explicitly_reported(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
) -> None:
    """Verify rbac_main() warns explicitly on stderr if restoration PATCH returns 200 but defenses.rbac does not match original_rbac."""
    results_file = tmp_path / "combined_rbac_results.json"
    defense_manager.reset()

    patch_count = 0
    original_patch = client.patch

    def mock_patch(url, *args, **kwargs):
        nonlocal patch_count
        if "/admin/defenses" in url:
            patch_count += 1
            # 1st patch: set OFF (200)
            # 2nd patch: set ON (200)
            # 3rd patch: restoration returns 200, but claims rbac=True when original_rbac was False!
            if patch_count == 3:
                from httpx import Response
                return Response(
                    status_code=200,
                    json={"message": "Defenses updated successfully", "defenses": {"rbac": True}},
                )
        return original_patch(url, *args, **kwargs)

    with patch.object(client, "patch", side_effect=mock_patch):
        rbac_main(
            target_url="http://127.0.0.1:8000",
            results_path=results_file,
            client=client,
            raise_on_failure=False,
        )

    captured = capsys.readouterr()
    assert "The server's RBAC defense state may be unresolved." in captured.err
    assert "rbac=True, expected=False" in captured.err


def test_run_rbac_attack_unverified_detection_when_events_do_not_match(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_rbac_attack sets outcome='unverified_detection' when detection cannot be verified."""
    custom_results_path = tmp_path / "unverified_rbac.json"
    defense_manager.reset()

    # Mock admin events endpoint query after attack to return empty events list
    original_get = client.get

    def mock_get(url, *args, **kwargs):
        if "/admin/events?limit=20" in url:
            from httpx import Response
            return Response(status_code=200, json={"events": [], "total": 0})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_rbac_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    assert res["status_code"] == 200
    assert res["attack_success"] is True
    assert res["detection_verified"] is False
    assert res["matched_event_id"] is None
    # Crucially, outcome must be 'unverified_detection', NOT 'vulnerability_exploited'
    assert res["outcome"] == "unverified_detection"


def test_run_rbac_attack_unexpected_outcome_on_unexpected_status(
    client: TestClient,
    seeded_db: dict[str, Any],
    lab_mode_enabled: None,
    tmp_path: Path,
) -> None:
    """Verify run_rbac_attack sets outcome='unexpected' when target endpoint returns unexpected HTTP status."""
    custom_results_path = tmp_path / "unexpected_rbac.json"
    defense_manager.reset()

    original_get = client.get

    def mock_get(url, *args, **kwargs):
        # Alice's attack request to /admin/events
        if url.endswith("/admin/events") and "Authorization" in kwargs.get("headers", {}):
            from httpx import Response
            return Response(status_code=502, json={"detail": "Bad Gateway"})
        return original_get(url, *args, **kwargs)

    with patch.object(client, "get", side_effect=mock_get):
        res = run_rbac_attack(
            target_url="http://127.0.0.1:8000",
            results_path=custom_results_path,
            client=client,
        )

    assert res["status_code"] == 502
    assert res["attack_success"] is False
    assert res["blocked"] is False
    assert res["detection_verified"] is False
    assert res["outcome"] == "unexpected"
