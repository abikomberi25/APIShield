"""OWASP API2:2023 Broken Authentication — controlled attack script for APIShield.

Performs bounded failed-login attempts against a synthetic account to demonstrate
brute-force behavior with auth_hardening defense OFF and ON.
Strictly validates the target against a hardcoded local allowlist before any network
requests. Never logs passwords, tokens, or Authorization headers.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Optional, Union
from urllib.parse import urlparse
import httpx

ALLOWED_SCHEMES = {"http"}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "api"}
ALLOWED_PORTS = {8000}

# Hard limit on failed-login attempts — never exceed this in any run
MAX_ATTEMPTS = 10
# Attempt count for the experiment (must be <= MAX_ATTEMPTS and > LOCKOUT_MAX_ATTEMPTS=5)
TARGET_ATTEMPTS = 7


def validate_target_url(target_url: str) -> str:
    """Validate target URL against hardcoded local security allowlist.

    Must be called before making any network requests.
    Raises ValueError if the target is not explicitly allowed.
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("Target URL must be a non-empty string.")
    parsed = urlparse(target_url.strip())
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(f"Disallowed scheme '{parsed.scheme}'.")
    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname not in ALLOWED_HOSTS:
        raise ValueError(f"Disallowed host '{hostname}'. Allowed: {sorted(ALLOWED_HOSTS)}.")
    port = parsed.port
    if port is None or port not in ALLOWED_PORTS:
        raise ValueError(f"Disallowed port '{port}'.")
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in target URL are prohibited.")
    if parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain query strings or fragments.")
    return f"{parsed.scheme}://{hostname}:{port}"


def run_auth_attack(
    target_url: str,
    attempt_count: int = TARGET_ATTEMPTS,
    results_path: Optional[Union[Path, bool]] = None,
    client: Optional[httpx.Client] = None,
) -> dict[str, Any]:
    """Execute controlled brute-force login attempt experiment.

    Steps:
    1. Validate target URL against allowlist.
    2. Get admin event baseline.
    3. Fire attempt_count failed login attempts against synthetic account 'alice'.
    4. Attempt one final correct login to check if the account is locked.
    5. Verify the corresponding security event via /admin/events.
    6. Return structured result dict.
    """
    if attempt_count > MAX_ATTEMPTS:
        raise ValueError(f"attempt_count {attempt_count} exceeds safety limit {MAX_ATTEMPTS}.")

    base_url = validate_target_url(target_url)

    close_client = False
    if client is None:
        client = httpx.Client(timeout=10.0)
        close_client = True

    try:
        # Admin auth for baseline and event verification
        admin_login = client.post(
            f"{base_url}/auth/login",
            json={"username": "admin", "password": "AdminSyntheticPass123!"},
        )
        if admin_login.status_code != 200:
            raise RuntimeError(f"Admin auth failed: HTTP {admin_login.status_code}")
        admin_token = admin_login.json().get("access_token")
        if not admin_token:
            raise RuntimeError("Admin login missing access_token.")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Event baseline
        latest_id_before = 0
        baseline_res = client.get(f"{base_url}/admin/events?limit=1", headers=admin_headers)
        if baseline_res.status_code == 200:
            evs = baseline_res.json().get("events", [])
            if evs:
                latest_id_before = evs[0].get("id", 0)

        # Current defense state
        def_res = client.get(f"{base_url}/admin/defenses", headers=admin_headers)
        defense_active = False
        if def_res.status_code == 200:
            defense_active = def_res.json().get("defenses", {}).get("auth_hardening", False)

        # Fire attempt_count failed logins against alice with wrong password
        failed_401 = 0
        failed_429 = 0
        first_lockout_attempt: Optional[int] = None

        for i in range(attempt_count):
            resp = client.post(
                f"{base_url}/auth/login",
                # Wrong password — never log it; use a deterministic wrong value
                json={"username": "alice", "password": "WrongPassword_Attempt"},
            )
            if resp.status_code == 401:
                failed_401 += 1
            elif resp.status_code == 429:
                failed_429 += 1
                if first_lockout_attempt is None:
                    first_lockout_attempt = i + 1
            # Any other status is unexpected

        # Try one correct login to check if account is accessible
        correct_resp = client.post(
            f"{base_url}/auth/login",
            json={"username": "alice", "password": "AliceSyntheticPass123!"},
        )
        account_accessible = correct_resp.status_code == 200
        account_locked = correct_resp.status_code == 429

        # Verify detection event
        detection_verified = False
        matched_event_id: Optional[int] = None
        expected_action = "blocked" if defense_active else "detected"
        try:
            events_res = client.get(f"{base_url}/admin/events?limit=50", headers=admin_headers)
            if events_res.status_code == 200:
                post_events = events_res.json().get("events", [])
                for ev in post_events:
                    if (
                        ev.get("id", 0) > latest_id_before
                        and ev.get("owasp_category") == "API2:2023"
                        and ev.get("rule_name") == "auth_brute_force"
                        and ev.get("action") == expected_action
                    ):
                        detection_verified = True
                        matched_event_id = ev.get("id")
                        break
        except Exception:
            detection_verified = False

        # Classify outcome
        if defense_active and failed_429 > 0 and account_locked and detection_verified:
            outcome = "attack_blocked"
        elif not defense_active and failed_401 == attempt_count and account_accessible and detection_verified:
            outcome = "vulnerability_exploited"
        elif not defense_active and failed_401 == attempt_count and account_accessible and not detection_verified:
            outcome = "unverified_detection"
        else:
            outcome = "unexpected"

        result = {
            "experiment": "OWASP API2:2023 Broken Authentication",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": base_url,
            "target_username": "alice",
            "defense_active": defense_active,
            "attempt_count": attempt_count,
            "failed_401": failed_401,
            "failed_429": failed_429,
            "first_lockout_at_attempt": first_lockout_attempt,
            "account_accessible_after_attempts": account_accessible,
            "account_locked_after_attempts": account_locked,
            "detection_verified": detection_verified,
            "matched_event_id": matched_event_id,
            "outcome": outcome,
        }

        if results_path is not False and outcome in ("vulnerability_exploited", "attack_blocked"):
            if results_path is None:
                results_path = (
                    Path(__file__).resolve().parent.parent
                    / "docs" / "results" / "auth_results.json"
                )
            results_path.parent.mkdir(parents=True, exist_ok=True)
            results_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return result

    finally:
        if close_client:
            client.close()


def main(
    target_url: Optional[str] = None,
    results_path: Optional[Union[Path, bool]] = None,
    client: Optional[httpx.Client] = None,
    raise_on_failure: bool = False,
) -> None:
    """CLI entry point: dual-run broken-auth experiment (defense OFF then ON).

    Run 1 — auth_hardening OFF: failed attempts all return 401, account stays accessible.
    Run 2 — auth_hardening ON: account locked after threshold, correct login returns 429.
    Restores original toggle in a finally block.
    """
    if target_url is None:
        parser = argparse.ArgumentParser(
            description="APIShield OWASP API2:2023 Broken Authentication Experiment"
        )
        parser.add_argument(
            "--target", default="http://127.0.0.1:8000",
            help="Target base URL (default: http://127.0.0.1:8000)"
        )
        args = parser.parse_args()
        target_to_use = args.target
    else:
        target_to_use = target_url

    try:
        validate_target_url(target_to_use)
    except ValueError as exc:
        print(f"[REJECTED] {exc}", file=sys.stderr)
        if raise_on_failure:
            raise
        sys.exit(1)

    print("==================================================")
    print(" APIShield Broken Authentication Experiment")
    print(f" Target: {target_to_use}")
    print("==================================================")

    base_url = target_to_use.rstrip("/")

    if results_path is None:
        target_results_path: Union[Path, bool] = (
            Path(__file__).resolve().parent.parent
            / "docs" / "results" / "auth_results.json"
        )
    else:
        target_results_path = results_path

    close_client = False
    if client is None:
        client = httpx.Client(timeout=10.0)
        close_client = True

    try:
        admin_login = client.post(
            f"{base_url}/auth/login",
            json={"username": "admin", "password": "AdminSyntheticPass123!"},
        )
        if admin_login.status_code != 200:
            raise RuntimeError(f"Admin auth failed: HTTP {admin_login.status_code}")
        admin_token = admin_login.json().get("access_token")
        if not admin_token:
            raise RuntimeError("Admin login missing access_token.")
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        def_res = client.get(f"{base_url}/admin/defenses", headers=admin_headers)
        if def_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch defenses: HTTP {def_res.status_code}")
        defenses = def_res.json().get("defenses", {})
        if "auth_hardening" not in defenses:
            raise RuntimeError("auth_hardening defense toggle not found.")
        original_auth_hardening = defenses["auth_hardening"]

        # Need lab mode active
        lab_res = client.get(f"{base_url}/admin/lab-mode", headers=admin_headers)
        if lab_res.status_code != 200 or not lab_res.json().get("lab_mode", False):
            raise RuntimeError(
                "Lab mode is not enabled. Start the server with APISHIELD_LAB_MODE=true."
            )

        restoration_succeeded = False

        try:
            # Run 1: auth_hardening OFF
            print("\n[Run 1] Setting auth_hardening OFF (vulnerable mode)...")
            patch_off = client.patch(
                f"{base_url}/admin/defenses",
                json={"auth_hardening": False},
                headers=admin_headers,
            )
            if (
                patch_off.status_code != 200
                or patch_off.json().get("defenses", {}).get("auth_hardening") is not False
            ):
                raise RuntimeError(
                    f"Failed to set auth_hardening=False: HTTP {patch_off.status_code}"
                )

            result_off = run_auth_attack(
                target_url=target_to_use, results_path=False, client=client
            )
            if (
                result_off.get("outcome") != "vulnerability_exploited"
                or not result_off.get("detection_verified")
            ):
                raise RuntimeError(
                    f"Run 1 failed: outcome={result_off.get('outcome')!r}, "
                    f"detection_verified={result_off.get('detection_verified')!r}"
                )

            # Run 2: auth_hardening ON
            print("\n[Run 2] Setting auth_hardening ON (defended mode)...")
            patch_on = client.patch(
                f"{base_url}/admin/defenses",
                json={"auth_hardening": True},
                headers=admin_headers,
            )
            if (
                patch_on.status_code != 200
                or patch_on.json().get("defenses", {}).get("auth_hardening") is not True
            ):
                raise RuntimeError(
                    f"Failed to set auth_hardening=True: HTTP {patch_on.status_code}"
                )

            # Reset lockout state before defended run so it counts from 0
            # (in real deployment this would already be fresh; for experiment repeatability
            #  we reset it via the admin endpoint if available, or accept the fresh window)
            result_on = run_auth_attack(
                target_url=target_to_use, results_path=False, client=client
            )
            if (
                result_on.get("outcome") != "attack_blocked"
                or not result_on.get("detection_verified")
            ):
                raise RuntimeError(
                    f"Run 2 failed: outcome={result_on.get('outcome')!r}, "
                    f"detection_verified={result_on.get('detection_verified')!r}"
                )

        finally:
            try:
                restore_res = client.patch(
                    f"{base_url}/admin/defenses",
                    json={"auth_hardening": original_auth_hardening},
                    headers=admin_headers,
                )
                restored_val = (
                    restore_res.json().get("defenses", {}).get("auth_hardening")
                    if restore_res.status_code == 200 else None
                )
                if (
                    restore_res.status_code != 200
                    or restored_val != original_auth_hardening
                ):
                    print(
                        f"[WARNING] Failed to restore auth_hardening "
                        f"(HTTP {restore_res.status_code}, got={restored_val}, "
                        f"expected={original_auth_hardening}). "
                        "Server defense state may be unresolved.",
                        file=sys.stderr,
                    )
                else:
                    restoration_succeeded = True
            except Exception as restore_exc:
                print(
                    f"[WARNING] Exception during auth_hardening restoration: {restore_exc}.",
                    file=sys.stderr,
                )

        if not restoration_succeeded:
            raise RuntimeError(
                "auth_hardening defense state was not confirmed as restored. "
                "Combined results not written."
            )

        combined = {
            "experiment": "OWASP API2:2023 Broken Authentication",
            "timestamp": result_on["timestamp"],
            "target": result_on["target"],
            "target_username": "alice",
            "attempt_count": result_on["attempt_count"],
            "vulnerable_run": {
                "defense_active": result_off["defense_active"],
                "failed_401": result_off["failed_401"],
                "failed_429": result_off["failed_429"],
                "account_accessible_after_attempts": result_off["account_accessible_after_attempts"],
                "account_locked_after_attempts": result_off["account_locked_after_attempts"],
                "detection_verified": result_off["detection_verified"],
                "matched_event_id": result_off["matched_event_id"],
                "outcome": result_off["outcome"],
            },
            "defended_run": {
                "defense_active": result_on["defense_active"],
                "failed_401": result_on["failed_401"],
                "failed_429": result_on["failed_429"],
                "first_lockout_at_attempt": result_on["first_lockout_at_attempt"],
                "account_accessible_after_attempts": result_on["account_accessible_after_attempts"],
                "account_locked_after_attempts": result_on["account_locked_after_attempts"],
                "detection_verified": result_on["detection_verified"],
                "matched_event_id": result_on["matched_event_id"],
                "outcome": result_on["outcome"],
            },
        }

        if target_results_path is not False:
            assert isinstance(target_results_path, Path)
            target_results_path.parent.mkdir(parents=True, exist_ok=True)
            target_results_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")
            print(f" Results written to: {target_results_path}")

        print("\n--- Experiment Summary ---")
        print(
            f" [Vulnerable] 401x{result_off['failed_401']} | "
            f"{result_off['outcome']} | detection_verified={result_off['detection_verified']}"
        )
        print(
            f" [Defended]   429x{result_on['failed_429']} | "
            f"{result_on['outcome']} | detection_verified={result_on['detection_verified']}"
        )
        print("==================================================")

    except Exception as exc:
        print(f"[ERROR] Experiment failed: {exc}", file=sys.stderr)
        if raise_on_failure:
            raise
        sys.exit(1)
    finally:
        if close_client:
            client.close()


if __name__ == "__main__":
    main()
