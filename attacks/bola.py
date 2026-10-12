"""OWASP API1:2023 (BOLA) reproducible attack script for APIShield.

Performs controlled cross-user access attempts against seeded synthetic data.
Strictly validates scheme, host, and port before making any network requests.
Never prints or logs passwords, tokens, or Authorization headers.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Optional
from urllib.parse import urlparse
import httpx

ALLOWED_SCHEMES = {"http"}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "api"}
ALLOWED_PORTS = {8000}


def validate_target_url(target_url: str) -> str:
    """Validate target URL against hardcoded local security allowlist.

    Must be called before making any network requests.
    Enforces scheme, host, port, and URL hygiene. Raises ValueError if invalid.
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("Target URL must be a non-empty string.")

    parsed = urlparse(target_url.strip())

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Disallowed scheme '{parsed.scheme}'. Scheme must be strictly 'http'."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"Disallowed target host '{hostname}'. Host must be one of: {sorted(ALLOWED_HOSTS)}."
        )

    port = parsed.port
    if port is None or port not in ALLOWED_PORTS:
        raise ValueError(
            f"Disallowed or missing port '{port}'. Port must be strictly: {sorted(ALLOWED_PORTS)}."
        )

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in target URL are prohibited.")

    if parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain query strings or fragments.")

    # Return normalized base URL without trailing slash
    return f"{parsed.scheme}://{hostname}:{port}"


def run_bola_attack(
    target_url: str,
    results_path: Optional[Path] = None,
    client: Optional[httpx.Client] = None,
) -> dict[str, Any]:
    """Execute the controlled BOLA attack experiment.

    Steps:
    1. Validate scheme, hostname, and port before any network activity.
    2. Authenticate synthetic user 'alice' (never logging credentials/token).
    3. Attempt unauthorized read of Bob's item (/items/3).
    4. Authenticate as 'admin' to query /admin/events and verify the logged event.
    5. Save structured results to docs/results/bola_results.json.
    """
    # Step 1: Pre-flight validation
    base_url = validate_target_url(target_url)

    # Use provided client (e.g. for testing) or instantiate a new one
    close_client = False
    if client is None:
        client = httpx.Client(timeout=10.0)
        close_client = True

    try:
        # Step 2: Authenticate Alice
        login_res = client.post(
            f"{base_url}/auth/login",
            json={"username": "alice", "password": "AliceSyntheticPass123!"},
        )
        if login_res.status_code != 200:
            raise RuntimeError(
                f"Authentication failed for synthetic attacker 'alice': HTTP {login_res.status_code}"
            )

        alice_token = login_res.json().get("access_token")
        if not alice_token:
            raise RuntimeError("Login response did not contain an access_token.")

        # Step 3: Attempt cross-user read on Bob's Item 3
        headers_alice = {"Authorization": f"Bearer {alice_token}"}
        target_item_id = 3
        attack_res = client.get(
            f"{base_url}/items/{target_item_id}",
            headers=headers_alice,
        )

        status_code = attack_res.status_code
        attack_success = status_code == 200 and attack_res.json().get("id") == target_item_id
        blocked = status_code == 403

        # Step 4: Verify security event via Admin API
        detection_verified = False
        defense_active = None
        try:
            admin_login = client.post(
                f"{base_url}/auth/login",
                json={"username": "admin", "password": "AdminSyntheticPass123!"},
            )
            if admin_login.status_code == 200:
                admin_token = admin_login.json().get("access_token")
                admin_headers = {"Authorization": f"Bearer {admin_token}"}

                # Check defenses state
                def_res = client.get(f"{base_url}/admin/defenses", headers=admin_headers)
                if def_res.status_code == 200:
                    defense_active = def_res.json().get("defenses", {}).get("bola", False)

                # Check logged events
                events_res = client.get(
                    f"{base_url}/admin/events?limit=10",
                    headers=admin_headers,
                )
                if events_res.status_code == 200:
                    events = events_res.json().get("events", [])
                    expected_action = "blocked" if blocked else "detected"
                    for ev in events:
                        if (
                            ev.get("owasp_category") == "API1:2023"
                            and ev.get("rule_name") == "bola_cross_tenant_access"
                            and ev.get("object_id") == str(target_item_id)
                            and ev.get("action") == expected_action
                        ):
                            detection_verified = True
                            break
        except Exception:
            detection_verified = False

        # Step 5: Construct structured outcome
        outcome = "vulnerability_exploited" if attack_success else ("attack_blocked" if blocked else "unexpected")
        result = {
            "experiment": "OWASP API1:2023 BOLA",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": base_url,
            "attacker": "alice",
            "target_object_id": target_item_id,
            "status_code": status_code,
            "detection_verified": detection_verified,
            "blocked": blocked,
            "attack_success": attack_success,
            "defense_active": defense_active,
            "outcome": outcome,
        }

        # Step 6: Persist results
        if results_path is None:
            results_path = (
                Path(__file__).resolve().parent.parent
                / "docs"
                / "results"
                / "bola_results.json"
            )

        results_path.parent.mkdir(parents=True, exist_ok=True)
        results_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

        return result
    finally:
        if close_client:
            client.close()


def main() -> None:
    """CLI entry point for running the BOLA attack experiment."""
    parser = argparse.ArgumentParser(
        description="APIShield OWASP API1:2023 BOLA Attack Experiment Script"
    )
    parser.add_argument(
        "--target",
        default="http://127.0.0.1:8000",
        help="Target base URL (default: http://127.0.0.1:8000)",
    )
    args = parser.parse_args()

    try:
        # Pre-flight check before anything else
        validate_target_url(args.target)
    except ValueError as exc:
        print(f"[REJECTED] Target validation failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print("==================================================")
    print(" APIShield BOLA Experiment Execution")
    print(f" Target: {args.target}")
    print("==================================================")

    try:
        result = run_bola_attack(args.target)
        print("\n--- Experiment Summary ---")
        print(f" HTTP Status:        {result['status_code']}")
        print(f" Outcome:            {result['outcome']}")
        print(f" Attack Success:     {result['attack_success']}")
        print(f" Blocked by Defense: {result['blocked']}")
        print(f" Detection Verified: {result['detection_verified']}")
        print(f" Defense Active:     {result['defense_active']}")
        print("==================================================")
    except Exception as exc:
        print(f"[ERROR] Experiment failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
