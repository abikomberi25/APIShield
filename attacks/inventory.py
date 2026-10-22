"""OWASP API9:2023 Improper Inventory Management controlled attack script for APIShield.

Demonstrates that a deprecated/forgotten API route (/api/v0/items/{item_id}) is still
reachable when inventory management defenses are inactive.

Dual-run orchestration:
  Vulnerable run: deprecated_route_protection=OFF → deprecated route returns data, 'detected' event
  Defended  run: deprecated_route_protection=ON  → deprecated route returns 403, 'blocked' event

Safety constraints:
  - Target URL validated against allowlist BEFORE any network call
  - Lab mode verified BEFORE any experiment
  - Original defense toggle restored in finally block
  - Passwords and tokens are never logged or persisted in results
  - Results written only after both runs verified and state restored
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

# ---------------------------------------------------------------------------
# Allowlist — only these host:port combinations are permitted attack targets
# ---------------------------------------------------------------------------
_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
_ALLOWED_PORT: int = 8000


def _validate_target(url: str) -> None:
    """Raise ValueError if *url* is not in the local allowlist."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if host not in _ALLOWED_HOSTS or port != _ALLOWED_PORT:
        raise ValueError(
            f"Disallowed target: {url!r}. "
            f"Only {_ALLOWED_HOSTS} on port {_ALLOWED_PORT} are permitted."
        )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASE_URL = "http://127.0.0.1:8000"
DEFAULT_RESULTS_PATH = Path("docs/results/inventory_results.json")
DEPRECATED_PATH = "/api/v0/items/1"
ADMIN_USER = "admin"
ADMIN_PASSWORD = "adminpassword"
REGULAR_USER = "alice"
REGULAR_PASSWORD = "password123"


def _login(client: httpx.Client, username: str, password: str) -> str:
    """Authenticate and return an access token. Password is NOT stored."""
    resp = client.post("/auth/login", json={"username": username, "password": password})
    resp.raise_for_status()
    token: str = resp.json()["access_token"]
    return token


def _get_defenses(client: httpx.Client, token: str) -> dict[str, Any]:
    resp = client.get("/admin/defenses", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()  # type: ignore[return-value]


def _set_defense(client: httpx.Client, token: str, name: str, value: bool) -> bool:
    """Toggle a defense. Returns the confirmed value from the server."""
    resp = client.patch(
        "/admin/defenses",
        json={name: value},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    confirmed: bool = resp.json().get("defenses", {}).get(name, not value)
    if confirmed != value:
        raise RuntimeError(
            f"Defense toggle mismatch: requested {name}={value}, server returned {confirmed}"
        )
    return confirmed


def _get_events(client: httpx.Client, token: str) -> list[dict[str, Any]]:
    resp = client.get("/admin/events", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()  # type: ignore[return-value]


def _find_event(
    events: list[dict[str, Any]],
    *,
    rule: str,
    action: str,
    after_event_id: int,
) -> Optional[dict[str, Any]]:
    """Return the first matching event created AFTER *after_event_id*."""
    for ev in reversed(events):
        if ev["id"] <= after_event_id:
            continue
        if ev.get("rule_name") == rule and ev.get("action") == action:
            return ev
    return None


def _get_max_event_id(client: httpx.Client, token: str) -> int:
    events = _get_events(client, token)
    return max((e["id"] for e in events), default=0)


def run_inventory_attack(
    base_url: str,
    *,
    admin_token: str,
    user_token: str,
    defense_active: bool,
    baseline_event_id: int,
    client: httpx.Client,
) -> dict[str, Any]:
    """Run a single deprecated-route access attempt and verify the outcome.

    Returns a result dict with keys: outcome, http_status, detected, event_id.
    """
    # Access deprecated route as a regular user
    resp = client.get(
        DEPRECATED_PATH,
        headers={"Authorization": f"Bearer {user_token}"},
    )
    http_status = resp.status_code

    events = _get_events(client, admin_token)

    if defense_active:
        expected_action = "blocked"
        attack_success = False
        expected_http = 403
    else:
        expected_action = "detected"
        attack_success = True
        expected_http = 200

    matched_event = _find_event(
        events,
        rule="deprecated_route_access",
        action=expected_action,
        after_event_id=baseline_event_id,
    )

    detection_verified = matched_event is not None
    event_id: Optional[int] = matched_event["id"] if matched_event else None

    if not detection_verified:
        outcome = "unverified_detection"
    elif defense_active and http_status == 403:
        outcome = "attack_blocked"
    elif not defense_active and http_status == 200 and attack_success:
        outcome = "vulnerability_exploited"
    else:
        outcome = "unexpected"

    return {
        "defense_active": defense_active,
        "http_status": http_status,
        "attack_success": attack_success,
        "detection_verified": detection_verified,
        "outcome": outcome,
        "matched_event_id": event_id,
        "deprecated_path": DEPRECATED_PATH,
    }


def main(results_path: Path | bool = DEFAULT_RESULTS_PATH) -> int:
    """Orchestrate the dual-run API9:2023 inventory management experiment."""
    # --- Allowlist check BEFORE any network activity ---
    _validate_target(BASE_URL)

    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        # 1. Verify lab mode is enabled
        admin_token = _login(client, ADMIN_USER, ADMIN_PASSWORD)
        lab_resp = client.get(
            "/admin/lab-mode", headers={"Authorization": f"Bearer {admin_token}"}
        )
        lab_resp.raise_for_status()
        lab_data = lab_resp.json()
        if not lab_data.get("lab_mode", False):
            print("ERROR: Lab mode is not enabled. Enable it before running experiments.", file=sys.stderr)
            return 1

        # 2. Capture original toggle state
        defenses = _get_defenses(client, admin_token)
        original_protection = defenses.get("deprecated_route_protection", False)

        # 3. Get a regular user token
        user_token = _login(client, REGULAR_USER, REGULAR_PASSWORD)

        vulnerable_result: dict[str, Any] = {}
        defended_result: dict[str, Any] = {}
        restoration_error: Optional[str] = None

        try:
            # === VULNERABLE RUN (deprecated_route_protection=OFF) ===
            _set_defense(client, admin_token, "deprecated_route_protection", False)
            baseline_v = _get_max_event_id(client, admin_token)
            vulnerable_result = run_inventory_attack(
                BASE_URL,
                admin_token=admin_token,
                user_token=user_token,
                defense_active=False,
                baseline_event_id=baseline_v,
                client=client,
            )

            if vulnerable_result["outcome"] != "vulnerability_exploited":
                print(
                    f"ERROR: Vulnerable run outcome={vulnerable_result['outcome']!r} (expected 'vulnerability_exploited')",
                    file=sys.stderr,
                )
                return 1

            # === DEFENDED RUN (deprecated_route_protection=ON) ===
            _set_defense(client, admin_token, "deprecated_route_protection", True)
            baseline_d = _get_max_event_id(client, admin_token)
            defended_result = run_inventory_attack(
                BASE_URL,
                admin_token=admin_token,
                user_token=user_token,
                defense_active=True,
                baseline_event_id=baseline_d,
                client=client,
            )

            if defended_result["outcome"] != "attack_blocked":
                print(
                    f"ERROR: Defended run outcome={defended_result['outcome']!r} (expected 'attack_blocked')",
                    file=sys.stderr,
                )
                return 1

        except Exception as exc:
            print(f"ERROR during experiment: {exc}", file=sys.stderr)
            # Attempt restoration before re-raising
            try:
                _set_defense(client, admin_token, "deprecated_route_protection", original_protection)
            except Exception as restore_exc:
                restoration_error = str(restore_exc)
                print(f"ERROR: Restoration also failed: {restore_exc}", file=sys.stderr)
            return 1
        finally:
            # 4. Restore original toggle
            try:
                _set_defense(client, admin_token, "deprecated_route_protection", original_protection)
            except Exception as restore_exc:
                restoration_error = str(restore_exc)
                print(f"ERROR: Could not restore deprecated_route_protection: {restore_exc}", file=sys.stderr)

        if restoration_error:
            print(f"ERROR: State restoration failed, not writing results.", file=sys.stderr)
            return 1

        # 5. Both runs verified — write combined report
        report: dict[str, Any] = {
            "experiment": "API9:2023 Improper Inventory Management",
            "owasp_category": "API9:2023",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": BASE_URL,
            "deprecated_path": DEPRECATED_PATH,
            "runs": {
                "vulnerable": vulnerable_result,
                "defended": defended_result,
            },
            "summary": {
                "vulnerability_confirmed": vulnerable_result.get("outcome") == "vulnerability_exploited",
                "defense_effective": defended_result.get("outcome") == "attack_blocked",
            },
        }

        if results_path is not False:
            path = Path(results_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"Results written to {path}")

        print(f"Vulnerable run: {vulnerable_result['outcome']}")
        print(f"Defended  run: {defended_result['outcome']}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
