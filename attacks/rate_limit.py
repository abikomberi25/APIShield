"""OWASP API4:2023 Unrestricted Resource Consumption — controlled attack script.

Executes a bounded burst of synthetic requests to demonstrate and measure
rate-limit behavior with defenses OFF and ON. Strictly local-only targets.
Never logs passwords, tokens, or Authorization headers.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Any, Optional, Union
from urllib.parse import urlparse
import httpx

ALLOWED_SCHEMES = {"http"}
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "api"}
ALLOWED_PORTS = {8000}

# Bounded experiment constants — hard limits prevent uncontrolled traffic generation
MAX_BURST_REQUESTS = 50    # hard cap on total malicious requests per run
MAX_LEGIT_REQUESTS = 10    # hard cap on total legitimate requests per run
TARGET_BURST = 25          # burst count for the experiment (must be <= MAX_BURST_REQUESTS)
LEGIT_COUNT = 5            # legitimate requests to test false-positive rate


def validate_target_url(target_url: str) -> str:
    """Validate target URL against hardcoded local security allowlist.

    Must be called before making any network requests.
    Raises ValueError if the target is not explicitly allowed.
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("Target URL must be a non-empty string.")

    parsed = urlparse(target_url.strip())

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Disallowed scheme '{parsed.scheme}'. Only 'http' is allowed."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname or hostname not in ALLOWED_HOSTS:
        raise ValueError(
            f"Disallowed target host '{hostname}'. Allowed: {sorted(ALLOWED_HOSTS)}."
        )

    port = parsed.port
    if port is None or port not in ALLOWED_PORTS:
        raise ValueError(
            f"Disallowed or missing port '{port}'. Allowed: {sorted(ALLOWED_PORTS)}."
        )

    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials in target URL are prohibited.")

    if parsed.query or parsed.fragment:
        raise ValueError("Target URL must not contain query strings or fragments.")

    return f"{parsed.scheme}://{hostname}:{port}"


def run_rate_limit_attack(
    target_url: str,
    burst_count: int = TARGET_BURST,
    results_path: Optional[Union[Path, bool]] = None,
    client: Optional[httpx.Client] = None,
) -> dict[str, Any]:
    """Execute controlled rate-limit experiment: burst requests then measure outcomes.

    Steps:
    1. Validate target URL (allowlist enforcement before any network call).
    2. Authenticate as synthetic attacker 'alice'.
    3. Record event baseline.
    4. Fire burst_count requests to /items/1 (bounded, no more than MAX_BURST_REQUESTS).
    5. Classify each response: 200 (allowed), 429 (rate-limited), other (unexpected).
    6. Verify detection event in /admin/events.
    7. Return structured result dict.
    """
    if burst_count > MAX_BURST_REQUESTS:
        raise ValueError(
            f"burst_count {burst_count} exceeds safety limit {MAX_BURST_REQUESTS}."
        )

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
        baseline_res = client.get(
            f"{base_url}/admin/events?limit=1", headers=admin_headers
        )
        if baseline_res.status_code == 200:
            evs = baseline_res.json().get("events", [])
            if evs:
                latest_id_before = evs[0].get("id", 0)

        # Current defense state
        def_res = client.get(f"{base_url}/admin/defenses", headers=admin_headers)
        defense_active = False
        if def_res.status_code == 200:
            defense_active = def_res.json().get("defenses", {}).get("rate_limit", False)

        # Authenticate attacker
        alice_login = client.post(
            f"{base_url}/auth/login",
            json={"username": "alice", "password": "AliceSyntheticPass123!"},
        )
        if alice_login.status_code != 200:
            raise RuntimeError(f"Alice auth failed: HTTP {alice_login.status_code}")
        alice_token = alice_login.json().get("access_token")
        alice_id = alice_login.json().get("user", {}).get("id")
        if not alice_token:
            raise RuntimeError("Alice login missing access_token.")
        alice_headers = {"Authorization": f"Bearer {alice_token}"}

        # Execute bounded burst
        results_200 = 0
        results_429 = 0
        results_other = 0
        latencies_ms: list[float] = []

        for _ in range(burst_count):
            t_start = time.perf_counter()
            resp = client.get(f"{base_url}/items/1", headers=alice_headers)
            latency_ms = (time.perf_counter() - t_start) * 1000.0
            latencies_ms.append(latency_ms)

            if resp.status_code == 200:
                results_200 += 1
            elif resp.status_code == 429:
                results_429 += 1
            else:
                results_other += 1

        # Verify detection event
        detection_verified = False
        matched_event_id: Optional[int] = None
        expected_action = "blocked" if defense_active else "detected"

        try:
            events_res = client.get(
                f"{base_url}/admin/events?limit=50", headers=admin_headers
            )
            if events_res.status_code == 200:
                post_events = events_res.json().get("events", [])
                for ev in post_events:
                    if (
                        ev.get("id", 0) > latest_id_before
                        and ev.get("owasp_category") == "API4:2023"
                        and ev.get("rule_name") == "rate_limit_exceeded"
                        and ev.get("action") == expected_action
                    ):
                        detection_verified = True
                        matched_event_id = ev.get("id")
                        break
        except Exception:
            detection_verified = False

        total = burst_count
        attack_success_rate = results_200 / total if total > 0 else 0.0
        block_rate = results_429 / total if total > 0 else 0.0

        if defense_active and results_429 > 0 and detection_verified:
            outcome = "attack_blocked"
        elif not defense_active and results_200 == total and detection_verified:
            outcome = "vulnerability_exploited"
        elif not defense_active and results_200 == total and not detection_verified:
            outcome = "unverified_detection"
        else:
            outcome = "unexpected"

        sorted_lat = sorted(latencies_ms)
        p50_idx = int(len(sorted_lat) * 0.50)
        p95_idx = int(len(sorted_lat) * 0.95)
        p50_ms = sorted_lat[p50_idx] if sorted_lat else 0.0
        p95_ms = sorted_lat[min(p95_idx, len(sorted_lat) - 1)] if sorted_lat else 0.0

        result = {
            "experiment": "OWASP API4:2023 Unrestricted Resource Consumption",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": base_url,
            "attacker": "alice",
            "defense_active": defense_active,
            "burst_count": burst_count,
            "results_200_allowed": results_200,
            "results_429_limited": results_429,
            "results_other": results_other,
            "attack_success_rate": round(attack_success_rate, 4),
            "block_rate": round(block_rate, 4),
            "detection_verified": detection_verified,
            "matched_event_id": matched_event_id,
            "outcome": outcome,
            "latency_p50_ms": round(p50_ms, 2),
            "latency_p95_ms": round(p95_ms, 2),
        }

        if results_path is not False and outcome in ("vulnerability_exploited", "attack_blocked"):
            if results_path is None:
                results_path = (
                    Path(__file__).resolve().parent.parent
                    / "docs" / "results" / "rate_limit_results.json"
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
    """CLI entry point: dual-run rate-limit experiment (defense OFF then ON).

    Run 1 — rate_limit OFF: burst requests all succeed, events detected only.
    Run 2 — rate_limit ON: burst requests rate-limited after threshold, events blocked.
    Restores original toggle in a finally block.
    Never prints or persists tokens or credentials.
    """
    if target_url is None:
        parser = argparse.ArgumentParser(
            description="APIShield OWASP API4:2023 Rate Limit Experiment"
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
    print(" APIShield Rate Limit Experiment Execution")
    print(f" Target: {target_to_use}")
    print("==================================================")

    base_url = target_to_use.rstrip("/")

    if results_path is None:
        target_results_path: Union[Path, bool] = (
            Path(__file__).resolve().parent.parent
            / "docs" / "results" / "rate_limit_results.json"
        )
    else:
        target_results_path = results_path

    close_client = False
    if client is None:
        client = httpx.Client(timeout=10.0)
        close_client = True

    try:
        # Admin auth for toggle management
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

        # Capture original toggle
        def_res = client.get(f"{base_url}/admin/defenses", headers=admin_headers)
        if def_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch defenses: HTTP {def_res.status_code}")
        defenses = def_res.json().get("defenses", {})
        if "rate_limit" not in defenses:
            raise RuntimeError("rate_limit defense toggle not found in defenses.")
        original_rate_limit = defenses["rate_limit"]

        restoration_succeeded = False

        try:
            # --- Run 1: rate_limit OFF (vulnerable) ---
            print("\n[Run 1] Setting rate_limit OFF (vulnerable mode)...")
            patch_off = client.patch(
                f"{base_url}/admin/defenses",
                json={"rate_limit": False},
                headers=admin_headers,
            )
            if (
                patch_off.status_code != 200
                or patch_off.json().get("defenses", {}).get("rate_limit") is not False
            ):
                raise RuntimeError(
                    f"Failed to set rate_limit=False: HTTP {patch_off.status_code}"
                )

            result_off = run_rate_limit_attack(
                target_url=target_to_use, results_path=False, client=client
            )
            if (
                result_off.get("outcome") != "vulnerability_exploited"
                or not result_off.get("detection_verified")
            ):
                raise RuntimeError(
                    f"Run 1 failed verification: got outcome={result_off.get('outcome')!r}, "
                    f"detection_verified={result_off.get('detection_verified')!r}"
                )

            # --- Run 2: rate_limit ON (defended) ---
            print("\n[Run 2] Setting rate_limit ON (defended mode)...")
            patch_on = client.patch(
                f"{base_url}/admin/defenses",
                json={"rate_limit": True},
                headers=admin_headers,
            )
            if (
                patch_on.status_code != 200
                or patch_on.json().get("defenses", {}).get("rate_limit") is not True
            ):
                raise RuntimeError(
                    f"Failed to set rate_limit=True: HTTP {patch_on.status_code}"
                )

            result_on = run_rate_limit_attack(
                target_url=target_to_use, results_path=False, client=client
            )
            if (
                result_on.get("outcome") != "attack_blocked"
                or not result_on.get("detection_verified")
            ):
                raise RuntimeError(
                    f"Run 2 failed verification: got outcome={result_on.get('outcome')!r}, "
                    f"detection_verified={result_on.get('detection_verified')!r}"
                )

        finally:
            # Always restore original rate_limit state
            try:
                restore_res = client.patch(
                    f"{base_url}/admin/defenses",
                    json={"rate_limit": original_rate_limit},
                    headers=admin_headers,
                )
                restored_val = (
                    restore_res.json().get("defenses", {}).get("rate_limit")
                    if restore_res.status_code == 200
                    else None
                )
                if (
                    restore_res.status_code != 200
                    or restored_val != original_rate_limit
                ):
                    print(
                        f"[WARNING] Failed to restore rate_limit defense state "
                        f"(HTTP {restore_res.status_code}, "
                        f"rate_limit={restored_val}, expected={original_rate_limit}). "
                        "The server's rate_limit defense state may be unresolved.",
                        file=sys.stderr,
                    )
                else:
                    restoration_succeeded = True
            except Exception as restore_exc:
                print(
                    f"[WARNING] Exception during rate_limit defense restoration: "
                    f"{restore_exc}. "
                    "The server's rate_limit defense state may be unresolved.",
                    file=sys.stderr,
                )

        if not restoration_succeeded:
            raise RuntimeError(
                "rate_limit defense state was not confirmed as restored. "
                "Combined results not written."
            )

        combined = {
            "experiment": "OWASP API4:2023 Unrestricted Resource Consumption",
            "timestamp": result_on["timestamp"],
            "target": result_on["target"],
            "attacker": "alice",
            "burst_count": result_on["burst_count"],
            "vulnerable_run": {
                "defense_active": result_off["defense_active"],
                "results_200_allowed": result_off["results_200_allowed"],
                "results_429_limited": result_off["results_429_limited"],
                "attack_success_rate": result_off["attack_success_rate"],
                "block_rate": result_off["block_rate"],
                "detection_verified": result_off["detection_verified"],
                "matched_event_id": result_off["matched_event_id"],
                "outcome": result_off["outcome"],
                "latency_p50_ms": result_off["latency_p50_ms"],
                "latency_p95_ms": result_off["latency_p95_ms"],
            },
            "defended_run": {
                "defense_active": result_on["defense_active"],
                "results_200_allowed": result_on["results_200_allowed"],
                "results_429_limited": result_on["results_429_limited"],
                "attack_success_rate": result_on["attack_success_rate"],
                "block_rate": result_on["block_rate"],
                "detection_verified": result_on["detection_verified"],
                "matched_event_id": result_on["matched_event_id"],
                "outcome": result_on["outcome"],
                "latency_p50_ms": result_on["latency_p50_ms"],
                "latency_p95_ms": result_on["latency_p95_ms"],
            },
        }

        if target_results_path is not False:
            assert isinstance(target_results_path, Path)
            target_results_path.parent.mkdir(parents=True, exist_ok=True)
            target_results_path.write_text(
                json.dumps(combined, indent=2), encoding="utf-8"
            )
            print(f" Results written to: {target_results_path}")

        print("\n--- Experiment Summary ---")
        print(
            f" [Vulnerable] {result_off['results_200_allowed']}/{result_off['burst_count']} allowed | "
            f"{result_off['outcome']} | detection_verified={result_off['detection_verified']}"
        )
        print(
            f" [Defended]   {result_on['results_429_limited']}/{result_on['burst_count']} limited | "
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
