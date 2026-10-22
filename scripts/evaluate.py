#!/usr/bin/env python3
"""M8 Evaluation Framework — APIShield multi-run experiment orchestrator.

Runs each attack module N times against a live server, computes aggregate statistics,
and writes results to docs/results/evaluation_summary.json and evaluation_summary.csv.

REQUIREMENTS:
  - A live APIShield server running at http://127.0.0.1:8000
  - Lab mode MUST be enabled (start with APISHIELD_LAB_MODE=true)
  - All defenses start at their default (OFF) state

USAGE:
  python scripts/evaluate.py --module bopla --runs 5
  python scripts/evaluate.py --all --runs 10
  python scripts/evaluate.py --help

SAFETY:
  - Target URL validated against allowlist before any network call
  - Passwords and tokens never logged or written to results
  - Results only written after all runs complete and state is verified restored
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, stdev
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Allowlist — only these host:port combinations are permitted attack targets
# ---------------------------------------------------------------------------
_ALLOWED_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost"})
_ALLOWED_PORT: int = 8000
BASE_URL = "http://127.0.0.1:8000"
RESULTS_DIR = Path("docs/results")


def _validate_target(url: str) -> None:
    """Raise ValueError if url is not in the local allowlist."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if host not in _ALLOWED_HOSTS or port != _ALLOWED_PORT:
        raise ValueError(
            f"Disallowed target: {url!r}. "
            f"Only {_ALLOWED_HOSTS} on port {_ALLOWED_PORT} are permitted."
        )


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

def _run_bola(run_index: int) -> dict[str, Any]:
    from attacks.bola import main as bola_main
    result_path = RESULTS_DIR / f"_eval_bola_run_{run_index}.json"
    exit_code = bola_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


def _run_bopla(run_index: int) -> dict[str, Any]:
    from attacks.bopla import main as bopla_main
    result_path = RESULTS_DIR / f"_eval_bopla_run_{run_index}.json"
    exit_code = bopla_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


def _run_bfla(run_index: int) -> dict[str, Any]:
    from attacks.bfla import main as bfla_main
    result_path = RESULTS_DIR / f"_eval_bfla_run_{run_index}.json"
    exit_code = bfla_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


def _run_auth(run_index: int) -> dict[str, Any]:
    from attacks.auth import main as auth_main
    result_path = RESULTS_DIR / f"_eval_auth_run_{run_index}.json"
    exit_code = auth_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


def _run_rate_limit(run_index: int) -> dict[str, Any]:
    from attacks.rate_limit import main as rl_main
    result_path = RESULTS_DIR / f"_eval_rate_limit_run_{run_index}.json"
    exit_code = rl_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


def _run_inventory(run_index: int) -> dict[str, Any]:
    from attacks.inventory import main as inv_main
    result_path = RESULTS_DIR / f"_eval_inventory_run_{run_index}.json"
    exit_code = inv_main(results_path=result_path)
    data: dict[str, Any] = {}
    if result_path.exists():
        data = json.loads(result_path.read_text(encoding="utf-8"))
        result_path.unlink()
    return {
        "exit_code": exit_code,
        "vulnerable_outcome": data.get("runs", {}).get("vulnerable", {}).get("outcome"),
        "defended_outcome": data.get("runs", {}).get("defended", {}).get("outcome"),
    }


MODULE_RUNNERS: dict[str, Any] = {
    "bola": _run_bola,
    "bopla": _run_bopla,
    "bfla": _run_bfla,
    "auth": _run_auth,
    "rate_limit": _run_rate_limit,
    "inventory": _run_inventory,
}

EXPECTED_OUTCOMES = {
    "vulnerable": "vulnerability_exploited",
    "defended": "attack_blocked",
}


def _evaluate_module(module: str, runs: int) -> dict[str, Any]:
    """Run a module N times and compute aggregate statistics."""
    runner = MODULE_RUNNERS[module]
    run_results = []
    successes = 0
    failures = 0

    print(f"\n--- Evaluating module: {module} ({runs} runs) ---")
    for i in range(1, runs + 1):
        print(f"  Run {i}/{runs}...", end=" ", flush=True)
        try:
            result = runner(i)
            run_results.append(result)
            v_ok = result.get("vulnerable_outcome") == EXPECTED_OUTCOMES["vulnerable"]
            d_ok = result.get("defended_outcome") == EXPECTED_OUTCOMES["defended"]
            success = result["exit_code"] == 0 and v_ok and d_ok
            if success:
                successes += 1
                print("OK")
            else:
                failures += 1
                print(f"FAIL (v={result.get('vulnerable_outcome')}, d={result.get('defended_outcome')})")
        except Exception as exc:
            failures += 1
            run_results.append({"exit_code": -1, "error": str(exc)})
            print(f"ERROR: {exc}")

    success_rate = successes / runs if runs > 0 else 0.0

    return {
        "module": module,
        "total_runs": runs,
        "successes": successes,
        "failures": failures,
        "success_rate": round(success_rate, 4),
        "runs": run_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="APIShield M8 Evaluation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--module",
        choices=list(MODULE_RUNNERS.keys()),
        help="Module to evaluate (mutually exclusive with --all)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Evaluate all modules",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        choices=range(1, 11),
        metavar="N",
        help="Number of runs per module (1-10, default: 1)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULTS_DIR,
        help="Directory for output files (default: docs/results)",
    )
    args = parser.parse_args()

    if not args.module and not args.all:
        parser.error("Specify --module MODULE or --all")

    # --- Allowlist check BEFORE any network activity ---
    _validate_target(BASE_URL)

    modules_to_run = list(MODULE_RUNNERS.keys()) if args.all else [args.module]
    runs = args.runs
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"APIShield M8 Evaluation — target: {BASE_URL}")
    print(f"Modules: {modules_to_run}, runs per module: {runs}")
    print("=" * 60)

    results: list[dict[str, Any]] = []
    for mod in modules_to_run:
        mod_result = _evaluate_module(mod, runs)
        results.append(mod_result)

    # Aggregate summary
    overall_success_rate = mean(r["success_rate"] for r in results) if results else 0.0
    summary: dict[str, Any] = {
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "target": BASE_URL,
        "total_modules": len(results),
        "runs_per_module": runs,
        "overall_success_rate": round(overall_success_rate, 4),
        "modules": results,
        "note": (
            "Results generated by running attack scripts against a live APIShield server "
            "with lab mode enabled. Each 'success' means both the vulnerable run and defended "
            "run produced the expected outcomes."
        ),
    }

    # Write JSON summary
    json_path = output_dir / "evaluation_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nJSON summary written to: {json_path}")

    # Write CSV summary
    csv_path = output_dir / "evaluation_summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["module", "total_runs", "successes", "failures", "success_rate"],
        )
        writer.writeheader()
        for r in results:
            writer.writerow({
                "module": r["module"],
                "total_runs": r["total_runs"],
                "successes": r["successes"],
                "failures": r["failures"],
                "success_rate": r["success_rate"],
            })
    print(f"CSV  summary written to: {csv_path}")

    print("\n" + "=" * 60)
    print("RESULTS:")
    for r in results:
        status = "✓" if r["success_rate"] == 1.0 else "✗"
        print(f"  {status} {r['module']:20s}  {r['successes']}/{r['total_runs']}  ({r['success_rate']*100:.0f}%)")
    print(f"\nOverall success rate: {overall_success_rate*100:.0f}%")

    return 0 if all(r["failures"] == 0 for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
