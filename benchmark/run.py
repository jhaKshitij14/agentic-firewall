"""Run the red-team suite against a fresh firewall per attack and print a report.

    python benchmark/run.py            # human-readable table
    python benchmark/run.py --json     # machine-readable
Exit code is 0 only if every attack is blocked AND every benign control is allowed.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attacks import ALL_ATTACKS  # noqa: E402
from attacks.benign import run_controls  # noqa: E402
from attacks.harness import make_env  # noqa: E402


async def run_all() -> dict:
    attack_rows = []
    for attack in ALL_ATTACKS:
        env = await make_env()  # fresh state per attack
        try:
            result = await attack.run(env)
            attack_rows.append({"name": attack.name, "blocked": result.blocked, "detail": result.detail})
        except Exception as exc:  # an attack that crashes is not counted as blocked
            attack_rows.append({"name": attack.name, "blocked": False, "detail": f"harness error: {exc!r}"})
    env = await make_env()
    control_rows = [
        {"name": b.label, "allowed": ok, "detail": detail} for b, ok, detail in await run_controls(env)
    ]
    blocked = sum(r["blocked"] for r in attack_rows)
    allowed = sum(r["allowed"] for r in control_rows)
    return {
        "attacks": attack_rows,
        "controls": control_rows,
        "blocked": blocked,
        "total_attacks": len(attack_rows),
        "detection_rate": round(100 * blocked / len(attack_rows), 1),
        "benign_allowed": allowed,
        "total_benign": len(control_rows),
        "false_positive_rate": round(100 * (len(control_rows) - allowed) / len(control_rows), 1),
    }


def print_report(report: dict) -> None:
    print("\nRED-TEAM BENCHMARK\n" + "=" * 78)
    print(f"{'Attack':<36}{'Result':<10}Detail")
    print("-" * 78)
    for r in report["attacks"]:
        print(f"{r['name']:<36}{'BLOCKED' if r['blocked'] else 'PASSED!':<10}{r['detail']}")
    print("-" * 78)
    print(f"Blocked {report['blocked']}/{report['total_attacks']}  ->  detection rate {report['detection_rate']}%")
    print("\nBENIGN CONTROLS (must be allowed)\n" + "-" * 78)
    for r in report["controls"]:
        print(f"{r['name']:<36}{'ALLOWED' if r['allowed'] else 'BLOCKED!':<10}{'' if r['allowed'] else r['detail']}")
    print("-" * 78)
    print(f"Allowed {report['benign_allowed']}/{report['total_benign']}  ->  false-positive rate {report['false_positive_rate']}%")
    print("\nNote: this measures the attacks in attacks/, written by the same author as the firewall.")
    print("It is a regression suite, not proof of security. See README 'Known limitations'.\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = asyncio.run(run_all())
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    clean = report["blocked"] == report["total_attacks"] and report["benign_allowed"] == report["total_benign"]
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
