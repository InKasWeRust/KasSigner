#!/usr/bin/env python3
"""Persist and enforce critical-domain branch ratchets and hardening targets."""

from __future__ import annotations

import argparse
import json
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "qa/checks/quality/crap/policy.json"
BASELINE = ROOT / "target/qa/crap/health_summary.json"
RATCHET_OUTPUT = ROOT / "target/qa/security/branch-ratchets.json"
TARGET_OUTPUT = ROOT / "target/qa/security/branch-targets.json"
LCOV = ROOT / "target/qa/crap/lcov.info"


def audit(require_target: bool = False) -> tuple[list[str], dict[str, Any]]:
    policy = json.loads(POLICY.read_text())["health"]["critical_domains"]
    baseline = json.loads(BASELINE.read_text())
    errors: list[str] = []
    domains: dict[str, Any] = {}
    for name, config in policy.items():
        observed = baseline["critical_domains"][name]["metrics"]["branches"]
        actual = float(observed["percent"])
        floor = float(config["minimum_branch_coverage_percent"])
        target = float(config["target_branch_coverage_percent"])
        available = bool(observed["available"]) and int(observed["found"]) > 0
        floor_met = available and actual >= floor
        target_met = available and actual >= target
        met = target_met if require_target else floor_met
        if not floor_met:
            errors.append(
                f"{name} branch coverage {actual:.2f}% is below ratchet {floor:.2f}%"
            )
        elif require_target and not target_met:
            errors.append(
                f"{name} branch coverage {actual:.2f}% is below hardening target {target:.2f}%"
            )
        domains[name] = {
            "label": config["label"],
            "actual_percent": actual,
            "minimum_percent": floor,
            "target_percent": target,
            "branches_found": int(observed["found"]),
            "branches_hit": int(observed["hit"]),
            "floor_met": floor_met,
            "target_met": target_met,
            "met": met,
            "gap_to_target_percent": round(max(0.0, target - actual), 4),
        }
    document = {
        "schema_version": 2,
        "healthy": not errors,
        "mode": "hardening-target" if require_target else "regression-ratchet",
        "source": "last persisted real pinned-nightly branch run",
        "policy": (
            "all critical domains must reach their hardening targets"
            if require_target
            else "ratchets may increase but must never decrease"
        ),
        "domains": domains,
        "errors": errors,
    }
    return errors, document


def _normalize_lcov_path(raw: str) -> str:
    normalized = raw.replace("\\", "/").removeprefix("./")
    for marker in ("/crates/", "/apps/", "/qa/", "/tools/", "/external/"):
        if marker in normalized:
            return marker[1:] + normalized.rsplit(marker, 1)[1]
    legacy_marker = "/kassigner/"
    if legacy_marker in normalized:
        return normalized.split(legacy_marker, 1)[1]
    return normalized


def _uncovered_domain_branches(name: str) -> list[str]:
    """Return concrete uncovered LCOV branch identities for one critical domain."""
    if not LCOV.is_file():
        return []
    policy = json.loads(POLICY.read_text())["health"]["critical_domains"]
    config = policy.get(name, {})
    patterns = config.get("paths", []) if isinstance(config, dict) else []
    if not isinstance(patterns, list):
        return []
    current: str | None = None
    missing: set[str] = set()
    for raw in LCOV.read_text(errors="replace").splitlines():
        if raw.startswith("SF:"):
            current = _normalize_lcov_path(raw[3:])
            continue
        if raw == "end_of_record":
            current = None
            continue
        if current is None or not any(fnmatch(current, pattern) for pattern in patterns):
            continue
        if not raw.startswith("BRDA:"):
            continue
        fields = raw[5:].split(",")
        if len(fields) < 4 or fields[3] not in {"-", "0"}:
            continue
        missing.add(f"{current}:{fields[0]}:{fields[1]}:{fields[2]}")
    return sorted(missing)


def _print_target_branch_diagnostics(document: dict[str, Any]) -> None:
    domains = document.get("domains", {})
    if not isinstance(domains, dict):
        return
    for name, result in domains.items():
        if not isinstance(result, dict) or result.get("target_met"):
            continue
        missing = _uncovered_domain_branches(name)
        if not missing:
            continue
        print(f"Uncovered {name} LCOV branches ({len(missing)}):")
        for identity in missing[:20]:
            print(f"  {identity}")
        if len(missing) > 20:
            print(f"  ... and {len(missing) - 20} more")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-target", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or (TARGET_OUTPUT if args.require_target else RATCHET_OUTPUT)
    try:
        errors, document = audit(args.require_target)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: branch policy cannot be evaluated: {error}")
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        if args.require_target:
            _print_target_branch_diagnostics(document)
        return 1
    label = "hardening targets" if args.require_target else "ratchets"
    print(f"PASS: {len(document['domains'])} critical-domain branch {label} are met")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
