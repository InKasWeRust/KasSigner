#!/usr/bin/env python3
"""Measure the repository against the complete healthy-codebase contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
CHECK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CHECK_DIR))

from lcov_metrics import parse_lcov  # noqa: E402
from health_audit import audit_health  # noqa: E402



def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} cannot be read: {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return document


def render_summary(document: dict[str, Any]) -> str:
    criteria = document.get("criteria", {})
    host = document.get("host_metrics", {})
    lines = [
        "HEALTHY" if document.get("healthy") else "NOT HEALTHY",
        (
            "Production: "
            f"{criteria.get('production_crap_failures', {}).get('actual', 0)} effective failures; "
            f"{criteria.get('production_warnings', {}).get('actual', 0)} effective warnings"
        ),
        (
            "Assessment: "
            f"{document.get('production_assessment', {}).get('crap_functions', 0)} CRAP-scored; "
            f"{document.get('production_assessment', {}).get('source_complexity_functions', 0)} "
            "coverage-unavailable functions source-scored"
        ),
        (
            "Host coverage: "
            f"lines {host.get('lines', {}).get('percent', 0.0):.2f}%; "
            f"functions {host.get('functions', {}).get('percent', 0.0):.2f}%; "
            f"branches {host.get('branches', {}).get('percent', 0.0):.2f}%"
        ),
        (
            "Web runtime mapping: "
            f"{criteria.get('web_runtime_trace_mapping', {}).get('actual', 0.0):.2f}% "
            f"({'measured' if criteria.get('web_runtime_trace_mapping', {}).get('met') else 'incomplete'})"
        ),
        (
            "Browser recovery: "
            f"lines {document.get('critical_domains', {}).get('wallet_recovery', {}).get('supplemental', {}).get('line_percent', 0.0):.2f}%; "
            f"functions {document.get('critical_domains', {}).get('wallet_recovery', {}).get('supplemental', {}).get('function_percent', 0.0):.2f}%; "
            f"branches {document.get('critical_domains', {}).get('wallet_recovery', {}).get('supplemental', {}).get('branch_percent', 0.0):.2f}%; "
            f"{'measured' if document.get('critical_domains', {}).get('wallet_recovery', {}).get('supplemental', {}).get('complete') else 'missing or incomplete'}"
        ),
        (
            "Pure firmware models: "
            f"{criteria.get('pure_firmware_models', {}).get('actual', 0)}/"
            f"{criteria.get('pure_firmware_models', {}).get('target', 0)} measured"
        ),
        (
            "Board adapters: "
            f"{criteria.get('board_adapters_above_cc_limit', {}).get('actual', 0)} "
            "above the CC limit"
        ),
        (
            "Branch coverage: "
            f"{'present' if criteria.get('branch_coverage', {}).get('met') else 'missing'}"
        ),
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--run-manifest", type=Path, required=True)
    parser.add_argument(
        "--browser-recovery-coverage",
        type=Path,
        help="persisted KasSee browser recovery coverage summary",
    )
    parser.add_argument(
        "--web-runtime-coverage",
        type=Path,
        help="persisted all-module KasSee runtime V8 coverage summary",
    )
    parser.add_argument("--policy", type=Path, default=CHECK_DIR / "policy.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strict", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = _load(args.report, "classified CRAP report")
        run_manifest = _load(args.run_manifest, "coverage run manifest")
        policy = _load(args.policy, "CRAP policy")
        records = parse_lcov(args.lcov)
        supplemental: dict[str, dict[str, Any]] = {}
        if args.browser_recovery_coverage is not None:
            supplemental["browser_recovery"] = _load(
                args.browser_recovery_coverage, "browser recovery coverage"
            )
        if args.web_runtime_coverage is not None:
            supplemental["web_runtime"] = _load(
                args.web_runtime_coverage, "web runtime coverage"
            )
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}")
        return 1

    errors, document = audit_health(
        report, records, run_manifest, policy, supplemental
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(render_summary(document))
    if args.strict and errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
