#!/usr/bin/env python3
"""Write a reproducible manifest for one cargo-llvm-cov / cargo-crap run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def coverage_totals(path: Path) -> dict[str, dict[str, Any]]:
    totals: dict[str, dict[str, Any]] = {
        name: {"found": 0, "hit": 0}
        for name in ("lines", "functions", "branches")
    }
    prefixes = {
        "LF:": ("lines", "found"),
        "LH:": ("lines", "hit"),
        "FNF:": ("functions", "found"),
        "FNH:": ("functions", "hit"),
        "BRF:": ("branches", "found"),
        "BRH:": ("branches", "hit"),
    }
    for raw in path.read_text(errors="replace").splitlines():
        for prefix, (metric, field) in prefixes.items():
            if raw.startswith(prefix):
                try:
                    totals[metric][field] += int(raw[len(prefix) :])
                except ValueError:
                    pass
                break
    for values in totals.values():
        found = values["found"]
        hit = values["hit"]
        values["percent"] = round(hit * 100.0 / found, 4) if found else 0.0
        values["available"] = bool(found)
    return totals


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--rustc-version", required=True)
    parser.add_argument("--llvm-cov-version", required=True)
    parser.add_argument("--cargo-crap-version", required=True)
    parser.add_argument("--dev-opt-level", required=True)
    parser.add_argument("--test-opt-level", required=True)
    parser.add_argument("--lcov", type=Path, required=True)
    parser.add_argument("--cargo-crap-json", type=Path, required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--branch-requested", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve() if args.root is not None else None

    def artifact_path(path: Path) -> str:
        resolved = path.resolve()
        if root is not None:
            try:
                return resolved.relative_to(root).as_posix()
            except ValueError:
                pass
        return str(path)

    document = {
        "schema_version": 3,
        "started_at": args.started_at,
        "finished_at": args.finished_at,
        "tools": {
            "toolchain": args.toolchain,
            "rustc": args.rustc_version,
            "cargo_llvm_cov": args.llvm_cov_version,
            "cargo_crap": args.cargo_crap_version,
        },
        "coverage_profile": {
            "dev_opt_level": args.dev_opt_level,
            "test_opt_level": args.test_opt_level,
            "branch_instrumentation": args.branch_requested,
        },
        "coverage": coverage_totals(args.lcov),
        "branch_coverage_requested": args.branch_requested,
        "artifacts": {
            "lcov": {
                "path": artifact_path(args.lcov),
                "bytes": args.lcov.stat().st_size,
                "lines": sum(1 for _ in args.lcov.open(errors="replace")),
            },
            "cargo_crap_json": {
                "path": artifact_path(args.cargo_crap_json),
                "bytes": args.cargo_crap_json.stat().st_size,
            },
        },
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
