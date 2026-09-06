#!/usr/bin/env python3
"""Enforce source-level security invariants independent of UI and coverage."""

from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "qa/contracts/security/invariants.json"
DEFAULT_OUTPUT = ROOT / "target/qa/security/invariants.json"


def load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text())
    if not isinstance(document, dict):
        raise ValueError(f"expected JSON object: {path}")
    return document


def paths_for(spec: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    if isinstance(spec.get("path"), str):
        paths.append(ROOT / spec["path"])
    for value in spec.get("paths", []):
        if isinstance(value, str):
            paths.append(ROOT / value)
    for pattern in spec.get("globs", []):
        if isinstance(pattern, str):
            paths.extend(Path(value) for value in glob.glob(str(ROOT / pattern), recursive=True))
    return sorted(set(paths))


def check_invariant(invariant: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    evidence: list[dict[str, Any]] = []
    for requirement in invariant.get("evidence", []):
        requirement_paths = paths_for(requirement)
        if not requirement_paths:
            errors.append(f"evidence path did not resolve: {requirement}")
            continue
        for path in requirement_paths:
            if not path.is_file():
                errors.append(f"missing evidence file: {path.relative_to(ROOT)}")
                continue
            text = path.read_text(errors="replace")
            missing = [term for term in requirement.get("contains", []) if term not in text]
            evidence.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "required_terms": requirement.get("contains", []),
                    "missing_terms": missing,
                }
            )
            for term in missing:
                errors.append(f"{path.relative_to(ROOT)} missing required term {term!r}")

    for prohibition in invariant.get("forbidden", []):
        for path in paths_for(prohibition):
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            present = [term for term in prohibition.get("terms", []) if term in text]
            evidence.append(
                {
                    "path": str(path.relative_to(ROOT)),
                    "forbidden_terms": prohibition.get("terms", []),
                    "present_terms": present,
                }
            )
            for term in present:
                errors.append(f"{path.relative_to(ROOT)} contains forbidden term {term!r}")

    return {
        "id": invariant.get("id"),
        "description": invariant.get("description"),
        "met": not errors,
        "errors": errors,
        "evidence": evidence,
    }


def audit(contract_path: Path = CONTRACT) -> tuple[list[str], dict[str, Any]]:
    contract = load_json(contract_path)
    if contract.get("schema_version") != 1:
        return ["unsupported security-invariant schema"], {}
    results = [check_invariant(item) for item in contract.get("invariants", [])]
    errors = [f"{item['id']}: {error}" for item in results for error in item["errors"]]
    return errors, {
        "schema_version": 1,
        "healthy": not errors,
        "invariants_total": len(results),
        "invariants_met": sum(bool(item["met"]) for item in results),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, default=CONTRACT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    try:
        errors, report = audit(arguments.contract)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: security invariant audit failed: {error}")
        return 1
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print(
        f"PASS: {report['invariants_met']}/{report['invariants_total']} "
        f"source-level security invariants are enforced"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
