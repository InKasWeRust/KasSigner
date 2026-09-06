#!/usr/bin/env python3
"""Validate and package one pinned-nightly branch-coverage artifact bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import zipfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("target/qa/crap"),
        help="Generated CRAP artifact directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("target/qa/kassigner-branch-coverage.zip"),
        help="Destination ZIP",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate persisted branch records without creating the ZIP",
    )
    return parser.parse_args()


def require_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"required branch-coverage artifact is missing or empty: {path}")


def validate_manifest(input_dir: Path) -> dict:
    run_path = input_dir / "run.json"
    lcov_path = input_dir / "lcov.info"
    require_file(run_path)
    require_file(lcov_path)
    document = json.loads(run_path.read_text(encoding="utf-8"))
    branches = document.get("coverage", {}).get("branches", {})
    if document.get("branch_coverage_requested") is not True:
        raise ValueError("run.json does not record a requested branch-coverage run")
    if branches.get("available") is not True:
        raise ValueError("run.json says LLVM branch records are unavailable")
    if int(branches.get("found", 0)) <= 0:
        raise ValueError("run.json contains no persisted LLVM branch records")
    branch_lines = [
        line
        for line in lcov_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.startswith("BRF:")
    ]
    if not branch_lines:
        raise ValueError("lcov.info contains no BRF records")

    print("Requested:", document.get("branch_coverage_requested"))
    print("Available:", branches.get("available"))
    print("Found:", branches.get("found"))
    print("Hit:", branches.get("hit"))
    print("Percent:", branches.get("percent"))
    print("First BRF records:")
    for line in branch_lines[:5]:
        print(line)
    return document


REQUIRED_ARTIFACTS = (
    "run.json",
    "lcov.info",
    "cargo_crap.json",
    "current.json",
    "crap_summary.json",
    "health_summary.json",
    "coverage_run.txt",
    "crap_run.txt",
    "crap_report_prod.txt",
    "browser_recovery/summary.json",
    "browser_recovery/v8-coverage.json",
    "browser_recovery/report.txt",
    "web_runtime/summary.json",
    "web_runtime/v8-coverage.json",
    "web_runtime/report.txt",
)


def verify_archive(output: Path) -> None:
    require_file(output)
    required_members = {f"crap/{relative}" for relative in REQUIRED_ARTIFACTS}
    with zipfile.ZipFile(output) as archive:
        corrupt = archive.testzip()
        if corrupt is not None:
            raise ValueError(f"corrupt branch-coverage ZIP member: {corrupt}")
        names = set(archive.namelist())
    missing = sorted(required_members - names)
    if missing:
        raise ValueError(
            "branch-coverage ZIP is missing: " + ", ".join(missing)
        )
    print(f"Validated {output} ({output.stat().st_size} bytes)")


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output = args.output.resolve()
    validate_manifest(input_dir)
    if args.validate_only:
        return 0

    for relative in REQUIRED_ARTIFACTS:
        require_file(input_dir / relative)

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(input_dir.rglob("*")):
            if path.is_file():
                archive.write(path, Path("crap") / path.relative_to(input_dir))
    verify_archive(output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"ERROR: {error}")
        raise SystemExit(2)
