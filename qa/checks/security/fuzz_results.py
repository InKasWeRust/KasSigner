#!/usr/bin/env python3
"""Persist ephemeral fuzz logs, corpus state, and crash artifacts under target/qa."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[3]
SUMMARY = ROOT / "target/qa/security/fuzz-summary.json"
LATEST = Path(
    os.environ.get(
        "KASSIGNER_SECURITY_RUN_DIR",
        str(ROOT / "target/qa/security/latest"),
    )
)
if not LATEST.is_absolute():
    LATEST = ROOT / LATEST
RAW_ZIP = LATEST / "fuzz-results.zip"
LOG_ROOT = ROOT / "target/qa/fuzz"
CRASH_ROOT = ROOT / "target/qa/fuzz/artifacts"
CORPUS_ROOT = ROOT / "target/qa/fuzz/corpus"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_statuses(path: Path) -> list[dict[str, object]]:
    targets: list[dict[str, object]] = []
    for raw in path.read_text().splitlines():
        if not raw.strip():
            continue
        name, status_text = raw.split("\t", 1)
        status = int(status_text)
        targets.append(
            {
                "name": name,
                "status": "pass" if status == 0 else "fail",
                "exit_code": status,
                "log": f"target/qa/fuzz/{name}.log",
                "artifact_directory": f"target/qa/fuzz/artifacts/{name}",
                "working_corpus_directory": f"target/qa/fuzz/corpus/{name}",
            }
        )
    return targets


ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _write_archive_file(
    output: zipfile.ZipFile, source: Path, destination: Path
) -> None:
    """Write one deterministic member without trusting filesystem mtimes."""
    info = zipfile.ZipInfo(destination.as_posix(), date_time=ZIP_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | stat.S_IMODE(source.stat().st_mode)) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    output.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def archive(summary: Path) -> str:
    RAW_ZIP.parent.mkdir(parents=True, exist_ok=True)
    RAW_ZIP.unlink(missing_ok=True)
    entries: list[tuple[Path, Path]] = []
    for root, prefix in (
        (LOG_ROOT, Path("fuzz/logs")),
        (CRASH_ROOT, Path("fuzz/artifacts")),
        (CORPUS_ROOT, Path("fuzz/corpus")),
    ):
        if root.is_dir():
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    entries.append((path, prefix / path.relative_to(root)))
    entries.append((summary, Path("fuzz/fuzz-summary.json")))
    with zipfile.ZipFile(
        RAW_ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as output:
        for source, destination in entries:
            _write_archive_file(output, source, destination)
    with zipfile.ZipFile(RAW_ZIP) as output:
        corrupt = output.testzip()
        if corrupt is not None:
            raise RuntimeError(f"corrupt fuzz artifact member: {corrupt}")
    return sha256(RAW_ZIP)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--statuses", type=Path, required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--started", required=True)
    parser.add_argument("--completed", required=True)
    budget = parser.add_mutually_exclusive_group(required=True)
    budget.add_argument("--seconds", type=int)
    budget.add_argument("--runs", type=int)
    arguments = parser.parse_args()
    if arguments.seconds is not None and arguments.seconds < 1:
        parser.error("--seconds must be positive")
    if arguments.runs is not None and arguments.runs < 1:
        parser.error("--runs must be positive")

    targets = parse_statuses(arguments.statuses)
    failed = [target["name"] for target in targets if target["status"] != "pass"]
    document = {
        "schema_version": 2,
        "healthy": not failed,
        "tool": arguments.tool,
        "started_at_utc": arguments.started,
        "completed_at_utc": arguments.completed,
        "seconds_per_target": arguments.seconds,
        "runs_per_target": arguments.runs,
        "execution_budget": {
            "mode": "seconds" if arguments.seconds is not None else "runs",
            "value": arguments.seconds if arguments.seconds is not None else arguments.runs,
        },
        "targets": targets,
        "failed_targets": failed,
        "errors": [f"fuzz target failed: {name}" for name in failed],
        "raw_artifact": str(RAW_ZIP.relative_to(ROOT)),
    }
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    LATEST.mkdir(parents=True, exist_ok=True)
    latest_summary = LATEST / "fuzz-summary.json"
    latest_summary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    digest = archive(SUMMARY)
    checksum = RAW_ZIP.with_suffix(RAW_ZIP.suffix + ".sha256")
    checksum.write_text(f"{digest}  {RAW_ZIP.name}\n")

    print(f"Persisted fuzz evidence: {RAW_ZIP.relative_to(ROOT)}")
    print(f"SHA-256: {digest}")
    if failed:
        print("ERROR: failed fuzz targets: " + ", ".join(failed))
        return 1
    print(f"PASS: {len(targets)} real fuzz targets completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
