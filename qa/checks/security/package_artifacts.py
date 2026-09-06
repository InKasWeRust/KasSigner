#!/usr/bin/env python3
"""Package candidate hardening evidence inside the top-level target/qa tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[3]
SECURITY_ROOT = ROOT / "target/qa/security"
HARDENING_OUTPUT_ROOT = SECURITY_ROOT / "hardening"
EVIDENCE_OUTPUT = HARDENING_OUTPUT_ROOT / "kassigner-production-hardening-evidence.zip"
HEALTHY_OUTPUT = HARDENING_OUTPUT_ROOT / "kassigner-production-hardening.zip"

REQUIRED_HEALTHY_FILES = [
    SECURITY_ROOT / "current-control-evidence.json",
    SECURITY_ROOT / "invariants.json",
    SECURITY_ROOT / "irreversible-action-policy.json",
    SECURITY_ROOT / "branch-ratchets.json",
    SECURITY_ROOT / "branch-targets.json",
    SECURITY_ROOT / "test-quality.json",
    SECURITY_ROOT / "repository-test-quality.json",
    SECURITY_ROOT / "fuzz-summary.json",
    SECURITY_ROOT / "mutation-summary.json",
    SECURITY_ROOT / "crypto-mutation-summary.json",
    ROOT / "target/qa/crap/health_summary.json",
    ROOT / "target/qa/crap/run.json",
    ROOT / "target/qa/crap/lcov.info",
    ROOT / "target/qa/crap/cargo_crap.json",
    ROOT / "target/qa/crap/crap_summary.json",
    ROOT / "target/qa/crap/current.json",
]
HEALTH_JSON = [
    SECURITY_ROOT / "current-control-evidence.json",
    SECURITY_ROOT / "invariants.json",
    SECURITY_ROOT / "irreversible-action-policy.json",
    SECURITY_ROOT / "branch-ratchets.json",
    SECURITY_ROOT / "branch-targets.json",
    SECURITY_ROOT / "test-quality.json",
    SECURITY_ROOT / "repository-test-quality.json",
    SECURITY_ROOT / "fuzz-summary.json",
    SECURITY_ROOT / "mutation-summary.json",
    SECURITY_ROOT / "crypto-mutation-summary.json",
    ROOT / "target/qa/crap/health_summary.json",
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def run_directory() -> Path:
    configured = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else ROOT / path
    pointer = SECURITY_ROOT / "latest-run.json"
    if pointer.is_file():
        try:
            document = json.loads(pointer.read_text())
            path = Path(document["run_directory"])
            return path if path.is_absolute() else ROOT / path
        except (KeyError, json.JSONDecodeError, OSError):
            pass
    return SECURITY_ROOT / "latest"


def candidate_files(current_run: Path) -> list[Path]:
    files: set[Path] = set()
    for pattern in ("*.json", "*.sha256"):
        files.update(path for path in SECURITY_ROOT.glob(pattern) if path.is_file())
    crap_current = ROOT / "target/qa/crap/current.json"
    if crap_current.is_file():
        files.add(crap_current)
    crap_output = ROOT / "target/qa/crap"
    if crap_output.is_dir():
        files.update(path for path in crap_output.rglob("*") if path.is_file())
    latest_mutation = SECURITY_ROOT / "latest"
    if latest_mutation.is_dir():
        files.update(path for path in latest_mutation.rglob("*") if path.is_file())
    if current_run.is_dir():
        files.update(path for path in current_run.rglob("*") if path.is_file())
    return sorted(
        path
        for path in files
        if path not in {EVIDENCE_OUTPUT, HEALTHY_OUTPUT}
        and not path.name.endswith("production-hardening-evidence.zip.sha256")
        and not path.name.endswith("production-hardening.zip.sha256")
    )


def valid_completion(current_run: Path) -> bool:
    path = current_run / "hardening-completion.json"
    if not path.is_file():
        return False
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    supplemental = document.get("supplemental_gate")
    expected_run = relative(current_run) if current_run.is_relative_to(ROOT) else str(current_run)
    return (
        document.get("schema_version") == 1
        and document.get("healthy") is True
        and document.get("base_run_directory") == expected_run
        and isinstance(supplemental, dict)
        and supplemental.get("id") == "real-node-integration"
        and supplemental.get("status") == "pass"
    )


def validate_healthy(current_run: Path) -> list[str]:
    errors: list[str] = []
    for path in REQUIRED_HEALTHY_FILES:
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"missing or empty hardening artifact: {relative(path)}")
    for path in HEALTH_JSON:
        if not path.is_file():
            continue
        try:
            document = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            errors.append(f"invalid JSON artifact {relative(path)}: {error}")
            continue
        if document.get("healthy") is not True:
            errors.append(f"hardening artifact is not healthy: {relative(path)}")
        if path.name in {"mutation-summary.json", "crypto-mutation-summary.json"}:
            if document.get("candidate_certified") is not True:
                errors.append(
                    f"hardening mutation artifact is development-only, not fresh candidate-certified: {relative(path)}"
                )
    for name in ("mutation-results.zip", "fuzz-results.zip", "gate-results.json"):
        path = current_run / name
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"missing current-run evidence: {relative(path)}")
    gate_results = current_run / "gate-results.json"
    base_healthy = False
    if gate_results.is_file():
        try:
            base_healthy = json.loads(gate_results.read_text()).get("healthy") is True
        except json.JSONDecodeError:
            pass
    if not base_healthy and not valid_completion(current_run):
        errors.append(
            "hardening run is not healthy and has no valid supplemental sole-gate completion record"
        )
    return errors


def write_bundle(output: Path, files: list[Path], *, healthy: bool, current_run: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    manifest_files = [
        {"path": relative(path), "sha256": digest(path), "bytes": path.stat().st_size}
        for path in files
    ]
    source_sha256 = os.environ.get("KASSIGNER_SOURCE_SHA256", "").strip().lower()
    candidate_bound = len(source_sha256) == 64 and all(c in "0123456789abcdef" for c in source_sha256)
    manifest = {
        "schema_version": 4,
        "healthy": healthy,
        "hardware_in_the_loop": "deferred-by-owner",
        "evidence_is_real": True,
        "candidate_bound": candidate_bound,
        "source_sha256": source_sha256 if candidate_bound else None,
        "run_directory": relative(current_run) if current_run.is_relative_to(ROOT) else str(current_run),
        "files": manifest_files,
    }
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for path in files:
            archive.write(path, relative(path))
        archive.writestr(
            "evidence/manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
    with zipfile.ZipFile(output) as archive:
        corrupt = archive.testzip()
        if corrupt is not None:
            raise RuntimeError(f"corrupt member in hardening bundle: {corrupt}")
        archived_manifest = json.loads(archive.read("evidence/manifest.json"))
        for item in archived_manifest["files"]:
            actual = hashlib.sha256(archive.read(item["path"])).hexdigest()
            if actual != item["sha256"]:
                raise RuntimeError(f"checksum mismatch inside bundle: {item['path']}")
    checksum = output.with_suffix(output.suffix + ".sha256")
    checksum.write_text(f"{digest(output)}  {output.name}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("evidence", "healthy"), default="evidence")
    arguments = parser.parse_args()
    current_run = run_directory()
    files = candidate_files(current_run)
    if not files:
        print("ERROR: no hardening evidence is available to package")
        return 1

    if arguments.mode == "healthy":
        errors = validate_healthy(current_run)
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
        output = HEALTHY_OUTPUT
        healthy = True
    else:
        output = EVIDENCE_OUTPUT
        healthy = False
        gate_results = current_run / "gate-results.json"
        if gate_results.is_file():
            try:
                healthy = json.loads(gate_results.read_text()).get("healthy") is True
            except json.JSONDecodeError:
                healthy = False
        healthy = healthy or valid_completion(current_run)

    try:
        write_bundle(output, files, healthy=healthy, current_run=current_run)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"ERROR: hardening evidence bundle failed: {error}")
        return 1
    print(f"PASS: hardening evidence bundle: {relative(output)}")
    print(f"SHA-256: {digest(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
