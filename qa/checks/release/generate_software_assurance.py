#!/usr/bin/env python3
"""Create release-bound software-assurance evidence from real scanner outputs."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

_RELEASE_DIR = Path(__file__).resolve().parent
if str(_RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(_RELEASE_DIR))

from readiness.model import SHA256_RE, sha256_file  # noqa: E402
from readiness.signatures import sign_detached  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
SCAN_FILES = ("cargo-deny.txt", "sbom.cdx.json", "osv.json")
LOCKFILES = (
    "Cargo.lock",
    "external/rqrr-nostd/Cargo.lock",
    "apps/kassee-web/Cargo.lock",
    "apps/signer-firmware/Cargo.lock",
    "qa/Cargo.lock",
    "tools/Cargo.lock",
)
TOOLS = ("cargo-deny", "syft", "osv-scanner")


def descriptor(path: Path, evidence_dir: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(evidence_dir).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def tool_version(tool: str) -> str:
    result = subprocess.run([tool, "--version"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise ValueError(f"cannot read {tool} version")
    value = (result.stdout or result.stderr).strip().splitlines()
    if not value:
        raise ValueError(f"{tool} returned an empty version string")
    return value[0]


def create(arguments: argparse.Namespace) -> Path:
    for label, value in (("source", arguments.source_sha256), ("release artifact", arguments.release_artifact_sha256)):
        if not SHA256_RE.fullmatch(value):
            raise ValueError(f"{label} SHA-256 must be 64 lowercase hex characters")
    evidence_dir = arguments.evidence_dir.resolve()
    software_dir = evidence_dir / "software"
    software_dir.mkdir(parents=True, exist_ok=True)
    files: dict[str, object] = {}
    for name in SCAN_FILES:
        path = software_dir / name
        if not path.is_file():
            raise ValueError(f"missing software-assurance scanner output: {path}")
        files[name] = descriptor(path, evidence_dir)
    lock_dir = software_dir / "lockfiles"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lockfiles: dict[str, object] = {}
    for relative in LOCKFILES:
        source = ROOT / relative
        if not source.is_file():
            raise ValueError(f"missing release lockfile: {relative}")
        destination = lock_dir / relative.replace("/", "__")
        shutil.copyfile(source, destination)
        lockfiles[relative] = descriptor(destination, evidence_dir)
    report = {
        "schema": 2,
        "status": "pass",
        "source_sha256": arguments.source_sha256,
        "release_artifact_sha256": arguments.release_artifact_sha256,
        "signer_key_id": arguments.signer_key_id,
        "tool_versions": {tool: tool_version(tool) for tool in TOOLS},
        "files": files,
        "lockfiles": lockfiles,
    }
    output = evidence_dir / "software_assurance.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    sign_detached(output, arguments.signing_key)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--release-artifact-sha256", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        output = create(arguments)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"PASS: release-bound software assurance written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
