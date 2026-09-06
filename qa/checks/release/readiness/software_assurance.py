"""Release-bound verification of dependency, SBOM, advisory, and license evidence."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import verify_descriptor

REQUIRED_FILES = ("cargo-deny.txt", "sbom.cdx.json", "osv.json")
REQUIRED_TOOLS = ("cargo-deny", "syft", "osv-scanner")
REQUIRED_LOCKFILES = (
    "Cargo.lock",
    "external/rqrr-nostd/Cargo.lock",
    "apps/kassee-web/Cargo.lock",
    "apps/signer-firmware/Cargo.lock",
    "qa/Cargo.lock",
    "tools/Cargo.lock",
)


def verify(evidence_dir: Path, document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    tool_versions = document.get("tool_versions")
    if not isinstance(tool_versions, dict):
        errors.append("software_assurance.json: tool_versions must be an object")
    else:
        for tool in REQUIRED_TOOLS:
            value = tool_versions.get(tool)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"software_assurance.json: missing non-empty version for {tool}")
    files = document.get("files")
    if not isinstance(files, dict):
        return errors + ["software_assurance.json: files must be an object"]
    for name in REQUIRED_FILES:
        _, descriptor_errors = verify_descriptor(
            evidence_dir, files.get(name), f"software_assurance.json: {name}"
        )
        errors.extend(descriptor_errors)
    lockfiles = document.get("lockfiles")
    if not isinstance(lockfiles, dict):
        errors.append("software_assurance.json: lockfiles must bind the release lockfiles")
    else:
        missing = sorted(set(REQUIRED_LOCKFILES) - set(lockfiles))
        unexpected = sorted(set(lockfiles) - set(REQUIRED_LOCKFILES))
        if missing:
            errors.append(f"software_assurance.json: missing release lockfiles: {', '.join(missing)}")
        if unexpected:
            errors.append(f"software_assurance.json: unexpected lockfiles: {', '.join(unexpected)}")
        for name in REQUIRED_LOCKFILES:
            _, descriptor_errors = verify_descriptor(
                evidence_dir, lockfiles.get(name), f"software_assurance.json: lockfile {name}"
            )
            errors.extend(descriptor_errors)
    return errors
