"""Independent-builder manifest verification and final-manifest convergence."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import SHA256_RE, load_object, sha256_file, verify_descriptor


def artifact_hashes(manifest: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    if manifest.get("format_version") != 1:
        errors.append("artifact manifest format_version must be 1")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return {}, errors + ["artifact manifest must contain a non-empty artifacts array"]
    hashes: dict[str, str] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            errors.append("artifact manifest entries must be objects")
            continue
        name, digest, size = item.get("file"), item.get("sha256"), item.get("size")
        if not isinstance(name, str) or not name or "/" in name or "\\" in name:
            errors.append("artifact manifest file names must be simple relative names")
            continue
        if name in hashes:
            errors.append(f"artifact manifest contains duplicate file {name}")
            continue
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            errors.append(f"artifact manifest has invalid SHA-256 for {name}")
            continue
        if not isinstance(size, int) or size < 0:
            errors.append(f"artifact manifest has invalid size for {name}")
        hashes[name] = digest
    return hashes, errors


def unsigned_hashes(hashes: dict[str, str]) -> dict[str, str]:
    return {name: digest for name, digest in hashes.items() if "-unsigned" in name}


def verify_builder(evidence_dir: Path, name: str, document: dict[str, Any], final_manifest_hash: str, final_unsigned: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    builder_id = document.get("builder_id")
    if not isinstance(builder_id, str) or not builder_id.strip():
        errors.append(f"{name}: builder_id must be a non-empty string")
    if document.get("release_manifest_sha256") != final_manifest_hash:
        errors.append(f"{name}: release_manifest_sha256 does not bind the final release manifest")
    path, descriptor_errors = verify_descriptor(evidence_dir, document.get("manifest"), f"{name}: manifest")
    errors.extend(descriptor_errors)
    if path is None or descriptor_errors:
        return {}, errors
    try:
        manifest = load_object(path)
    except (OSError, ValueError) as exc:
        return {}, errors + [f"{name}: invalid builder artifact manifest: {exc}"]
    hashes, manifest_errors = artifact_hashes(manifest)
    errors.extend(f"{name}: {error}" for error in manifest_errors)
    actual_unsigned = unsigned_hashes(hashes)
    claimed = document.get("unsigned_artifact_hashes")
    if not isinstance(claimed, dict) or not claimed:
        errors.append(f"{name}: unsigned_artifact_hashes must be a non-empty object")
    elif claimed != actual_unsigned:
        errors.append(f"{name}: unsigned_artifact_hashes do not match the signed builder manifest")
    if actual_unsigned != final_unsigned:
        errors.append(f"{name}: builder unsigned artifacts do not match the final release manifest")
    return actual_unsigned, errors


def verify_final_artifact_files(manifest_path: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return ["final release artifact manifest has no artifacts array"]
    release_dir = manifest_path.parent.resolve()
    for item in artifacts:
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            continue
        name = item["file"]
        if "/" in name or "\\" in name or name in {"", ".", ".."}:
            continue
        artifact = (release_dir / name).resolve()
        if artifact.parent != release_dir:
            errors.append(f"final release artifact path escapes release directory: {name}")
            continue
        if not artifact.is_file():
            errors.append(f"final release artifact is missing: {name}")
            continue
        expected_size = item.get("size")
        expected_sha = item.get("sha256")
        if isinstance(expected_size, int) and artifact.stat().st_size != expected_size:
            errors.append(f"final release artifact size mismatch: {name}")
        if isinstance(expected_sha, str) and sha256_file(artifact) != expected_sha:
            errors.append(f"final release artifact SHA-256 mismatch: {name}")
    return errors


def load_final_manifest(path: Path) -> tuple[str, dict[str, str], list[str]]:
    errors: list[str] = []
    if not path.is_file():
        return "", {}, ["final release artifact manifest is missing"]
    digest = sha256_file(path)
    try:
        manifest = load_object(path)
    except (OSError, ValueError) as exc:
        return digest, {}, [f"invalid final release artifact manifest: {exc}"]
    hashes, manifest_errors = artifact_hashes(manifest)
    errors.extend(f"final release artifact manifest: {error}" for error in manifest_errors)
    if not manifest_errors:
        errors.extend(verify_final_artifact_files(path, manifest))
    final_unsigned = unsigned_hashes(hashes)
    if not final_unsigned:
        errors.append("final release artifact manifest contains no unsigned release artifacts")
    return digest, final_unsigned, errors
