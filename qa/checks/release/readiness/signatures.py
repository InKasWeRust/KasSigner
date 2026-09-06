"""Detached Ed25519 verification anchored to an externally hashed trust policy."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from .model import SHA256_RE, load_object, sha256_file


def load_trust_policy(path: Path, expected_sha256: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not path.is_file():
        return {}, ["release trust policy is missing"]
    if not SHA256_RE.fullmatch(expected_sha256):
        return {}, ["trust-policy SHA-256 must be 64 lowercase hex characters"]
    if sha256_file(path) != expected_sha256:
        return {}, ["release trust policy SHA-256 does not match the operator-supplied anchor"]
    try:
        policy = load_object(path)
    except (OSError, ValueError) as exc:
        return {}, [f"invalid release trust policy: {exc}"]
    if policy.get("schema") != 1:
        errors.append("release trust policy: schema must be 1")
    if not isinstance(policy.get("keys"), dict):
        errors.append("release trust policy: keys must be an object")
    if not isinstance(policy.get("evidence"), dict):
        errors.append("release trust policy: evidence must be an object")
    return policy, errors


def trusted_key(policy_path: Path, policy: dict[str, Any], evidence_name: str, key_id: object) -> tuple[Path | None, list[str]]:
    if not isinstance(key_id, str) or not key_id:
        return None, [f"{evidence_name}: signer_key_id must be a non-empty string"]
    allowed = policy.get("evidence", {}).get(evidence_name, [])
    if key_id not in allowed:
        return None, [f"{evidence_name}: signer_key_id {key_id!r} is not trusted for this evidence class"]
    spec = policy.get("keys", {}).get(key_id)
    if not isinstance(spec, dict):
        return None, [f"{evidence_name}: trust policy has no key record for {key_id!r}"]
    key_path_value = spec.get("public_key")
    if not isinstance(key_path_value, str) or not key_path_value:
        return None, [f"{evidence_name}: trusted key {key_id!r} has no public_key path"]
    key_path = (policy_path.parent / key_path_value).resolve()
    policy_root = policy_path.parent.resolve()
    if key_path != policy_root and policy_root not in key_path.parents:
        return None, [f"{evidence_name}: trusted key path escapes the trust-policy directory"]
    expected_sha = spec.get("sha256")
    if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha):
        return None, [f"{evidence_name}: trusted key {key_id!r} has an invalid SHA-256"]
    if not key_path.is_file():
        return None, [f"{evidence_name}: trusted public key is missing for {key_id!r}"]
    if sha256_file(key_path) != expected_sha:
        return None, [f"{evidence_name}: trusted public key hash mismatch for {key_id!r}"]
    return key_path, []


def _ed25519_key_error(key_path: Path, public: bool) -> str | None:
    command = ["openssl", "pkey"]
    if public:
        command.append("-pubin")
    command.extend(["-in", str(key_path), "-text", "-noout"])
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return "OpenSSL is required for Ed25519 evidence signatures"
    if result.returncode != 0:
        return "evidence key is not a readable OpenSSL key"
    details = (result.stdout + result.stderr).upper()
    if "ED25519" not in details:
        return "evidence key must be Ed25519"
    return None


def verify_detached_signature(evidence_path: Path, key_path: Path) -> list[str]:
    key_error = _ed25519_key_error(key_path, public=True)
    if key_error:
        return [f"{evidence_path.name}: {key_error}"]
    signature_path = evidence_path.with_name(evidence_path.name + ".sig")
    if not signature_path.is_file():
        return [f"{evidence_path.name}: missing detached signature {signature_path.name}"]
    command = [
        "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
        "-rawin", "-in", str(evidence_path), "-sigfile", str(signature_path),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return [f"{evidence_path.name}: OpenSSL is required to verify Ed25519 evidence signatures"]
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        suffix = f": {detail}" if detail else ""
        return [f"{evidence_path.name}: detached Ed25519 signature verification failed{suffix}"]
    return []


def sign_detached(document_path: Path, private_key_path: Path) -> Path:
    """Sign an evidence JSON file exactly as written using an Ed25519 private key."""
    if not private_key_path.is_file():
        raise ValueError("evidence signing key is missing")
    key_error = _ed25519_key_error(private_key_path, public=False)
    if key_error:
        raise ValueError(key_error)
    signature_path = document_path.with_name(document_path.name + ".sig")
    command = [
        "openssl", "pkeyutl", "-sign", "-inkey", str(private_key_path),
        "-rawin", "-in", str(document_path), "-out", str(signature_path),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ValueError("OpenSSL is required to create Ed25519 evidence signatures") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError(f"failed to sign evidence with Ed25519: {detail}")
    return signature_path
