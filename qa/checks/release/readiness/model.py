"""Shared model and file-integrity helpers for release evidence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_EVIDENCE = {
    "independent_security_audit.json": "independent third-party security/cryptography review",
    "independent_builder_a.json": "first independent clean reproducible builder",
    "independent_builder_b.json": "second independent clean reproducible builder",
    "signing_key_custody.json": "offline/HSM or equivalently protected dual-control production signing custody",
    "hil_waveshare.json": "Waveshare hardware-in-loop result",
    "hil_waveshare_af.json": "Waveshare-AF hardware-in-loop result",
    "hil_m5stack.json": "M5Stack hardware-in-loop result",
    "production_fused_smoke_waveshare.json": "production signed/fused Waveshare smoke result",
    "production_fused_smoke_waveshare_af.json": "production signed/fused Waveshare-AF smoke result",
    "production_fused_smoke_m5stack.json": "production signed/fused M5Stack smoke result",
    "m5stack_flash_encryption_release.json": "CoreS3 Flash Encryption Release Mode and write-protection evidence",
    "m5stack_secure_boot_v2.json": "CoreS3 Secure Boot v2 bootloader/profile and fused-key evidence",
    "m5stack_owner_authority.json": "CoreS3 dual-authority owner-firmware enrollment/install evidence",
    "m5stack_anti_rollback.json": "CoreS3 second-stage bootloader rejection of a correctly signed lower-security-version image",
    "m5stack_update_manifest_negative.json": "CoreS3 signed-update manifest tamper and cross-board/version/layout rejection evidence",
    "m5stack_secret_memory_map.json": "CoreS3 linker/map evidence that secret-bearing runtime roots are internal SRAM",
    "physical_entropy_sp80090b.json": "physical entropy characterization",
    "efuse_hmac_provisioning.json": "per-device eFuse HMAC uniqueness/read-protection evidence",
    "secure_boot_fault.json": "secure-boot modified-image/fault evidence",
    "update_power_loss_fault.json": "update power-loss/fault evidence",
    "credential_timing.json": "credential timing/side-channel evidence",
    "physical_fault_injection.json": "physical fault-injection evidence",
    "software_assurance.json": "dependency advisory/SBOM/license evidence",
    "ios_release_build.json": "iOS signed Release-build evidence",
    "ios_hil_smoke.json": "iOS physical-device Release/HIL smoke evidence",
    "android_release_build.json": "Android signed release-build evidence",
    "android_hil_smoke.json": "Android physical-device release/HIL smoke evidence",
}

SPECIALIZED_EVIDENCE = {
    "independent_builder_a.json",
    "independent_builder_b.json",
    "software_assurance.json",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("must be a JSON object")
    return data


def safe_evidence_file(root: Path, relative_name: object) -> Path:
    if not isinstance(relative_name, str) or not relative_name or "\\" in relative_name:
        raise ValueError("path must be a non-empty POSIX-style relative path")
    relative = Path(relative_name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("path must stay inside the evidence directory")
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("path escapes the evidence directory")
    return candidate


def verify_descriptor(root: Path, descriptor: object, label: str) -> tuple[Path | None, list[str]]:
    errors: list[str] = []
    if not isinstance(descriptor, dict):
        return None, [f"{label}: descriptor must be an object"]
    try:
        path = safe_evidence_file(root, descriptor.get("path"))
    except ValueError as exc:
        return None, [f"{label}: {exc}"]
    expected_sha = descriptor.get("sha256")
    expected_bytes = descriptor.get("bytes")
    if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha):
        errors.append(f"{label}: sha256 must be 64 lowercase hex characters")
    if not isinstance(expected_bytes, int) or expected_bytes < 0:
        errors.append(f"{label}: bytes must be a non-negative integer")
    if not path.is_file():
        errors.append(f"{label}: referenced file is missing: {descriptor.get('path')}")
        return path, errors
    actual = path.read_bytes()
    if isinstance(expected_bytes, int) and expected_bytes >= 0 and len(actual) != expected_bytes:
        errors.append(f"{label}: byte length does not match the signed descriptor")
    if isinstance(expected_sha, str) and SHA256_RE.fullmatch(expected_sha):
        if sha256_bytes(actual) != expected_sha:
            errors.append(f"{label}: SHA-256 does not match the signed descriptor")
    return path, errors
