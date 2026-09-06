"""Release-build and physical-device smoke requirements for mobile shells."""
from __future__ import annotations

from typing import Any

from .model import SHA256_RE

IOS_SMOKE = {
    "launch", "runtime_integrity", "navigation_confinement", "qr_import",
    "file_import_export", "app_lock_privacy", "background_foreground", "node_connectivity",
}
ANDROID_SMOKE = IOS_SMOKE | {"process_death_restore"}


def _sha_field(document: dict[str, Any], name: str, evidence_name: str) -> list[str]:
    value = document.get(name)
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        return [f"{evidence_name}: {name} must be 64 lowercase hex characters"]
    return []


def verify_release_build(name: str, document: dict[str, Any], platform: str) -> list[str]:
    errors: list[str] = []
    if document.get("platform") != platform:
        errors.append(f"{name}: platform must be {platform}")
    if document.get("configuration") != "release":
        errors.append(f"{name}: configuration must be release")
    if document.get("signed_build") is not True:
        errors.append(f"{name}: signed_build must be true")
    errors.extend(_sha_field(document, "mobile_artifact_sha256", name))
    errors.extend(_sha_field(document, "embedded_runtime_sha256", name))
    if not isinstance(document.get("toolchain_version"), str) or not document.get("toolchain_version", "").strip():
        errors.append(f"{name}: toolchain_version must be non-empty")
    return errors


def verify_hil_smoke(name: str, document: dict[str, Any], platform: str) -> list[str]:
    errors: list[str] = []
    if document.get("platform") != platform:
        errors.append(f"{name}: platform must be {platform}")
    if document.get("configuration") != "release":
        errors.append(f"{name}: configuration must be release")
    if document.get("physical_device") is not True:
        errors.append(f"{name}: physical_device must be true")
    if not isinstance(document.get("device_model"), str) or not document.get("device_model", "").strip():
        errors.append(f"{name}: device_model must be non-empty")
    if not isinstance(document.get("os_version"), str) or not document.get("os_version", "").strip():
        errors.append(f"{name}: os_version must be non-empty")
    tests = document.get("smoke_tests")
    required = IOS_SMOKE if platform == "ios" else ANDROID_SMOKE
    if not isinstance(tests, dict):
        return errors + [f"{name}: smoke_tests must be an object"]
    for test in sorted(required):
        if tests.get(test) != "pass":
            errors.append(f"{name}: smoke test {test} must be pass")
    return errors
