#!/usr/bin/env python3
"""Fail-closed verifier for externally produced, release-bound evidence."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

_RELEASE_DIR = Path(__file__).resolve().parent
if str(_RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(_RELEASE_DIR))

from readiness import builders, mobile, software_assurance  # noqa: E402
from readiness.model import (  # noqa: E402
    REQUIRED_EVIDENCE,
    SHA256_RE,
    SPECIALIZED_EVIDENCE,
    load_object,
    verify_descriptor,
)
from readiness.signatures import (  # noqa: E402
    load_trust_policy,
    trusted_key,
    verify_detached_signature,
)


def release_binding_errors(name: str, document: dict[str, Any], source_sha256: str, release_sha256: str) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != 2:
        errors.append(f"{name}: schema must be 2")
    if document.get("status") != "pass":
        errors.append(f"{name}: status must be pass")
    if document.get("source_sha256") != source_sha256:
        errors.append(f"{name}: source_sha256 must exactly bind the release source/artifact")
    if document.get("release_artifact_sha256") != release_sha256:
        errors.append(f"{name}: release_artifact_sha256 must exactly bind the release source/artifact")
    return errors


def generic_report_errors(evidence_dir: Path, name: str, document: dict[str, Any]) -> list[str]:
    _, errors = verify_descriptor(evidence_dir, document.get("report"), f"{name}: report")
    return errors


def domain_errors(name: str, document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if name == "independent_security_audit.json":
        if not isinstance(document.get("independent_organization"), str) or not document.get("independent_organization", "").strip():
            errors.append(f"{name}: independent_organization must be non-empty")
        if document.get("self_review") is not False:
            errors.append(f"{name}: self_review must be false")
        for severity in ("unresolved_critical", "unresolved_high"):
            if document.get(severity) != 0:
                errors.append(f"{name}: {severity} must be zero")
    elif name == "signing_key_custody.json":
        if document.get("dual_control") is not True:
            errors.append(f"{name}: dual_control must be true")
        if document.get("key_exportable") is not False:
            errors.append(f"{name}: key_exportable must be false")
        if document.get("storage") not in {"offline-hsm", "offline-hardware-token", "airgapped-dual-control"}:
            errors.append(f"{name}: storage must use an accepted offline/dual-control class")
    elif name == "m5stack_owner_authority.json":
        expected = {
            "vendor_digest_slot": 0,
            "owner_digest_slot": 1,
            "unused_digest_slot": 2,
            "unused_digest_revoked": True,
            "trusted_revoke_write_protected": True,
            "development_efuse_writes": False,
            "enrollment_before_pop_it": "pass",
            "enrollment_after_pop_it_rejected": "pass",
            "vendor_firmware_boot": "pass",
            "owner_firmware_boot": "pass",
            "unrelated_owner_key_rejected": "pass",
            "owner_downgrade_rejected": "pass",
            "failed_owner_install_preserves_previous_ota": "pass",
            "pop_it_without_owner_closes_enrollment": "pass",
        }
        for field, expected_value in expected.items():
            if document.get(field) != expected_value:
                errors.append(f"{name}: {field} must be {expected_value!r}")
    elif name == "ios_release_build.json":
        errors.extend(mobile.verify_release_build(name, document, "ios"))
    elif name == "android_release_build.json":
        errors.extend(mobile.verify_release_build(name, document, "android"))
    elif name == "ios_hil_smoke.json":
        errors.extend(mobile.verify_hil_smoke(name, document, "ios"))
    elif name == "android_hil_smoke.json":
        errors.extend(mobile.verify_hil_smoke(name, document, "android"))
    return errors


def load_signed_evidence(
    evidence_dir: Path,
    trust_policy_path: Path,
    trust_policy: dict[str, Any],
    source_sha256: str,
    release_sha256: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    documents: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for name, description in REQUIRED_EVIDENCE.items():
        path = evidence_dir / name
        if not path.is_file():
            errors.append(f"missing {description}: {name}")
            continue
        try:
            document = load_object(path)
        except (OSError, ValueError) as exc:
            errors.append(f"invalid {name}: {exc}")
            continue
        documents[name] = document
        key_path, key_errors = trusted_key(
            trust_policy_path, trust_policy, name, document.get("signer_key_id")
        )
        errors.extend(key_errors)
        if key_path is not None and not key_errors:
            errors.extend(verify_detached_signature(path, key_path))
        errors.extend(release_binding_errors(name, document, source_sha256, release_sha256))
        if name not in SPECIALIZED_EVIDENCE:
            errors.extend(generic_report_errors(evidence_dir, name, document))
        errors.extend(domain_errors(name, document))
    return documents, errors


def verify_builders(
    evidence_dir: Path,
    documents: dict[str, dict[str, Any]],
    release_manifest: Path,
) -> list[str]:
    errors: list[str] = []
    final_manifest_hash, final_unsigned, manifest_errors = builders.load_final_manifest(release_manifest)
    errors.extend(manifest_errors)
    a = documents.get("independent_builder_a.json")
    b = documents.get("independent_builder_b.json")
    if not a or not b or manifest_errors:
        return errors
    unsigned_a, errors_a = builders.verify_builder(
        evidence_dir, "independent_builder_a.json", a, final_manifest_hash, final_unsigned
    )
    unsigned_b, errors_b = builders.verify_builder(
        evidence_dir, "independent_builder_b.json", b, final_manifest_hash, final_unsigned
    )
    errors.extend(errors_a)
    errors.extend(errors_b)
    if a.get("builder_id") == b.get("builder_id"):
        errors.append("independent builders must have distinct builder_id values")
    if a.get("signer_key_id") == b.get("signer_key_id"):
        errors.append("independent builders must be signed by distinct trusted attester keys")
    if unsigned_a and unsigned_b and unsigned_a != unsigned_b:
        errors.append("independent builders do not converge on the same unsigned artifact set")
    return errors


def verify_software_assurance(evidence_dir: Path, documents: dict[str, dict[str, Any]]) -> list[str]:
    document = documents.get("software_assurance.json")
    if not document:
        return []
    return software_assurance.verify(evidence_dir, document)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--release-artifact-sha256", required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    errors: list[str] = []
    if not SHA256_RE.fullmatch(arguments.source_sha256):
        errors.append("source SHA-256 must be 64 lowercase hex characters")
    if not SHA256_RE.fullmatch(arguments.release_artifact_sha256):
        errors.append("release artifact SHA-256 must be 64 lowercase hex characters")
    trust_policy, trust_errors = load_trust_policy(
        arguments.trust_policy, arguments.trust_policy_sha256
    )
    errors.extend(trust_errors)
    documents: dict[str, dict[str, Any]] = {}
    if not trust_errors:
        documents, evidence_errors = load_signed_evidence(
            arguments.evidence_dir,
            arguments.trust_policy,
            trust_policy,
            arguments.source_sha256,
            arguments.release_artifact_sha256,
        )
        errors.extend(evidence_errors)
        errors.extend(verify_builders(arguments.evidence_dir, documents, arguments.release_manifest))
        errors.extend(verify_software_assurance(arguments.evidence_dir, documents))
    for error in errors:
        print("ERROR:", error)
    if errors:
        return 1
    print(
        f"PASS: {len(REQUIRED_EVIDENCE)}/{len(REQUIRED_EVIDENCE)} signed external/operational "
        "release evidence classes are source/artifact-bound, report-hash verified, and trust-policy anchored"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
