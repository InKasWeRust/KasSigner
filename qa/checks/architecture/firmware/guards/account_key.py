"""Canonical account-key boundary and conformance guards."""

from __future__ import annotations

from pathlib import Path
import re


def _source(path: Path) -> str:
    return path.read_text(errors="ignore")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    shared_path = root / "crates/shared-signer/src/account_key.rs"
    if not shared_path.is_file():
        return ["shared canonical account-key codec is missing"]

    shared = _source(shared_path)
    for required in (
        "ACCOUNT_KEY_TEXT_PREFIX",
        "validate_account_key_payload",
        "encode_account_key_text",
        "decode_account_key_text",
    ):
        if required not in shared:
            errors.append(f"shared account-key contract is missing: {required}")

    consumers = {
        "crates/offline-signer/src/derivation/xpub/kpub.rs": (
            "shared_signer::account_key",
            "encode_account_key_text",
            "decode_account_key_text",
        ),
        "crates/kassigner-protocol/src/account/bip32.rs": (
            "shared_signer::account_key",
            "encode_account_key_text",
            "decode_account_key_text",
        ),
    }
    for relative, required_symbols in consumers.items():
        source = _source(root / relative)
        for required in required_symbols:
            if required not in source:
                errors.append(
                    f"account-key consumer bypasses shared codec: {relative} missing {required}"
                )
        if re.search(r"\bbs58\b", source, re.IGNORECASE):
            errors.append(f"account-key consumer implements Base58 directly: {relative}")
        if "decode_legacy_kpub" not in source and "decode_kpub_compatible" not in source:
            errors.append(
                f"account-key consumer lacks isolated decode-only legacy recovery: {relative}"
            )

    online_bip32 = _source(root / "crates/online-watcher/src/account/bip32.rs")
    if "kassigner_protocol" not in online_bip32:
        errors.append("online watcher account/BIP32 facade must delegate to kassigner-protocol")

    online_manifest = _source(root / "crates/online-watcher/Cargo.toml")
    if re.search(r"(?m)^bs58\s*=", online_manifest):
        errors.append("online watcher still depends on bs58 for account-key import")

    conformance = root / "qa/tests/conformance/account_key.rs"
    if not conformance.is_file():
        errors.append("canonical account-key conformance tests are missing")
    else:
        source = _source(conformance)
        for required in (
            "canonical_account_key_round_trips",
            "account_key_rejects_noncanonical_metadata_and_text",
        ):
            if required not in source:
                errors.append(f"account-key conformance coverage is missing: {required}")
    return errors
