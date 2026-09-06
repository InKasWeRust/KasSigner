"""Transactional wallet-session ownership and result-handling guards."""

from __future__ import annotations

from pathlib import Path
import re

from architecture.core.common import rust_code_only

FIRMWARE_ROOT = Path("apps/signer-firmware/src")
SESSION_PATH = FIRMWARE_ROOT / "services/wallet_session.rs"


def discards_wallet_activation_result(source: str) -> bool:
    code = rust_code_only(source)
    return bool(re.search(
        r"let\s+_\s*=\s*[^;]*wallet_session::activate_slot\s*\(",
        code,
        re.S,
    ))


def check(root: Path) -> list[str]:
    errors: list[str] = []
    session_path = root / SESSION_PATH
    if not session_path.is_file():
        return ["authoritative wallet-session service is missing"]
    source = session_path.read_text(errors="ignore")
    for required in (
        "pub fn activate_slot(",
        "pub enum WalletActivationError",
        "struct ActivationPlan",
        "fn prepare_activation(",
        "fn commit_activation(",
        "pub fn clear_active_wallet(",
        "pub fn reset_derived_state(",
        "extra_pubkey_index = u16::MAX",
        "extra_change_pubkey_index = u16::MAX",
        "for public_key in &mut ad.wallet.addresses.change_pubkey_cache",
        "acct_key_raw",
    ):
        if required not in source:
            errors.append(f"wallet-session isolation contract is missing: {required}")

    regression = root / FIRMWARE_ROOT / "runtime/unit_tests/wallet_session.rs"
    regression_source = regression.read_text(errors="ignore") if regression.is_file() else ""
    for required in (
        "extra_change_pubkey_index = 5",
        "extra_change_pubkey_index == u16::MAX",
        "first_extended_change != second_extended_change",
        "before_failure",
        "WalletActivationError::InvalidRawKey",
        "WalletActivationError::InvalidAccountKey",
    ):
        if required not in regression_source:
            errors.append(f"wallet-switch regression coverage is missing: {required}")
    if not any(
        form in regression_source
        for form in (
            "ActiveWalletSnapshot::capture(ad) == before_failure",
            "ActiveWalletSnapshot::capture(&ad) == before_failure",
        )
    ):
        errors.append("wallet-switch regression coverage is missing: failed activation preserves ActiveWalletSnapshot")

    firmware_root = root / FIRMWARE_ROOT
    for path in firmware_root.rglob("*.rs"):
        if path == session_path or "unit_tests" in path.parts:
            continue
        relative = path.relative_to(root)
        text = path.read_text(errors="ignore")
        if re.search(r"\.seed_mgr\.activate\s*\(", text):
            errors.append(f"wallet activation bypasses wallet_session: {relative}")
        if discards_wallet_activation_result(text):
            errors.append(f"wallet activation result is discarded: {relative}")
        if re.search(r"extra_change_pubkey_index\s*=\s*(?:u16::MAX|0xFFFF)", text):
            errors.append(f"change-key cache reset bypasses wallet_session: {relative}")
        if re.search(r"extra_pubkey_index\s*=\s*(?:u16::MAX|0xFFFF)", text):
            errors.append(f"receive-key cache reset bypasses wallet_session: {relative}")
    return errors
