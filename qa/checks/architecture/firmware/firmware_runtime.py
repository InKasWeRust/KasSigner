"""Firmware runtime input and signing module boundaries."""

from __future__ import annotations

from pathlib import Path
import re

from architecture.core.common import relative_posix, rust_function_lengths


def runtime_function_lengths(source: str) -> list[tuple[str, int]]:
    """Return runtime function lengths through the shared Rust parser."""
    return rust_function_lengths(source, include_indented=True)

INPUT_MODULES = {
    "button.rs",
    "menu.rs",
    "routing.rs",
    "state.rs",
    "wallet_app.rs",
}
SIGNING_MODULES = {
    "derivation.rs",
    "kspt.rs",
    "loaded_accounts.rs",
    "pskt.rs",
    "qr.rs",
    "output.rs",
    "review.rs",
    "signature_status.rs",
    "strategy.rs",
    "verification.rs",
    "workflow.rs",
    "workflow_test.rs",
}
INPUT_EXPORTS = {
    "Action",
    "AppState",
    "Button",
    "ButtonEvent",
    "HandlerGroup",
    "Menu",
    "WalletApp",
}
SIGNING_EXPORTS = {
    "cycle_signed_qr",
    "derive_active_account_key",
    "derive_active_account_key_with_checkpoint",
    "derive_active_private_key_with_checkpoint",
    "derive_active_seed",
    "derive_active_seed_with_checkpoint",
    "derive_change_pubkey_from_acct",
    "derive_pubkey_from_acct",
    "derive_slot_pubkeys_with_checkpoint",
    "handle_signing_operation_step",
    "populate_active_pubkeys_with_checkpoint",
    "ReviewTotals",
    "run_firmware_verify",
    "serialize_active_xprv_with_checkpoint",
    "sign_and_serialize_multi",
    "transaction_review_totals",
    "verify_transaction_output_ownership",
    "verify_transaction_output_ownership_with_checkpoint",
}


def reexported_names(source: str) -> set[str]:
    names: set[str] = set()
    for body in re.findall(r"pub use\s+[^;]+;", source, re.S):
        body = re.sub(r"^pub use\s+", "", body).rstrip(";")
        if "{" in body:
            inside = body[body.index("{") + 1:body.rindex("}")]
            names.update(
                name.strip().split(" as ")[-1]
                for name in inside.split(",")
                if name.strip()
            )
        else:
            names.add(body.rsplit("::", 1)[-1].strip().split(" as ")[-1])
    return names


def check_facade(
    path: Path,
    expected_modules: set[str],
    expected_exports: set[str],
    errors: list[str],
) -> None:
    source = path.read_text(errors="ignore")
    if len(source.splitlines()) > 80:
        errors.append(f"firmware runtime facade exceeds 80 lines: {path.relative_to(path.parents[4])}")
    if re.search(r"(?m)^\s*(?:pub\s+)?(?:fn|struct|enum|impl)\s+", source):
        errors.append(f"firmware runtime facade contains implementation code: {path}")
    module_names = set(re.findall(r"(?m)^mod\s+([a-z_][a-z0-9_]*)\s*;", source))
    if module_names != {Path(name).stem for name in expected_modules}:
        errors.append(
            f"firmware runtime facade module inventory changed for {path.name}: "
            f"expected {sorted(Path(name).stem for name in expected_modules)}, "
            f"got {sorted(module_names)}"
        )
    exports = reexported_names(source)
    if exports != expected_exports:
        errors.append(
            f"firmware runtime facade exports changed for {path.name}: "
            f"expected {sorted(expected_exports)}, got {sorted(exports)}"
        )


def check_modules(root: Path, expected: set[str], errors: list[str]) -> None:
    actual = {path.name for path in root.glob("*.rs")}
    if actual != expected:
        errors.append(
            f"firmware runtime module inventory changed under {root}: "
            f"expected {sorted(expected)}, got {sorted(actual)}"
        )
    for path in root.glob("*.rs"):
        source = path.read_text(errors="ignore")
        line_count = len(source.splitlines())
        if line_count > 320:
            errors.append(f"firmware runtime module exceeds 320 lines: {path} ({line_count})")
        for function, function_lines in runtime_function_lengths(source):
            if function_lines > 300:
                errors.append(
                    f"firmware runtime function exceeds 300 lines: "
                    f"{path}:{function} ({function_lines})"
                )


def check(root: Path) -> list[str]:
    errors: list[str] = []
    runtime = root / "apps/signer-firmware/src/runtime"
    input_facade = runtime / "input.rs"
    signing_facade = runtime / "signing.rs"
    input_root = runtime / "input"
    signing_root = runtime / "signing"

    check_facade(input_facade, INPUT_MODULES, INPUT_EXPORTS, errors)
    check_facade(signing_facade, SIGNING_MODULES, SIGNING_EXPORTS, errors)
    check_modules(input_root, INPUT_MODULES, errors)
    check_modules(signing_root, SIGNING_MODULES, errors)

    input_tests = (runtime / "unit_tests/input_tests.rs").read_text(errors="ignore")
    if "pub enum HandlerGroup" in input_tests or "fn handler_group" in input_tests:
        errors.append("production input routing remains implemented under unit_tests")

    derivation_path = signing_root / "derivation.rs"
    address_cache_path = signing_root / "derivation/address_cache.rs"
    wallet_session_path = root / "apps/signer-firmware/src/services/wallet_session.rs"
    cache_writers = []
    for path in (root / "apps/signer-firmware/src").rglob("*.rs"):
        if path in (derivation_path, address_cache_path, wallet_session_path) or "unit_tests" in path.parts:
            continue
        source = path.read_text(errors="ignore")
        if re.search(
            r"(?:pubkey_cache|change_pubkey_cache)\s*\[[^]]+\]\s*"
            r"(?:\.copy_from_slice|=)"
            r"|pubkeys_cached\s*=\s*true",
            source,
        ):
            cache_writers.append(relative_posix(path, root))
    if cache_writers:
        errors.append(
            "firmware address caches bypass populate_active_pubkeys: "
            f"{sorted(cache_writers)}"
        )

    return errors
