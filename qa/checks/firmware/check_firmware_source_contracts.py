#!/usr/bin/env python3
"""Validate source-level contracts required before ESP firmware compilation."""

from __future__ import annotations

from boot_self_test_contract import check_boot_self_test_feature_contract
from board_partition_contract import check_board_partition_contract
from firmware_warning_contract import check_firmware_warning_contract
from qemu_platform_contract import check_qemu_platform_contract
from production_e2e_coverage import check as check_production_e2e_coverage
from security_integration_contract import check_security_integration_contract
from wallet_recovery_contract import check_wallet_recovery_contract
from source_contract_support import ROOT, read, require
from stack_budget_contract import check_stack_budget_contract
from source_contract_storage import (
    check_mutable_sector_slice_contract, check_sd_persistence_security_contract,
    check_storage_facades,
)
from source_contract_security import (
    check_advanced_security_feature_gates, check_hardware_test_contract,
)
from source_contract_visibility import (
    check_internal_visibility_contract, check_redraw_contract,
    check_retry_const_contract, check_firmware_core_test_import_contract,
)

def check_boot_macros(errors: list[str]) -> None:
    for board in ("waveshare", "m5stack"):
        path = f"apps/signer-firmware/src/boot/{board}/mod.rs"
        source = read(path)
        require(
            errors,
            "($peripherals:ident, $delay:ident) => {{" in source,
            f"{path}: initialize! must expand to an expression block",
        )
        require(
            errors,
            "\n    }}\n}\n\npub(crate) use initialize;" in source,
            f"{path}: initialize! expression block is not closed correctly",
        )

def check_iconoir_contract(errors: list[str]) -> None:
    paths = (
        "apps/signer-firmware/src/ui/screens/components/input_source.rs",
        "apps/signer-firmware/src/ui/screens/components/stego_picker.rs",
        "apps/signer-firmware/src/ui/screens/storage/sd/file_list.rs",
    )
    for path in paths:
        source = read(path)
        require(
            errors,
            "embedded_iconoir::prelude::IconoirNewIcon" in source,
            f"{path}: import IconoirNewIcon for icon constructors",
        )
        require(
            errors,
            "embedded_iconoir::prelude::Icon;" not in source,
            f"{path}: stale embedded_iconoir::prelude::Icon import",
        )

def check_kspt_boot_tests(errors: list[str]) -> None:
    path = "crates/offline-signer/src/transaction/kspt/unit_tests/mod.rs"
    source = read(path)
    for module in ("wire_adapter", "common", "kssn", "script", "status"):
        require(
            errors,
            f"#[cfg(test)]\nmod {module};" in source,
            f"{path}: {module} must be test-only",
        )
    require(
        errors,
        "mod codec;" not in source,
        f"{path}: retired local codec module must not return; canonical wire ownership is kassigner-protocol",
    )
    require(
        errors,
        "pub use integration::run_kspt_tests;" in source,
        f"{path}: verbose-boot KSPT runner must be exported",
    )

def check_module_owners(errors: list[str]) -> None:
    verify = read("apps/signer-firmware/src/services/verify/mod.rs")
    require(
        errors,
        "CANARY_POST_VERIFY" in verify.split("mod mapped_segment;", 1)[0],
        "services/verify/mod.rs: post-verification canary must be imported from types",
    )

    picker = read(
        "apps/signer-firmware/src/runtime/interactions/tx/multisig_setup/seed_picker.rs"
    )
    require(
        errors,
        "ui::display::{draw_lato_hint, measure_hint, COLOR_TEXT_DIM}" in picker,
        "multisig seed picker must use UI presentation helpers from ui::display",
    )
    for stale in (
        "display::measure_hint",
        "display::draw_lato_hint",
        "display::COLOR_TEXT_DIM",
    ):
        require(errors, stale not in picker, f"seed_picker.rs: stale {stale} path")

    qr = read("apps/signer-firmware/src/qr/encoder/ecc/codewords.rs")
    require(
        errors,
        "super::super::matrix::build(version, codewords)" in qr,
        "QR ECC code must construct matrices through the matrix facade",
    )
    for private_call in (
        "QrCode::new",
        ".draw_function_patterns()",
        ".place_data(codewords)",
        ".apply_best_mask()",
    ):
        require(
            errors,
            private_call not in qr,
            f"QR ECC code bypasses matrix facade with {private_call}",
        )


def check_workflow_menu_adapter_contract(errors: list[str]) -> None:
    facade = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")
    production = read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
    require(
        errors,
        '#[cfg(feature = "workflow-test-auto")]\npub(crate) fn workflow_wallet_backup_methods_select' in facade
        and 'production::workflow_wallet_backup_methods_select(ad, item)' in facade,
        "menu/primary.rs: workflow backup-method selector must be parent-visible for connected firmware builds",
    )
    require(
        errors,
        '#[cfg(feature = "workflow-test-auto")]\npub(super) fn workflow_wallet_backup_methods_select' in production,
        "menu/primary/production.rs: workflow backup-method implementation must remain available to the parent facade",
    )

def check_signing_boot_api_contract(errors: list[str]) -> None:
    gate = '#[cfg(any(test, all(feature = "m5stack", feature = "hardware-tests")))]\n'
    facade = read("apps/signer-firmware/src/runtime/signing.rs")
    implementation = read("apps/signer-firmware/src/runtime/signing/kspt.rs")
    require(
        errors,
        f"{gate}pub use kspt::sign_and_serialize_multi;" in facade,
        "runtime/signing.rs: M5Stack hardware-test signing re-export must match its implementation gate",
    )
    require(
        errors,
        f"{gate}#[inline(never)]\npub fn sign_and_serialize_multi(" in implementation,
        "runtime/signing/kspt.rs: boot signing helper must compile for M5Stack hardware-test builds",
    )
    require(
        errors,
        ") -> Result<usize, offline_signer::transaction::kspt::PsktError> {" in implementation
        and ".unwrap_or(0)" not in implementation,
        "runtime/signing/kspt.rs: boot signing helper must preserve KSPT errors instead of collapsing them to zero",
    )


def check_refactored_firmware_api_contracts(errors: list[str]) -> None:
    sdhost = read(
        "apps/signer-firmware/src/hw/waveshare/storage/transport/sdhost/command.rs"
    )
    require(
        errors,
        "SdHostCommandPoll" in sdhost
        and "poll_sdhost_command(\n        SdHostCommandPoll {" in sdhost
        and "poll_sdhost_command(\n        1_000_000," not in sdhost,
        "sdhost/command.rs: firmware caller must use the typed SdHostCommandPoll API",
    )

    signing = read("apps/signer-firmware/src/runtime/data/signing.rs")
    require(
        errors,
        "Transaction::try_new().map_err(|_| ())?" in signing,
        "runtime/data/signing.rs: transaction storage allocation errors must map into the firmware initialization error boundary",
    )

def main() -> int:
    errors: list[str] = []
    check_boot_macros(errors)
    check_iconoir_contract(errors)
    check_kspt_boot_tests(errors)
    check_module_owners(errors)
    check_storage_facades(errors)
    check_firmware_warning_contract(ROOT, errors)
    check_boot_self_test_feature_contract(ROOT, errors)
    check_board_partition_contract(ROOT, errors)
    check_security_integration_contract(ROOT, errors)
    check_wallet_recovery_contract(ROOT, errors)
    check_signing_boot_api_contract(errors)
    check_refactored_firmware_api_contracts(errors)
    check_workflow_menu_adapter_contract(errors)
    check_internal_visibility_contract(errors)
    check_redraw_contract(errors)
    check_firmware_core_test_import_contract(errors)
    check_retry_const_contract(errors)
    check_mutable_sector_slice_contract(errors)
    check_hardware_test_contract(errors)
    check_advanced_security_feature_gates(errors)
    check_sd_persistence_security_contract(errors)
    check_qemu_platform_contract(ROOT, errors)
    check_stack_budget_contract(errors)
    errors.extend(check_production_e2e_coverage(ROOT))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("PASS: firmware source compile contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
