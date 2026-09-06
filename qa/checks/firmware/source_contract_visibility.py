"""Focused firmware source-contract checks."""
from source_contract_support import read, require

def check_internal_visibility_contract(errors: list[str]) -> None:
    context = read("apps/signer-firmware/src/runtime/interactions/sd/common/context.rs")
    for field in (
        "ad",
        "boot_display",
        "delay",
        "i2c",
        "sd_card_type",
        "list_zones",
        "page_up_zone",
        "page_down_zone",
        "x",
        "y",
        "is_back",
    ):
        if f"{field}:" in context:
            require(
                errors,
                f"pub(in crate::runtime::interactions::sd) {field}:" in context,
                f"SD context field {field} must be visible to the SD controller subtree",
            )

    filename = read("apps/signer-firmware/src/runtime/interactions/sd/common/filename.rs")
    for field in (
        "extension",
        "back_state",
        "filename_state",
        "next_state",
        "redraw_if_exists",
        "redraw_if_available",
    ):
        require(
            errors,
            f"pub(in crate::runtime::interactions::sd) {field}:" in filename,
            f"FilenameWorkflow field {field} is too private",
        )

    listing = read("apps/signer-firmware/src/runtime/interactions/sd/common/list_navigation.rs")
    for field in ("allow_delete", "current_state", "back_state"):
        require(
            errors,
            f"pub(in crate::runtime::interactions::sd) {field}:" in listing,
            f"FileListWorkflow field {field} is too private",
        )

    shared = read("apps/signer-firmware/src/runtime/interactions/sd/common/shared.rs")
    require(
        errors,
        "pub(in crate::runtime::interactions::sd) type ParsedMultisigDescriptor" in shared
        and "kassigner_protocol::wire::multisig_descriptor::ParsedMultisigDescriptor" in shared,
        "SD descriptor parsing must reuse the canonical kassigner-protocol descriptor type",
    )
    require(
        errors,
        "pub(in crate::runtime::interactions::sd) fn parse_descriptor" in shared,
        "parse_descriptor must remain visible throughout the SD controller subtree",
    )
    require(
        errors,
        ".filter(|parsed| parsed.is_hd())" in shared,
        "firmware SD descriptor adapter must reject legacy static multi(...) descriptors",
    )
    require(
        errors,
        "struct ParsedMultisigDescriptor" not in shared,
        "SD controller must not duplicate the canonical multisig descriptor type",
    )

    sd_mod = read("apps/signer-firmware/src/runtime/interactions/sd/mod.rs")
    require(
        errors,
        "use shared::{parse_descriptor, sd_file_exists};" in sd_mod,
        "SD descriptor helpers must remain private ancestor imports for child modules",
    )
    for overly_broad in (
        "pub(super) use shared::{parse_descriptor",
        "pub(in crate::runtime::interactions::sd) use shared::parse_descriptor",
        "pub(crate) use shared::parse_descriptor",
    ):
        require(
            errors,
            overly_broad not in sd_mod,
            "SD descriptor parser must not be re-exported beyond its declared visibility",
        )

    qr = read("apps/signer-firmware/src/ui/screens/components/qr_renderer.rs")
    for method in ("draw_qr_screen_with_options", "draw_numeric_qr"):
        require(
            errors,
            f"pub(in crate::ui::screens) fn {method}" in qr,
            f"QR renderer method {method} must match its option type visibility",
        )

def check_redraw_contract(errors: list[str]) -> None:
    source = read("apps/signer-firmware/src/runtime/interactions/sd/exports/qr.rs")
    mode_choice = source.split("pub(crate) fn handle_show_qr_mode_choice", 1)[1]
    require(
        errors,
        "let mut needs_redraw = false;" not in mode_choice,
        "QR mode choice initializes a redraw flag that is always overwritten",
    )

def check_firmware_core_test_import_contract(errors: list[str]) -> None:
    source = read("crates/signer-firmware-core/src/unit_tests/firmware_decisions/navigation.rs")
    require(
        errors,
        "use crate::input::{" in source,
        "firmware-core navigation tests must import through crate::input",
    )
    for stale in ("button::ButtonEvent", "navigation::{next_page"):
        require(
            errors,
            not source.startswith("use crate::{") or stale not in source,
            "firmware-core navigation tests must not use stale crate-root module imports",
        )

def check_retry_const_contract(errors: list[str]) -> None:
    source = read("crates/signer-firmware-core/src/storage/retry.rs")
    tests = read("crates/signer-firmware-core/src/unit_tests/firmware_decisions/retry.rs")
    require(
        errors,
        "retry_response != Some(response)" not in source,
        "firmware-core retry const fn must not use non-const Option equality",
    )
    require(
        errors,
        "match retry_response" in source,
        "firmware-core retry classification must use stable const pattern matching",
    )
    require(
        errors,
        "const CONST_CLASSIFIED_RETRY: RetryAction" in tests,
        "firmware-core retry policy must remain const-evaluable in a compile test",
    )
