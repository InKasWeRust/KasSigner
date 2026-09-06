"""Feature availability, shared primitives, and stale-path invariants."""

from __future__ import annotations

from pathlib import Path
import re


HEX_HELPER = re.compile(
    r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*(?:hex[^\s(]*nibble|nibble[^\s(]*hex)[A-Za-z0-9_]*)\s*\("
)
VOLATILE_ZERO_LOOP = re.compile(
    r"(?ms)for\s+\w+\s+in\s+[^\{]+iter_mut\(\)[^\{]*\{.{0,240}?"
    r"write_volatile\([^,]+,\s*(?:0|0x00|0u8)\s*\)"
)


def _source(path: Path) -> str:
    return path.read_text(errors="ignore")

def _check_explicit_module_paths(root: Path) -> list[str]:
    errors: list[str] = []
    for source_root in (root / "apps", root / "crates"):
        for path in source_root.rglob("*.rs"):
            source = _source(path)
            for relative in re.findall(r'#\[path\s*=\s*"([^"]+)"\]', source):
                target = path.parent / relative
                if not target.is_file():
                    errors.append(
                        f"explicit Rust module path does not exist: "
                        f"{path.relative_to(root)} -> {relative}"
                    )
    return errors


def _check_camera_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    camera = root / "apps/signer-firmware/src/runtime/interactions/camera_loop"
    sources = {path: _source(path) for path in camera.rglob("*.rs")}
    combined = "\n".join(sources.values())
    render_source = sources.get(camera / "dvp_capture.rs", "")
    render_match = re.search(
        r"(?ms)(?:unsafe\s+)?fn\s+render_and_copy_frame\b(?P<body>.*?)(?=\n(?:unsafe\s+)?fn\s+|\Z)",
        render_source,
    )
    if not render_match or "data: &[u8]" not in render_match.group("body"):
        errors.append("camera frame renderer must receive an explicit data slice")
    elif "buf_back" in render_match.group("body"):
        errors.append("camera frame renderer must not reference an out-of-scope DMA buffer")
    if re.search(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+mut\s+", combined):
        errors.append("camera controller state must remain owned by CameraSessionState, not static mut")
    if "pub struct CameraSessionState" not in combined:
        errors.append("camera controller lost its explicit CameraSessionState owner")
    if "0x6004_1000" in combined:
        errors.append("camera controller must not manipulate LCD_CAM registers outside ESP-HAL")
    redraw = _source(root / "apps/signer-firmware/src/ui/redraw/device.rs")
    scan_match = re.search(r"(?ms)AppState::ScanQR\s*=>\s*\{(?P<body>.*?)\n\s*\}", redraw)
    if scan_match and "draw_camera_screen" in scan_match.group("body"):
        errors.append("generic redraw must not own ScanQR camera entry rendering")
    if "QR_RESET_FLAG" in redraw or "QR_RESET_FLAG" in _source(root / "apps/signer-firmware/src/main.rs"):
        errors.append("camera entry reset must remain session-owned, not global-atomic-owned")
    return errors


def _check_silent_availability(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"
    required = {
        firmware / "runtime/interactions/settings/mod.rs": "pub fn handle_settings_touch",
        firmware / "wallet/mnemonic/validation.rs": "pub fn validate",
        firmware / "services/raw_key.rs": "decode_hex_nibble",
    }
    for path, symbol in required.items():
        source = _source(path)
        if symbol not in source:
            errors.append(f"production-required symbol is missing: {path.relative_to(root)}::{symbol}")
        gated = re.search(
            rf'#\[cfg\(not\(feature\s*=\s*"silent"\)\)\]\s*[^\n]*\b{re.escape(symbol.split()[-1])}\b',
            source,
        )
        if gated:
            errors.append(
                f"silent feature removes production-required symbol: "
                f"{path.relative_to(root)}::{symbol.split()[-1]}"
            )
    return errors


def _check_shared_primitives(root: Path) -> list[str]:
    errors: list[str] = []
    shared = root / "crates/shared-signer/src/bytes.rs"
    shared_source = _source(shared)
    for symbol in ("decode_hex_nibble", "volatile_clear", "zeroize_bytes", "zeroize_u16"):
        if f"fn {symbol}" not in shared_source:
            errors.append(f"shared byte primitive is missing: {symbol}")

    for source_root in (root / "apps", root / "crates", root / "tools"):
        for path in source_root.rglob("*.rs"):
            if path == shared or any(part in {"external", "target", "generated"} for part in path.parts):
                continue
            source = _source(path)
            relative = path.relative_to(root)
            for helper in HEX_HELPER.findall(source):
                errors.append(f"duplicate hexadecimal nibble helper {helper}: {relative}")
            if VOLATILE_ZERO_LOOP.search(source):
                errors.append(f"local volatile zeroization loop bypasses shared primitive: {relative}")

    firmware = root / "apps/signer-firmware/src"
    touch_contract = root / "crates/signer-firmware-core/src/input/touch.rs"
    touch_facade = firmware / "hw/shared/touch.rs"
    touch_patterns = {
        "TouchEventType": r"\benum\s+TouchEventType\b",
        "TouchPoint": r"\bstruct\s+TouchPoint\b",
        "TouchState": r"\benum\s+TouchState\b",
        "TouchZone": r"\bstruct\s+TouchZone\b",
    }
    touch_owner_roots = (
        firmware,
        root / "crates/shared-signer/src",
        root / "crates/signer-firmware-core/src",
    )
    for symbol, pattern in touch_patterns.items():
        owners = sorted(
            path.relative_to(root)
            for source_root in touch_owner_roots
            for path in source_root.rglob("*.rs")
            if re.search(pattern, _source(path))
        )
        expected = [touch_contract.relative_to(root)]
        if owners != expected:
            errors.append(f"board-neutral {symbol} must have one firmware-core owner: {owners}")

    # TouchState and TouchZone are consumed by both hardware implementations and
    # belong in the board-neutral firmware facade. Raw TouchEventType/TouchPoint
    # are only exposed by the Waveshare driver; forcing them through hw/shared
    # makes M5Stack builds fail the crate-level deny(unused_imports) policy.
    touch_facade_source = _source(touch_facade)
    for symbol in ("TouchState", "TouchZone"):
        if symbol not in touch_facade_source:
            errors.append(f"firmware shared touch facade must re-export {symbol}")

    waveshare_touch = firmware / "hw/waveshare/touch/mod.rs"
    waveshare_touch_source = _source(waveshare_touch)
    for symbol in ("TouchEventType", "TouchPoint"):
        if symbol not in waveshare_touch_source:
            errors.append(f"Waveshare touch facade must re-export {symbol}")
    return errors


def _check_firmware_unsafe_state(root: Path) -> list[str]:
    errors: list[str] = []
    firmware_root = root / "apps/signer-firmware/src"
    static_mut = re.compile(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+mut\s+")
    for path in firmware_root.rglob("*.rs"):
        match = static_mut.search(_source(path))
        if match:
            line = _source(path).count("\n", 0, match.start()) + 1
            errors.append(
                f"mutable firmware global bypasses owned/atomic state: "
                f"{path.relative_to(root)}:{line}"
            )

    camera_dma_root = firmware_root / "hw/waveshare/cameras/dma"
    camera_sources = {
        path.name: _source(path)
        for path in camera_dma_root.glob("*.rs")
    }
    source = "\n".join(camera_sources.values())
    for obsolete in ("pub fn get_frame", "pub fn get_entropy_bytes", "&'static [u8]"):
        if obsolete in source:
            errors.append(f"camera DMA exposes obsolete static-lifetime API: {obsolete}")
    required_files = {"buffers.rs", "capture.rs", "descriptors.rs", "owner.rs", "registers.rs", "mod.rs"}
    missing_files = sorted(required_files - camera_sources.keys())
    if missing_files:
        errors.append(f"camera DMA responsibility modules are missing: {missing_files}")
    for required in ("struct CameraDma", "struct CameraDmaSlot", "pub fn with_frame", "pub fn copy_entropy_sample"):
        if required not in source:
            errors.append(f"camera DMA owner contract is missing: {required}")
    return errors


def _check_bip340_release_path(root: Path) -> list[str]:
    errors: list[str] = []
    obsolete = root / "tools/firmware/gen_hash/signing.rs"
    if obsolete.exists():
        errors.append("tool-local Schnorr implementation must not return")
    shared = _source(root / "crates/offline-signer/src/crypto/schnorr.rs")
    for required in ("k256::schnorr", "sign_raw", "verify_raw"):
        if required not in shared:
            errors.append(f"shared BIP340 implementation is missing: {required}")
    for forbidden in ("generate_rfc6979_nonce", "has_even_y", "SHA256(R.x"):
        if forbidden in shared:
            errors.append(f"custom or misleading Schnorr implementation remains: {forbidden}")
    tool = _source(root / "tools/firmware/lib.rs")
    for required in (
        "offline_signer::crypto::schnorr::schnorr_sign",
        "offline_signer::crypto::schnorr::schnorr_verify",
        "signer_firmware_core::update::release::PRODUCTION_RELEASE_PUBKEY",
        "signer_firmware_core::update::release::DEV_TEST_PUBKEY",
        "sign_test_firmware_hash",
    ):
        if required not in tool:
            errors.append(f"firmware release tool bypasses production BIP340 path: {required}")
    verifier = _source(root / "apps/signer-firmware/src/services/verify/signature.rs")
    if "signer_firmware_core::update::release::PRODUCTION_RELEASE_PUBKEY" not in verifier:
        errors.append("firmware verification must consume the shared release public key")
    vector = root / "qa/tests/integration/firmware_signing.rs"
    if not vector.is_file() or "generator_matches_bip340_vector_zero_and_production_verifier" not in _source(vector):
        errors.append("cross-package BIP340 release compatibility test is missing")
    return errors


def _check_sensitive_zeroization(root: Path) -> list[str]:
    errors: list[str] = []
    sensitive_paths = (
        "apps/signer-firmware/src/wallet/mnemonic/generation.rs",
        "apps/signer-firmware/src/runtime/interactions/seed/bip85/derivation.rs",
        "apps/signer-firmware/src/runtime/interactions/tx/commit_results.rs",
        "apps/signer-firmware/src/runtime/interactions/tx/commit_reveal.rs",
        "crates/offline-signer/src/transaction/kspt/signing/multisig.rs",
        "crates/offline-signer/src/transaction/kspt/signing/covenant.rs",
        "crates/offline-signer/src/transaction/kspt/signing/multi_address.rs",
        "tools/firmware/gen_hash/output.rs",
        "apps/signer-firmware/src/runtime/interactions/export/private_key.rs",
    )
    for relative in sensitive_paths:
        source = _source(root / relative)
        if ".fill(0)" in source:
            errors.append(f"sensitive buffer uses optimizable fill instead of shared zeroization: {relative}")
        if "zeroize_" not in source:
            errors.append(f"sensitive module does not use shared zeroization: {relative}")
    release_source = _source(root / "tools/firmware/gen_hash/output.rs")
    for required in ("zeroize_bytes(&mut key_data)", "zeroize_bytes(&mut private_key)"):
        if required not in release_source:
            errors.append(f"firmware release key cleanup is incomplete: {required}")
    return errors


def _check_repository_hygiene(root: Path) -> list[str]:
    errors: list[str] = []
    dockerignore = _source(root / ".dockerignore")
    if re.search(r"(?m)^Install\.sh$", dockerignore):
        errors.append(".dockerignore contains obsolete mixed-case Install.sh")

    attributes = _source(root / ".gitattributes")
    for recursive in (
        "apps/kassee-web/web/lib/** linguist-vendored",
        "apps/kassee-web/web/constellation/** linguist-generated",
    ):
        if recursive not in attributes:
            errors.append(f".gitattributes lost recursive generated/vendor classification: {recursive}")

    version_source = _source(root / "apps/signer-firmware/src/version.rs")
    version_requirements = ('assert!(MINOR < 100', 'assert!(PATCH < 100',
        '(MAJOR as u32) * 10_000 + (MINOR as u32) * 100 + PATCH as u32')
    for required in version_requirements:
        if required not in version_source:
            errors.append(f"firmware semantic version encoding lost its stable bound: {required}")
    if "1.0" + ".3" in "\n".join(
        _source(path) for path in (root / "apps/signer-firmware/src").rglob("*.rs")
    ):
        errors.append("stale release-specific wording remains in firmware source")
    return errors



def _check_ci_firmware_matrix(root: Path) -> list[str]:
    """Require CI to reach the firmware matrix through the canonical run-all catalog."""
    workflow = root / ".github/workflows/core.yml"
    catalog = root / "qa/linux/runner/catalog.sh"
    if not workflow.is_file() or "make test STRICT_LOCKFILES=1" not in _source(workflow):
        return ["push/PR CI must execute the fast contributor suite through the Make facade"]
    if not catalog.is_file():
        return ["master QA catalog is missing"]
    catalog_source = _source(catalog)
    if "integration.signer-firmware-builds" not in catalog_source \
            or "check_firmware_builds.py" not in catalog_source:
        return ["canonical QA catalog lost the firmware cargo-check matrix"]
    return []



def _check_remediation_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"
    interactions = firmware / "runtime/interactions"
    controller_sources = {
        path: _source(path) for path in interactions.rglob("*.rs")
    }

    redraw_owners = sorted(
        path.relative_to(root)
        for path, source in controller_sources.items()
        if re.search(r"\bstruct\s+RedrawFlag\b", source)
    )
    expected_redraw_owner = [Path("apps/signer-firmware/src/runtime/interactions/support/feedback.rs")]
    if redraw_owners != expected_redraw_owner:
        errors.append(
            f"interaction redraw accumulator must be owned only by feedback.rs: {redraw_owners}"
        )
    invalid_redraw_calls = sorted(
        path.relative_to(root)
        for path, source in controller_sources.items()
        if re.search(r"(?:ad|self)\.runtime\.needs_redraw\s*\.\s*set\s*\(", source)
    )
    if invalid_redraw_calls:
        errors.append(f"plain runtime redraw bool is used as a wrapper: {invalid_redraw_calls}")

    camera = interactions / "camera_loop"
    camera_sources = {path: _source(path) for path in camera.rglob("*.rs")}
    combined_camera = "\n".join(camera_sources.values())
    if len(re.findall(r"\bfn\s+route_camera_back\s*\(", combined_camera)) != 1:
        errors.append("camera back navigation must have exactly one policy owner")
    touch_input_source = camera_sources.get(camera / "touch_input.rs", "")
    capture_source = camera_sources.get(camera / "waveshare_capture.rs", "")
    event_dispatch = _source(firmware / "runtime/event_loop/dispatch.rs")
    if "pub(crate) fn route_camera_back" not in touch_input_source:
        errors.append("camera back navigation policy must remain owned by touch_input.rs")
    if "runtime::interactions::camera_loop::route_camera_back($ad)" not in event_dispatch:
        errors.append("event-loop touch owner must dispatch camera Back through the shared policy")
    for token in ("touch_service::", "read_touch(", "route_camera_back(ad)"):
        if token in capture_source:
            errors.append(f"camera capture must not own touch/back dispatch: {token}")

    navigation = firmware / "ui/screens/navigation"
    menu_source = _source(navigation / "menu.rs")
    secondary_source = _source(navigation / "secondary.rs")
    if menu_source.count("fn draw_navigation_card") != 1:
        errors.append("navigation card presentation must have exactly one rendering owner")
    if menu_source.count("draw_navigation_card(") < 2:
        errors.append("primary navigation menu bypasses shared card rendering")
    if "draw_navigation_card(" not in secondary_source:
        errors.append("secondary navigation menu bypasses shared card rendering")
    if "RoundedRectangle::new" in secondary_source:
        errors.append("secondary navigation menu duplicates card presentation details")

    feedback_owner = interactions / "support/feedback.rs"
    direct_feedback = sorted(
        path.relative_to(root)
        for path, source in controller_sources.items()
        if path != feedback_owner
        and re.search(r"\.draw_(?:rejected|success)_screen\s*\(", source)
    )
    if direct_feedback:
        errors.append(
            f"interaction transient feedback bypasses feedback.rs: {direct_feedback}"
        )

    menu_selection_owner = interactions / "support/menu_selection.rs"
    direct_menu_mapping = sorted(
        path.relative_to(root)
        for path, source in controller_sources.items()
        if path != menu_selection_owner
        and re.search(
            r"\.(?:visible_to_absolute|can_page_up|can_page_down)\s*\(", source
        )
    )
    if direct_menu_mapping:
        errors.append(
            f"interaction menu hit-testing bypasses menu_selection.rs: {direct_menu_mapping}"
        )

    # The pure controller boundary may classify normalized input only. Effectful
    # hardware adapters deliberately live under runtime/interactions.
    pure_controller = _source(firmware / "controllers.rs")
    for token in ("esp_hal", "crate::hw", "crate::services", "crate::ui", "PersistentWallet", "BootDisplay"):
        if token in pure_controller:
            errors.append(f"pure controller boundary regained effectful dependency: {token}")
    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_explicit_module_paths(root),
        *_check_camera_ownership(root),
        *_check_silent_availability(root),
        *_check_shared_primitives(root),
        *_check_firmware_unsafe_state(root),
        *_check_bip340_release_path(root),
        *_check_sensitive_zeroization(root),
        *_check_repository_hygiene(root),
        *_check_ci_firmware_matrix(root),
        *_check_remediation_ownership(root),
    ]
