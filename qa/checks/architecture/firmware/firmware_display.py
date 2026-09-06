"""Firmware display transport and UI presentation boundaries."""

from __future__ import annotations

from pathlib import Path
import re

UI_DISPLAY_MODULES = {
    "mod.rs": 80,
    "boot.rs": 420,
    "icons.rs": 180,
    "palette.rs": 80,
    "typography.rs": 320,
}

ICON_SUBMODULES = {
    "classification.rs": 120,
    "drawing.rs": 300,
}

TRANSPORT_MODULES = {
    "shared/display.rs": 100,
    "waveshare/display.rs": 160,
    "m5stack/display.rs": 160,
}

EXPECTED_PRESENTATION_METHODS = (
    "show_verification_screen",
    "show_logo_screen",
    "show_panic_screen",
    "clear_screen",
    "draw_frame_counter",
    "draw_sig_status",
    "draw_back_button",
    "clear_keep_nav",
)

PRESENTATION_SYMBOLS = (
    "draw_lato_title",
    "draw_lato_title_opaque",
    "draw_lato_body",
    "draw_lato_18",
    "draw_lato_22",
    "draw_lato_22_opaque",
    "draw_lato_hint",
    "draw_oswald_header",
    "draw_rubik_big",
    "draw_oswald_sub",
    "measure_title",
    "measure_body",
    "measure_18",
    "measure_22",
    "measure_header",
    "measure_big",
    "measure_sub",
    "measure_hint",
    "draw_menu_icon",
)

BOARD_CONTRACTS = {
    "waveshare/display.rs": {
        "model": "models::ST7789",
        "orientation": "Rotation::Deg90",
        "color_order": "ColorOrder::Rgb",
        "extra": ".display_size(240, 320)",
        "transport": "ExclusiveDevice::new_no_delay",
    },
    "m5stack/display.rs": {
        "model": "models::ILI9342CRgb565",
        "orientation": "Rotation::Deg180",
        "color_order": "ColorOrder::Bgr",
        "extra": ".set_orientation(",
        "transport": "lcd_device(cs_pin)?",
    },
}

UI_PROFILE_FRAGMENTS = (
    'board_label: "Waveshare ESP32-S3-Touch-LCD-2"',
    "verification_version_y: 135",
    "verification_hash_y: 165",
    'board_label: "M5Stack CoreS3 Lite"',
    "verification_version_y: 125",
    "verification_hash_y: 155",
    "TransactionMenuIcon::Coin",
    "audio: false",
    "TransactionMenuIcon::Download",
    "audio: true",
)


def impl_method_names(source: str, type_name: str) -> tuple[str, ...]:
    impl_match = re.search(rf"impl<'a>\s+{re.escape(type_name)}<'a>\s*\{{", source)
    if not impl_match:
        return ()
    start = source.find("{", impl_match.start())
    depth = 0
    index = start
    while index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                body = source[start + 1:index]
                return tuple(re.findall(r"(?m)^\s*pub fn\s+([A-Za-z_]\w*)", body))
        index += 1
    return ()


def _check_display_inventories(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    firmware_root = root / "apps/signer-firmware/src"
    hardware_root = firmware_root / "hw"
    ui_root = firmware_root / "ui/display"
    for board_root in (hardware_root / "shared", hardware_root / "waveshare", hardware_root / "m5stack"):
        if (board_root / "presentation").exists():
            errors.append(f"display presentation must not live under {board_root.relative_to(root)}")

    actual_transport = {
        relative for relative in TRANSPORT_MODULES
        if (hardware_root / relative).is_file()
    }
    if actual_transport != set(TRANSPORT_MODULES):
        errors.append(
            "firmware hardware display inventory changed: expected "
            f"{sorted(TRANSPORT_MODULES)}, got {sorted(actual_transport)}"
        )

    for name, limit in TRANSPORT_MODULES.items():
        path = hardware_root / name
        if not path.is_file():
            errors.append(f"required firmware display transport is missing: {path.relative_to(root)}")
            continue
        line_count = len(path.read_text(errors="ignore").splitlines())
        if line_count > limit:
            errors.append(
                f"firmware display transport exceeds SRP limit: "
                f"{path.relative_to(root)} ({line_count} > {limit})"
            )

    shadow_support = firmware_root / "hw/shared/display_support/mod.rs"
    if not shadow_support.is_file():
        errors.append("required screenshot display support is missing")
    elif len(shadow_support.read_text(errors="ignore").splitlines()) > 180:
        errors.append("screenshot display support exceeds 180-line SRP limit")

    ui_modules = {path.name for path in ui_root.glob("*.rs")}
    expected_ui_modules = set(UI_DISPLAY_MODULES) | {"icon_data.rs"}
    if ui_modules != expected_ui_modules:
        errors.append(
            "firmware UI display inventory changed: expected "
            f"{sorted(expected_ui_modules)}, got {sorted(ui_modules)}"
        )

    combined_ui = ""
    for name, limit in UI_DISPLAY_MODULES.items():
        path = ui_root / name
        if not path.is_file():
            errors.append(f"required firmware UI display module is missing: {path.relative_to(root)}")
            continue
        source = path.read_text(errors="ignore")
        combined_ui += "\n" + source
        line_count = len(source.splitlines())
        if line_count > limit:
            errors.append(
                f"firmware UI display module exceeds SRP limit: "
                f"{path.relative_to(root)} ({line_count} > {limit})"
            )

    icon_root = ui_root / "icons"
    actual_icon_modules = {path.name for path in icon_root.glob("*.rs")}
    if actual_icon_modules != set(ICON_SUBMODULES):
        errors.append(
            "firmware menu-icon submodule inventory changed: expected "
            f"{sorted(ICON_SUBMODULES)}, got {sorted(actual_icon_modules)}"
        )
    for name, limit in ICON_SUBMODULES.items():
        path = icon_root / name
        if not path.is_file():
            errors.append(f"required firmware menu-icon module is missing: {path.relative_to(root)}")
            continue
        source = path.read_text(errors="ignore")
        combined_ui += "\n" + source
        if len(source.splitlines()) > limit:
            errors.append(
                f"firmware menu-icon module exceeds SRP limit: "
                f"{path.relative_to(root)} ({len(source.splitlines())} > {limit})"
            )

    icon_data = ui_root / "icon_data.rs"
    if not icon_data.is_file():
        errors.append("firmware UI icon data is missing")

    return errors, combined_ui


def _check_ui_presentation(root: Path, combined_ui: str) -> list[str]:
    errors: list[str] = []
    firmware_root = root / "apps/signer-firmware/src"
    hardware_root = firmware_root / "hw"
    ui_root = firmware_root / "ui/display"
    forbidden_ui_transport_tokens = (
        "esp_hal::",
        "embedded_hal_bus::",
        "mipidsi::",
        "StaticCell",
        "ST7789",
        "ILI9342",
    )
    for token in forbidden_ui_transport_tokens:
        if token in combined_ui:
            errors.append(f"display transport dependency leaked into UI presentation: {token}")

    ownership = {
        "palette.rs": ("KASPA_TEAL", "COLOR_BG"),
        "typography.rs": ("draw_lato_title", "measure_hint", "crate::ui::prop_fonts"),
        "icons.rs": ("draw_menu_icon", "MenuIconProfile", "mod classification", "mod drawing"),
        "boot.rs": (
            "show_verification_screen",
            "clear_keep_nav",
            "crate::services::fw_update",
            "crate::hw::display::BootDisplay",
            'include_bytes!("../../../assets/kascoin_90.raw")',
            'include_bytes!("../../../assets/logo_320x240.raw")',
        ),
        "icon_data.rs": ("ICON_BACK", "ICON_TRASH"),
    }
    for module_name, symbols in ownership.items():
        source = (ui_root / module_name).read_text(errors="ignore")
        for symbol in symbols:
            if symbol not in source:
                errors.append(f"firmware UI display ownership changed: {symbol} missing from {module_name}")

    icon_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (ui_root / "icons").glob("*.rs")
    )
    for symbol in ("PREFIX_ICONS", "embedded_iconoir", "draw_classified_icon"):
        if symbol not in icon_source:
            errors.append(f"firmware menu-icon decomposition lost ownership symbol: {symbol}")

    combined_profiles = (
        (ui_root / "boot.rs").read_text(errors="ignore")
        + "\n"
        + (ui_root / "icons.rs").read_text(errors="ignore")
        + "\n"
        + icon_source
    )
    for fragment in UI_PROFILE_FRAGMENTS:
        if fragment not in combined_profiles:
            errors.append(f"firmware UI display profile lost board contract: {fragment}")

    boot_source = (ui_root / "boot.rs").read_text(errors="ignore")
    presentation_methods = impl_method_names(boot_source, "BootDisplay")
    if presentation_methods != EXPECTED_PRESENTATION_METHODS:
        errors.append(
            "firmware display presentation API changed: expected "
            f"{EXPECTED_PRESENTATION_METHODS}, got {presentation_methods}"
        )

    return errors


def _check_hardware_transport(root: Path) -> list[str]:
    errors: list[str] = []
    firmware_root = root / "apps/signer-firmware/src"
    hardware_root = firmware_root / "hw"
    ui_root = firmware_root / "ui/display"
    combined_hardware = ""
    common_source = (hardware_root / "shared/display.rs").read_text(errors="ignore")
    for fragment in ("clear_and_settle", "Rgb565::BLACK"):
        if fragment not in common_source:
            errors.append(f"shared display transport primitive is missing: {fragment}")
    for fragment in ("DisplayInterface", "spi_interface", "SPI_BUFFER"):
        if fragment in common_source:
            errors.append(f"board-specific display transport leaked into shared display: {fragment}")
    for facade_name, contract in BOARD_CONTRACTS.items():
        path = hardware_root / facade_name
        if not path.is_file():
            continue
        source = path.read_text(errors="ignore")
        combined_hardware += "\n" + source

        required_fragments = (
            "pub struct BootDisplay<'a>",
            "pub type TeeDisplay<'a> = crate::hw::shared::display_support::TeeDisplay<PanelDisplay<'a>>;",
            contract["transport"],
            "shared::display::clear_and_settle",
            contract["model"],
            contract["orientation"],
            contract["color_order"],
            contract["extra"],
        )
        for fragment in required_fragments:
            if fragment not in source:
                errors.append(f"firmware display transport lost board contract: {facade_name}: {fragment}")

        methods = impl_method_names(source, "BootDisplay")
        if methods != ("new",):
            errors.append(
                f"hardware display facade owns non-transport methods in {facade_name}: {methods}"
            )

        forbidden_transport_ownership = (
            "crate::ui::",
            "crate::services::",
            "embedded_iconoir",
            "BootPresentation",
            "MenuIconProfile",
            "TransactionMenuIcon",
            "board_label:",
            "verification_version_y:",
            "verification_hash_y:",
        )
        for token in forbidden_transport_ownership:
            if token in source:
                errors.append(f"UI presentation remains in hardware display {facade_name}: {token}")
        for symbol in PRESENTATION_SYMBOLS:
            if re.search(rf"(?m)^pub\(crate\) fn\s+{re.escape(symbol)}\b", source):
                errors.append(f"UI display helper remains implemented in {facade_name}: {symbol}")

    for token in ("crate::ui::", "crate::services::", "embedded_iconoir", "prop_fonts"):
        if token in combined_hardware:
            errors.append(f"hardware display depends upward on presentation/service code: {token}")

    hw_mod = (firmware_root / "hw/mod.rs").read_text(errors="ignore")
    if "icon_data" in hw_mod:
        errors.append("UI icon data is still exposed through hw/mod.rs")

    ui_mod = (firmware_root / "ui/mod.rs").read_text(errors="ignore")
    if "pub mod display;" not in ui_mod:
        errors.append("ui/mod.rs must expose the display presentation facade")

    all_firmware = "\n".join(path.read_text(errors="ignore") for path in firmware_root.rglob("*.rs"))
    for stale in (
        "crate::hw::icon_data",
        "crate::hw::display::COLOR_",
        "crate::hw::display::KASPA_",
        "crate::hw::display::draw_",
        "crate::hw::display::measure_",
        "use crate::hw::display::*;",
    ):
        if stale in all_firmware:
            errors.append(f"stale hardware-owned display presentation reference remains: {stale}")

    return errors



def _check_font_transport_batching(root: Path) -> list[str]:
    errors: list[str] = []
    fonts = (root / "apps/signer-firmware/src/ui/prop_fonts.rs").read_text(errors="ignore")
    if "display.draw_iter(core::iter::once" in fonts:
        errors.append(
            "firmware proportional-font renderer regressed to one display transaction per pixel"
        )
    draw_start = fonts.find("pub fn draw_prop_text<")
    opaque_start = fonts.find("pub fn draw_prop_text_opaque<")
    transparent = fonts[draw_start:opaque_start] if draw_start >= 0 and opaque_start > draw_start else ""
    for fragment in ("let pixels = (0..height as usize).flat_map", "display.draw_iter(pixels)"):
        if fragment not in transparent:
            errors.append(f"firmware proportional-font batching contract changed: missing {fragment}")

    opaque = fonts[opaque_start:] if opaque_start >= 0 else ""
    for fragment in (
        "let cell_width = cw.saturating_add(1)",
        "(0..cell_width).map",
        "display.fill_contiguous(&area, pixel_iter)",
    ):
        if fragment not in opaque:
            errors.append(f"firmware opaque-font batching contract changed: missing {fragment}")
    if "let gap_area = Rectangle::new" in opaque:
        errors.append("firmware opaque-font renderer regressed to a second display submit for glyph spacing")

    receive = (root / "apps/signer-firmware/src/ui/screens/wallet/address/receive.rs").read_text(errors="ignore")
    if "draw_lato_title_opaque" not in receive:
        errors.append("Receive address redraw must use opaque batched title glyphs")
    return errors

def check(root: Path) -> list[str]:
    inventory_errors, combined_ui = _check_display_inventories(root)
    return [
        *inventory_errors,
        *_check_ui_presentation(root, combined_ui),
        *_check_hardware_transport(root),
        *_check_font_transport_batching(root),
    ]
