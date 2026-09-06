"""Warning-free feature and generated-source contracts for signer firmware."""

from __future__ import annotations

import re
from pathlib import Path


def check_firmware_warning_contract(root: Path, errors: list[str]) -> None:
    """Keep every production feature set warning-free without broad allowances."""

    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    main = read("apps/signer-firmware/src/main.rs")
    require(
        '#![deny(unused_imports)]' in main,
        "signer-firmware: unused imports must remain denied in every feature set",
    )
    require(
        '#![warn(dead_code)]' in main,
        "signer-firmware: dead-code diagnostics must remain enabled in every feature set",
    )
    hil_dead_code_allow = '#![cfg_attr(feature = "hardware-tests", allow(dead_code))]'
    require(
        hil_dead_code_allow not in main,
        "signer-firmware: hardware-tests dead-code suppression must not be crate-wide",
    )
    for relative in (
        "boot/mod.rs", "controllers.rs", "crypto/mod.rs", "hw/mod.rs",
        "runtime/mod.rs", "services/mod.rs", "ui/mod.rs", "wallet/mod.rs",
    ):
        require(
            hil_dead_code_allow in read(f"apps/signer-firmware/src/{relative}"),
            f"signer-firmware: hardware-tests dead-code suppression must be owned by {relative}",
        )
    require(
        not re.search(r"#!\s*\[.*allow\s*\(\s*dead_code\s*\).*\]", main),
        "signer-firmware: crate-wide dead_code allowances are forbidden",
    )
    require(
        "allow(unused_imports)" not in main,
        "signer-firmware: unused imports must never be allowed, including hardware-tests",
    )
    require(
        0 <= main.find("macro_rules! log") < main.find("mod boot;"),
        "signer-firmware: log! must be defined before the module tree",
    )
    require(
        'if false {\n            let _ = core::format_args!($($arg)+);' in main,
        "signer-firmware: silent log! must remain an expression and consume arguments",
    )
    require(
        '#[cfg_attr(feature = "hardware-tests", allow(unused_variables))]\n'
        '    #[cfg(feature = "m5stack")]\n'
        '    let (i2c, mut boot_display, dvp_camera_opt, cam_dma_buf_opt,' in main,
        "M5Stack hardware-test profile must locally suppress only intentionally retained peripheral owners",
    )

    runtime_facade = read("apps/signer-firmware/src/runtime/mod.rs")
    input_facade = read("apps/signer-firmware/src/runtime/input.rs")
    signing_facade = read("apps/signer-firmware/src/runtime/signing.rs")
    entropy_facade = read("apps/signer-firmware/src/services/entropy/mod.rs")
    sd_facade = read("apps/signer-firmware/src/runtime/interactions/sd/mod.rs")
    camera_facade = read("apps/signer-firmware/src/runtime/interactions/camera_loop.rs")
    require(
        '#[cfg(not(feature = "hardware-tests"))]\npub(crate) mod event_loop;' in runtime_facade,
        "hardware-test builds must not compile the production event-loop facade",
    )
    require(
        'mod routing;' in input_facade
        and '#[cfg(not(feature = "hardware-tests"))]\nmod routing;' not in input_facade
        and 'pub use routing::HandlerGroup;' in input_facade,
        "hardware-test builds compile controllers/navigation and therefore require HandlerGroup routing",
    )
    require(
        'pub use common::context::SdTouchContext;' in sd_facade
        and 'pub use common::routing::handle_sd_touch;' in sd_facade
        and '#[cfg(not(feature = "hardware-tests"))]\npub use common::context::SdTouchContext;' not in sd_facade
        and '#[cfg(not(feature = "hardware-tests"))]\npub use common::routing::handle_sd_touch;' not in sd_facade,
        "hardware-test builds compile onboarding and therefore require SD touch routing",
    )
    for source, symbol in (
        (signing_facade, "pub use workflow::handle_signing_operation_step;"),
        (entropy_facade, "pub use ambient::stage_touch as stage_ambient_touch;"),
        (entropy_facade, "pub use touch::{harden_touch_entropy, touch_timestamp};"),
        (camera_facade, "pub use cycle::run_camera_cycle;"),
        (camera_facade, "pub use state::CameraSessionState;"),
    ):
        hardware_only_gate = f'#[cfg(not(feature = "hardware-tests"))]\n{symbol}'
        workflow_loop_gate = (
            f'#[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))]\n{symbol}'
        )
        require(
            hardware_only_gate in source or workflow_loop_gate in source,
            f"hardware-test builds must not expose production-only facade symbol: {symbol}",
        )

    firmware_src = root / "apps/signer-firmware/src"
    for source_path in firmware_src.rglob("*.rs"):
        source = source_path.read_text(encoding="utf-8")
        for use_decl in re.finditer(r"(?ms)^use\s+.*?;[ \t]*(?:\n|$)", source):
            require(
                re.search(r"\blog\b", use_decl.group(0)) is None,
                f"{source_path.relative_to(root)}: log! is lexically visible; do not import it",
            )

    boot_display = read("apps/signer-firmware/src/ui/display/boot.rs")
    palette_import = re.search(r"(?ms)^use super::\{.*?\};", boot_display)
    require(
        palette_import is not None and "COLOR_ORANGE" in palette_import.group(0),
        "ui/display/boot.rs: signature warning color must be imported from the display palette",
    )

    fat32_facade = read("apps/signer-firmware/src/hw/shared/storage/fat32/mod.rs")
    fat32_directory_helpers = read("apps/signer-firmware/src/hw/shared/storage/fat32/directory/helpers.rs")
    require(
        "pub(super) use policy::detect_fat32_partition;" not in fat32_facade,
        "hw/shared/storage/fat32/mod.rs: internal partition detection must not leak through the facade",
    )
    require(
        "use super::super::policy::detect_fat32_partition;" in fat32_directory_helpers,
        "hw/shared/storage/fat32/directory/helpers.rs: import partition detection directly from its owner",
    )

    matrix_runner = read("tools/build/firmware/matrix_runner.py")
    require(
        'if operation == "check":' in matrix_runner and '"-Dwarnings"' in matrix_runner,
        "firmware build matrix must reject every crate warning",
    )
    lint_runner = read("qa/checks/firmware/check_firmware_lints.py")
    require(
        '"-D", "dead_code"' in lint_runner,
        "firmware lint matrix must reject dead code",
    )

    hash_generator = read("tools/firmware/gen_hash/output.rs")
    require(
        "SigningIdentity::Production => sign_firmware_hash" in hash_generator
        and "SigningIdentity::Development => sign_test_firmware_hash" in hash_generator,
        "firmware hash generator must keep release signatures production-only",
    )
    require(
        "FIRMWARE_HASH_HEX" not in hash_generator,
        "firmware hash generator must not recreate the unused hex constant",
    )
    dockerfile = read("Dockerfile")
    hash_builder = read("tools/build/firmware/build_with_hash.sh")
    require(
        "pub static EXPECTED_FIRMWARE_HASH: [u8; 32] = [" in hash_builder
        and "--read-generated-hash" in hash_builder
        and "FIRMWARE_HASH_HEX" not in hash_builder,
        "firmware convergence helper must require the rodata-static EXPECTED_FIRMWARE_HASH declaration and never depend on the retired hex constant",
    )
    lock_reconciler = read("tools/build/firmware/reconcile_tools_lock.py")
    require(
        "--offline" in lock_reconciler
        and "--locked" in lock_reconciler
        and "introduced external package identities" in lock_reconciler
        and "network fallback is forbidden" in lock_reconciler,
        "firmware hash tools lock repair must remain offline, locked-verified, and identity-monotonic",
    )
    require(
        "reconcile_tools_lock.py" in hash_builder
        and 'cp -p "$TOOLS_LOCK_BACKUP" "$TOOLS_LOCK"' in hash_builder,
        "firmware convergence helper must reconcile and restore the independent tools lock",
    )
    require(
        "build_with_hash.sh --read-generated-hash" in dockerfile
        and "FIRMWARE_HASH_HEX" not in dockerfile,
        "Docker convergence must use the canonical generated hash reader",
    )

    sound_m5 = read("apps/signer-firmware/src/hw/m5stack/sound.rs")
    require(
        '#[cfg(not(feature = "silent"))]\n    {\n        let chip_id = '
        in sound_m5,
        "sound_m5.rs: logging-only AW88298 chip ID must not exist in silent builds",
    )
    require(
        'let chip_id = ((buf[0] as u16) << 8) | buf[1] as u16;\n'
        '    #[cfg(not(feature = "silent"))]'
        not in sound_m5,
        "sound_m5.rs: chip ID binding must remain inside its non-silent block",
    )

    for path in (
        "apps/signer-firmware/src/hw/waveshare/power/battery.rs",
        "apps/signer-firmware/src/hw/m5stack/power/battery.rs",
    ):
        require(
            "pub present: bool" not in read(path),
            f"{path}: unread battery-present field must not return",
        )

    display_facade = read("apps/signer-firmware/src/ui/display/mod.rs")
    require(
        "password_strength" not in display_facade
        and not (root / "apps/signer-firmware/src/ui/display/security.rs").exists(),
        "ui/display: retired password-strength helper must not return as dead production code",
    )

    prop_fonts = read("apps/signer-firmware/src/ui/prop_fonts.rs")
    require(
        "OSWALD_SB_16" not in prop_fonts,
        "ui/prop_fonts.rs: unused Oswald 16px asset must not return",
    )
    for required in ("pub fn draw_prop_text", "pub fn draw_prop_text_opaque", "LATO_22_HEIGHT"):
        require(
            required in prop_fonts,
            f"ui/prop_fonts.rs: warning cleanup removed required {required}",
        )


    mmio = read("apps/signer-firmware/src/hw/shared/mmio.rs")
    lockdown = read("apps/signer-firmware/src/hw/shared/lockdown.rs")
    for helper in ("read", "write", "set_bits", "clear_bits"):
        require(
            f"pub(crate) unsafe fn {helper}" in mmio,
            f"hw/shared/mmio.rs: missing shared MMIO helper {helper}",
        )
    require(
        "use super::mmio::{clear_bits, read, set_bits, write};" in lockdown,
        "shared lockdown must consume the shared MMIO owner",
    )

    gc0308_bus = read("apps/signer-firmware/src/hw/m5stack/cameras/gc0308/bus.rs")
    require(
        "pub fn read_reg" not in gc0308_bus,
        "camera_gc0308/bus.rs: unused diagnostic read wrapper must not return",
    )

    touch_types = read("apps/signer-firmware/src/hw/shared/touch.rs")
    touch_m5 = read("apps/signer-firmware/src/hw/m5stack/touch/mod.rs")
    shared_touch = read("crates/signer-firmware-core/src/input/touch.rs")
    require(
        "Two" not in touch_types
        and "decode_rotated_single_touch" in touch_m5
        and "if points != 1" in shared_touch
        and "return TouchState::NoTouch;" in shared_touch,
        "multi-touch must be ignored at the M5Stack driver boundary",
    )
    for variant in ("Hold {", "SwipeUp", "SwipeDown"):
        require(
            variant not in touch_m5,
            f"M5Stack touch action retains an unconstructed variant: {variant}",
        )

    battery_m5 = read("apps/signer-firmware/src/hw/m5stack/power/battery.rs")
    require(
        "pub voltage_mv:" not in battery_m5,
        "battery_m5.rs: raw voltage must remain an internal percentage input",
    )

    fat32_types = read("apps/signer-firmware/src/hw/shared/storage/fat32/types.rs")
    waveshare_registers = read(
        "apps/signer-firmware/src/hw/waveshare/storage/transport/registers.rs"
    )
    require(
        "None" not in fat32_types
        and "pub fn boot_card_type() -> Option<SdCardType>" in waveshare_registers,
        "SD-card absence must remain private to the Waveshare transport cache",
    )

    m5_transport_root = root / "apps/signer-firmware/src/hw/m5stack/storage/transport"
    m5_transport = read("apps/signer-firmware/src/hw/m5stack/storage/transport/mod.rs")
    m5_spi_state = read("apps/signer-firmware/src/hw/m5stack/spi_bus/state.rs")
    m5_spi_config = read("apps/signer-firmware/src/hw/m5stack/spi_bus/config.rs")
    m5_spi_gpio35 = read("apps/signer-firmware/src/hw/m5stack/spi_bus/gpio35.rs")
    require(
        "mod bitbang;" not in m5_transport
        and not (m5_transport_root / "bitbang").exists()
        and not (m5_transport_root / "registers.rs").exists()
        and not (m5_transport_root / "gpio.rs").exists(),
        "M5Stack retired raw/bitbang SD transport must not return",
    )
    for stale in (
        "save_and_reclaim", "restore_spi_state", "USE_HW_SPI2",
        "set_hw_spi2_enabled", "SPI2_CLOCK_REG", "SPI2_USER_REG",
    ):
        require(
            stale not in "\n".join(
                path.read_text(encoding="utf-8") for path in m5_transport_root.rglob("*.rs")
            ),
            f"M5Stack SD transport retains retired SPI2 ownership state: {stale}",
        )
    require(
        "StaticCell<SharedBus>" in m5_spi_state
        and "AtomicPtr<SharedBus>" in m5_spi_state
        and "ensure_frequency" in m5_spi_config
        and "apply_config" in m5_spi_config
        and "GPIO_ENABLE1_W1TC" in m5_spi_gpio35,
        "CoreS3 shared SPI2 owner must remain explicit and fail-closed",
    )

    app_data = read("apps/signer-firmware/src/runtime/data.rs")
    require(
        '#[cfg(feature = "waveshare")]\n    pub camera: CameraState,' in app_data,
        "AppData camera tuning state must compile only for Waveshare",
    )

    camera_session = read("apps/signer-firmware/src/runtime/interactions/camera_loop/state.rs")
    event_loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
    require(
        '#[cfg(feature = "waveshare")]\n    sensor_is_ov2640: bool,' in camera_session
        and '#[cfg(feature = "waveshare")]\n    pub(crate) const fn is_ov2640' in camera_session,
        "camera sensor identity must not compile into M5Stack sessions",
    )
    require(
        '#[cfg(feature = "m5stack")]\n        let mut camera_session = $crate::runtime::interactions::camera_loop::CameraSessionState::new();'
        in event_loop,
        "M5Stack event loop must construct a sensor-neutral camera session",
    )

    lockdown = read("apps/signer-firmware/src/hw/shared/lockdown.rs")
    signing_facade = read("apps/signer-firmware/src/runtime/signing.rs")
    verify_types = read("apps/signer-firmware/src/services/verify/types.rs")
    require(
        "/// disables the JTAG bridge\n\n" not in lockdown,
        "hw/shared/lockdown.rs: orphaned JTAG documentation must not return",
    )
    require(
        '#[cfg(not(feature = "skip-tests"))]\n\npub use qr::cycle_signed_qr;'
        not in signing_facade,
        "runtime/signing.rs: cfg attributes must stay attached to their imports",
    )
    require(
        "/// Equivalent address on data bus (for reading)" not in verify_types,
        "services/verify/types.rs: orphaned mapped-address documentation must not return",
    )

    fat32_policy = read("apps/signer-firmware/src/hw/shared/storage/fat32/policy.rs")
    krc20 = read("apps/signer-firmware/src/services/krc20.rs")
    menu = read("apps/signer-firmware/src/runtime/input/menu.rs")
    navigation_core = read("crates/signer-firmware-core/src/input/navigation.rs")
    require(
        "left.eq_ignore_ascii_case(&right)" in fat32_policy,
        "FAT32 name matching must use the standard ASCII-insensitive comparison",
    )
    require(
        "eq_ignore_ascii_case" in krc20
        and "to_ascii_lowercase() !=" not in krc20,
        "KRC20 matching must use the standard ASCII-insensitive comparison",
    )
    require(
        "signer_firmware_core::input::navigation" in menu
        and "menu.items[..count].copy_from_slice(&labels[..count]);" in navigation_core,
        "fixed-capacity menu labels must remain host-tested and use slice copying",
    )

    hardware_tests = read("apps/signer-firmware/src/services/unit_tests/hardware.rs")
    boot_tests = read("apps/signer-firmware/src/runtime/unit_tests/boot.rs")
    require(
        "passed: [bool; HardwareTest::COUNT]" in hardware_tests
        and "pub all_passed: bool" not in hardware_tests,
        "hardware self-test results must use indexed outcomes instead of an excessive bool struct",
    )
    require(
        "test_results.all_passed()" in boot_tests
        and "test_results.passed(HardwareTest::Sram)" in boot_tests,
        "boot self-tests must consume the typed hardware result API",
    )

    camera_cycle = read("apps/signer-firmware/src/runtime/interactions/camera_loop/cycle.rs")
    require(
        "drop(platform);" not in camera_cycle
        and "let buffers = {" in camera_cycle,
        "camera cycle must end platform borrows by scope, not drop a non-Drop value",
    )
    require(
        (
            '#[cfg(not(feature = "hardware-tests"))]\npub use qr::cycle_signed_qr;' in signing_facade
            or '#[cfg(all(not(feature = "hardware-tests"), not(feature = "workflow-test-auto")))]\npub use qr::cycle_signed_qr;' in signing_facade
        ),
        "runtime/signing.rs: signed QR cycling must remain available in skip-tests releases",
    )
    event_loop_facade = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
    require(
        '#[cfg(not(feature = "hardware-tests"))]\npub(crate) mod runner;'
        in event_loop_facade,
        "runtime/event_loop: ownership runner must stay out of hardware-test-only builds",
    )

    event_runner = read("apps/signer-firmware/src/runtime/event_loop/runner.rs")
    require(
        "fn main() -> ! {\n    firmware_main()\n}" in main
        and "clippy::cognitive_complexity" not in main,
        "firmware entrypoint must isolate ESP-HAL expansion without a main.rs lint exception",
    )
    require(
        "#[allow(clippy::cognitive_complexity)]\npub(crate) fn run(" in event_runner
        and "super::run!(" in event_runner,
        "event-loop macro complexity exception must stay on the focused ownership runner",
    )
    require(
        "sd_card_type: Option<SdCardType>," in event_runner,
        "event-loop ownership runner must preserve optional SD-card availability",
    )

    commands = read("qa/linux/runner/commands.sh")
    for features in ("waveshare,verbose-boot", "m5stack,verbose-boot"):
        require(
            f"--features {features}" in commands,
            f"master runner: missing signer-firmware compile configuration {features}",
        )
