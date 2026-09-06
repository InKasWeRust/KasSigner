from __future__ import annotations

from pathlib import Path
import re

def _check_hardware_roots(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"
    hardware = firmware / "hw"
    boot = firmware / "boot"

    expected_hw_entries = {"mod.rs", "shared", "waveshare", "m5stack"}
    actual_hw_entries = {path.name for path in hardware.iterdir()}
    if actual_hw_entries != expected_hw_entries:
        errors.append(
            "firmware hardware root must contain only the selector and explicit board roots: "
            f"expected {sorted(expected_hw_entries)}, got {sorted(actual_hw_entries)}"
        )

    for required in (
        hardware / "shared/mod.rs",
        hardware / "waveshare/mod.rs",
        hardware / "m5stack/mod.rs",
        hardware / "shared/storage/fat32/mod.rs",
        hardware / "waveshare/storage/mod.rs",
        hardware / "m5stack/storage/mod.rs",
        boot / "shared/mod.rs",
        boot / "waveshare/mod.rs",
        boot / "m5stack/mod.rs",
    ):
        if not required.is_file():
            errors.append(f"required board-boundary module is missing: {required.relative_to(root)}")

    selector = (hardware / "mod.rs").read_text(errors="ignore")
    for contract in (
        "pub(crate) mod shared;",
        "mod waveshare;",
        "mod m5stack;",
        "use waveshare as active_board;",
        "use m5stack as active_board;",
        "pub(crate) use active_board::{battery, camera, display, pmu, sdcard, sound, touch};",
    ):
        if contract not in selector:
            errors.append(f"hardware selector lost stable active-board facade: {contract}")
    if "#[path" in selector:
        errors.append("hardware selector must use the standard Rust module hierarchy")

    shared_source = "\n".join(
        path.read_text(errors="ignore") for path in (hardware / "shared").rglob("*.rs")
    )
    board_gate = re.compile(
        r'#\[cfg\([^\n]*(?:feature\s*=\s*"waveshare"|feature\s*=\s*"m5stack")'
    )
    if board_gate.search(shared_source):
        errors.append("shared hardware code contains a board feature gate")
    for forbidden in ("crate::hw::waveshare", "crate::hw::m5stack"):
        if forbidden in shared_source:
            errors.append(f"shared hardware depends on a concrete board: {forbidden}")

    waveshare_source = "\n".join(
        path.read_text(errors="ignore") for path in (hardware / "waveshare").rglob("*.rs")
    )
    m5stack_source = "\n".join(
        path.read_text(errors="ignore") for path in (hardware / "m5stack").rglob("*.rs")
    )
    if 'feature = "m5stack"' in waveshare_source or "crate::hw::m5stack" in waveshare_source:
        errors.append("Waveshare hardware contains an M5Stack dependency or feature gate")
    if 'feature = "waveshare"' in m5stack_source or "crate::hw::waveshare" in m5stack_source:
        errors.append("M5Stack hardware contains a Waveshare dependency or feature gate")

    boot_shared = "\n".join(
        path.read_text(errors="ignore") for path in (boot / "shared").rglob("*.rs")
    )
    if board_gate.search(boot_shared):
        errors.append("shared boot policy contains a board feature gate")

    for stale_name in (
        "camera", "display", "power", "sound", "storage", "touch", "board",
        "registers", "decode_core", "display_support", "diagnostics",
    ):
        stale = hardware / stale_name
        if stale.exists():
            errors.append(f"interleaved legacy hardware root must not exist: {stale.relative_to(root)}")
    return errors

def check(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = _check_hardware_roots(root)
    # Firmware entry-point orchestration keeps boot order and hardware singleton
    # construction in main.rs. The completed runtime split owns the outer loop in
    # focused macro modules so ESP-HAL ownership stays local without a main monolith.
    inactive_board_map = ROOT / "apps/signer-firmware/src/hw/board/board.rs"
    hw_mod = ROOT / "apps/signer-firmware/src/hw/mod.rs"
    if inactive_board_map.exists():
        errors.append("inactive duplicate board pin map must not return")
    if hw_mod.exists() and re.search(r"(?m)^pub mod board;", hw_mod.read_text(errors="ignore")):
        errors.append("hardware module must not export the inactive board pin map")

    firmware_main = ROOT / "apps/signer-firmware/src/main.rs"
    boot_root = ROOT / "apps/signer-firmware/src/boot"
    runtime_root = ROOT / "apps/signer-firmware/src/runtime"
    required_main_modules = (
        boot_root / "mod.rs",
        boot_root / "shared/security.rs",
        boot_root / "waveshare/mod.rs",
        boot_root / "m5stack/mod.rs",
        runtime_root / "event_loop/mod.rs",
        runtime_root / "event_loop/touch.rs",
        runtime_root / "event_loop/dispatch.rs",
        runtime_root / "event_loop/frame.rs",
        runtime_root / "event_loop/camera.rs",
        runtime_root / "event_loop/runner.rs",
        runtime_root / "touch_dispatch.rs",
        runtime_root / "power_state.rs",
        runtime_root / "camera_tuning.rs",
    )
    for required in required_main_modules:
        if not required.exists():
            errors.append(f"required staged main module is missing: {required.relative_to(ROOT)}")

    if firmware_main.exists():
        firmware_main_source = firmware_main.read_text(errors="ignore")
        firmware_main_lines = len(firmware_main_source.splitlines())
        if firmware_main_lines > 260:
            errors.append(
                f"firmware main.rs exceeds completed 260-line limit: {firmware_main_lines} lines"
            )
        for required_fragment in (
            "#[main]\nfn main() -> !",
            "runtime::secret_state::initialize()",
            "runtime::event_loop::runner::run(",
            "pub use runtime::power_state::halt_forever;",
            "boot::waveshare::initialize!(peripherals, delay)",
            "boot::m5stack::initialize!(peripherals, delay)",
        ):
            if required_fragment not in firmware_main_source:
                errors.append(f"firmware main lost staged boundary: {required_fragment}")
        if "loop {" in firmware_main_source:
            errors.append("firmware main.rs must delegate the outer loop to runtime::event_loop")
        if "#[allow(clippy::too_many_lines" in firmware_main_source or "clippy::cognitive_complexity" in firmware_main_source:
            errors.append("firmware main.rs no longer requires complexity lint exceptions")

        for moved_function in (
            "init_pmu_ws",
            "init_sd_card_ws",
            "init_pmu_m5",
            "init_sd_card_m5",
            "touch_zones",
            "handle_wake",
            "handle_idle",
            "continue_without_display",
            "cam_tune_apply_all",
            "cam_tune_apply_ov2640",
            "cam_tune_apply_gc0308",
        ):
            if re.search(rf"(?m)^fn\s+{moved_function}\b", firmware_main_source):
                errors.append(f"firmware main retains extracted helper: {moved_function}")
        boot_markers = (
            "ESP32-S3 initialization",
            "Hardware self-tests",
            "Initialize peripherals",
            "Verify firmware integrity",
            "Boot into main application",
            "Main loop",
        )
        marker_positions = [firmware_main_source.find(marker) for marker in boot_markers]
        if any(position < 0 for position in marker_positions) or marker_positions != sorted(marker_positions):
            errors.append("firmware main top-level boot and loop order changed")

    main_module_limits = {
        boot_root / "mod.rs": 80,
        boot_root / "shared/security.rs": 80,
        boot_root / "waveshare/mod.rs": 400,
        boot_root / "m5stack/mod.rs": 300,
        runtime_root / "event_loop/mod.rs": 100,
        runtime_root / "event_loop/touch.rs": 140,
        runtime_root / "event_loop/dispatch.rs": 260,
        runtime_root / "event_loop/frame.rs": 140,
        runtime_root / "event_loop/camera.rs": 140,
        runtime_root / "event_loop/runner.rs": 100,
        runtime_root / "touch_dispatch.rs": 100,
        runtime_root / "power_state.rs": 180,
        runtime_root / "camera_tuning.rs": 220,
    }
    for path, maximum in main_module_limits.items():
        if path.exists():
            line_count = len(path.read_text(errors="ignore").splitlines())
            if line_count > maximum:
                errors.append(
                    f"staged main module exceeds SRP limit: "
                    f"{path.relative_to(ROOT)} ({line_count} > {maximum})"
                )

    if (boot_root / "waveshare/mod.rs").exists() and (boot_root / "m5stack/mod.rs").exists():
        boot_source = (boot_root / "waveshare/mod.rs").read_text(errors="ignore") + "\n" + (
            boot_root / "m5stack/mod.rs"
        ).read_text(errors="ignore")
        if len(re.findall(r"macro_rules!\s+initialize", boot_source)) != 2:
            errors.append("staged boot must have one ownership-preserving initializer per board")

    power_state = runtime_root / "power_state.rs"
    if power_state.exists():
        power_source = power_state.read_text(errors="ignore")
        if not re.search(r"(?m)^pub\s+fn\s+halt_forever\s*\(", power_source):
            errors.append("runtime power_state must own the public halt implementation")

    return errors
