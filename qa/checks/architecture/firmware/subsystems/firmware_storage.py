from __future__ import annotations
from pathlib import Path
import re
def _roots(root: Path) -> tuple[Path, Path, Path]:
    firmware = root / "apps/signer-firmware/src/hw"
    return (
        firmware / "m5stack/storage",
        firmware / "waveshare/storage",
        firmware / "shared/storage/fat32",
    )


def _sdcard_limits(root: Path, m5_root: Path, ws_root: Path, fat32_root: Path) -> dict[Path, int]:
    return {
        m5_root / "transport/mod.rs": 40,
        m5_root / "transport/protocol/mod.rs": 40,
        m5_root / "transport/protocol/initialization.rs": 140,
        m5_root / "transport/protocol/wire.rs": 140,
        m5_root / "transport/block.rs": 120,
        m5_root / "transport/multi_block.rs": 100,
        m5_root / "transport/card.rs": 100,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/mod.rs": 40,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/config.rs": 80,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/state.rs": 180,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/lcd.rs": 150,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/gpio35.rs": 60,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/power_cycle.rs": 60,
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/sd_power_lines.rs": 80,
        ws_root / "transport/registers.rs": 230,
        ws_root / "transport/gpio.rs": 170,
        ws_root / "transport/sdhost/mod.rs": 80,
        ws_root / "transport/sdhost/routing.rs": 140,
        ws_root / "transport/sdhost/clock.rs": 180,
        ws_root / "transport/sdhost/command.rs": 140,
        ws_root / "transport/sdhost/initialization.rs": 160,
        ws_root / "transport/sdhost/block.rs": 220,
        ws_root / "transport/sdhost/multi_block.rs": 180,
        ws_root / "transport/sdhost/multi_block/fifo.rs": 120,
        ws_root / "transport/sdhost/boot.rs": 100,
        ws_root / "transport/card.rs": 150,
        fat32_root / "types.rs": 100,
        fat32_root / "policy.rs": 360,
        fat32_root / "allocation.rs": 120,
        fat32_root / "directory.rs": 230,
        fat32_root / "files.rs": 190,
        fat32_root / "lfn.rs": 180,
        root / "crates/signer-firmware-core/src/storage/fat32_lfn.rs": 320,
        fat32_root / "lfn/scanner.rs": 120,
        fat32_root / "format.rs": 150,
    }


def _check_sdcard_layout(root: Path) -> list[str]:
    errors: list[str] = []
    m5_root, ws_root, fat32_root = _roots(root)
    required = (
        m5_root / "mod.rs",
        m5_root / "transport/mod.rs",
        m5_root / "transport/protocol/mod.rs",
        m5_root / "transport/protocol/initialization.rs",
        m5_root / "transport/protocol/wire.rs",
        m5_root / "transport/block.rs",
        m5_root / "transport/multi_block.rs",
        m5_root / "transport/card.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/mod.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/config.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/state.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/lcd.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/gpio35.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/power_cycle.rs",
        root / "apps/signer-firmware/src/hw/m5stack/spi_bus/sd_power_lines.rs",
        ws_root / "mod.rs",
        ws_root / "transport/registers.rs",
        ws_root / "transport/gpio.rs",
        ws_root / "transport/sdhost/mod.rs",
        ws_root / "transport/sdhost/routing.rs",
        ws_root / "transport/sdhost/clock.rs",
        ws_root / "transport/sdhost/command.rs",
        ws_root / "transport/sdhost/initialization.rs",
        ws_root / "transport/sdhost/block.rs",
        ws_root / "transport/sdhost/multi_block.rs",
        ws_root / "transport/sdhost/multi_block/fifo.rs",
        ws_root / "transport/sdhost/boot.rs",
        ws_root / "transport/card.rs",
        fat32_root / "mod.rs",
        fat32_root / "types.rs",
        fat32_root / "policy.rs",
        fat32_root / "allocation.rs",
        fat32_root / "directory.rs",
        fat32_root / "files.rs",
        fat32_root / "lfn.rs",
        fat32_root / "lfn/scanner.rs",
        fat32_root / "format.rs",
    )
    for path in required:
        if not path.exists():
            errors.append(f"required firmware SD-card module is missing: {path.relative_to(root)}")

    for facade in (m5_root / "mod.rs", ws_root / "mod.rs"):
        if not facade.exists():
            continue
        source = facade.read_text(errors="ignore")
        if len(source.splitlines()) > 100:
            errors.append(f"SD-card facade exceeds 100 lines: {facade.relative_to(root)}")
        if "mod transport;" not in source:
            errors.append(f"SD-card facade lost board transport ownership: {facade.relative_to(root)}")
        if "pub use crate::hw::shared::storage::fat32::{" not in source:
            errors.append(f"SD-card facade no longer consumes shared FAT32: {facade.relative_to(root)}")
        if "include!(" in source:
            errors.append(f"SD-card facade must use real Rust modules: {facade.relative_to(root)}")

    limits = _sdcard_limits(root, m5_root, ws_root, fat32_root)
    for path, maximum in limits.items():
        if path.exists() and len(path.read_text(errors="ignore").splitlines()) > maximum:
            errors.append(
                f"firmware SD-card module exceeds SRP limit: {path.relative_to(root)}"
            )

    fat32_source = "\n".join(
        path.read_text(errors="ignore") for path in fat32_root.glob("*.rs")
    ) if fat32_root.exists() else ""
    fat32_all_source = "\n".join(
        path.read_text(errors="ignore") for path in fat32_root.rglob("*.rs")
    ) if fat32_root.exists() else ""
    for forbidden in (
        "SDHOST_", "SPI2_", "GPIO_OUT", "GPIO_ENABLE", "IO_MUX", "reg_write(",
        "bb_transfer", "sdhost_send_cmd", "restore_display_state", "restore_spi_state",
    ):
        if forbidden in fat32_all_source:
            errors.append(f"shared FAT32 contains platform transport concern: {forbidden}")
    if re.search(r"\b(?:struct|impl)\s+BmpInfo\b", fat32_all_source):
        errors.append("unused FAT32 BmpInfo type must not return")

    lfn_helpers = {
        root / "crates/signer-firmware-core/src/storage/fat32_lfn.rs": (
            "struct LfnAccumulator", "fn record", "fn display_name", "fn map_latin1",
            "enum DirectoryEntryKind", "fn classify_directory_entry",
        ),
        fat32_root / "lfn/scanner.rs": (
            "enum ScanControl", "fn scan_cluster", "fn process_entry",
        ),
    }
    for module_path, symbols in lfn_helpers.items():
        if not module_path.is_file():
            errors.append(
                f"FAT32 LFN decomposition source is missing: {module_path.relative_to(root)}"
            )
            continue
        source = module_path.read_text(errors="ignore")
        for symbol in symbols:
            if symbol not in source:
                errors.append(
                    f"FAT32 LFN decomposition lost {symbol} in {module_path.relative_to(root)}"
                )

    expected_functions = {
        "from_boot_sector", "cluster_to_sector", "cluster_bytes", "from_bytes",
        "first_cluster", "is_dir", "matches", "to_83_name",
        "checked_fat_entry_location", "read_fat_entry", "read_file_progress",
        "detect_fat32_partition", "write_fat_entry", "allocate_cluster",
        "allocate_chain", "mount_fat32", "find_file_in_root", "read_file",
        "create_file", "create_file_progress", "write_dir_entry_to_root",
        "delete_file", "overwrite_file", "list_root_dir", "list_root_dir_lfn",
        "format_83_display", "format_fat32", "do_format_fat32",
    }
    actual_functions = set(re.findall(
        r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<|\()",
        fat32_source,
    ))
    if actual_functions != expected_functions:
        errors.append(
            "shared FAT32 responsibility inventory changed: expected "
            f"{sorted(expected_functions)}, got {sorted(actual_functions)}"
        )
    return errors


def _check_shared_fat32_policy(root: Path) -> list[str]:
    errors: list[str] = []
    m5_root, ws_root, fat32_root = _roots(root)
    shared_policy = fat32_root / "policy.rs"
    for stale in (m5_root / "fat32_policy.rs", ws_root / "fat32_policy.rs"):
        if stale.exists():
            errors.append(f"board-specific FAT32 policy copy must not exist: {stale.relative_to(root)}")

    fat32_mod = fat32_root / "mod.rs"
    if fat32_mod.exists():
        source = fat32_mod.read_text(errors="ignore")
        if "mod policy;" not in source or "include!(" in source:
            errors.append("shared FAT32 facade must own policy.rs through a real module")

    policy_source = shared_policy.read_text(errors="ignore") if shared_policy.exists() else ""
    boot_policy = fat32_root / "policy" / "boot.rs"
    metadata_policy = root / "crates/signer-firmware-core/src/storage/fat32_metadata/mod.rs"
    guard_source = policy_source + (boot_policy.read_text(errors="ignore") if boot_policy.exists() else "")
    guard_source += metadata_policy.read_text(errors="ignore") if metadata_policy.exists() else ""
    required_guards = {
        "invalid-cluster guard": "if cluster < 2",
        "checked FAT geometry": "checked_mul(fat_size_32)",
        "saturating cluster arithmetic": "saturating_mul(self.sectors_per_cluster",
        "checked FAT entry location": "checked_fat_entry_location",
        "FAT entry bounds check": 'return Err("FAT offset out of range")',
        "bounded chain traversal": "MAX_FAT_CHAIN_STEPS",
        "premature-chain rejection": 'return Err("FAT chain ended before file size")',
        "MBR signature validation": 'return Err("Invalid MBR signature")',
    }
    for description, marker in required_guards.items():
        if marker not in guard_source:
            errors.append(f"shared FAT32 policy lost {description}")

    storage_source = "\n".join(
        path.read_text(errors="ignore")
        for base in (m5_root, ws_root, fat32_root)
        for path in base.rglob("*.rs")
    )
    for name in (
        "checked_fat_entry_location", "read_fat_entry", "read_file_progress",
        "to_83_name", "detect_fat32_partition",
    ):
        count = len(re.findall(
            rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+{name}\s*\(", storage_source
        ))
        if count != 1:
            errors.append(f"FAT32 policy function {name} must have one shared implementation, found {count}")
    return errors


def _check_real_module_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    m5_root, ws_root, fat32_root = _roots(root)
    targets = (
        m5_root / "mod.rs",
        m5_root / "transport/mod.rs",
        m5_root / "transport/bitbang/mod.rs",
        ws_root / "mod.rs",
        ws_root / "transport/mod.rs",
        ws_root / "transport/sdhost/mod.rs",
        fat32_root / "mod.rs",
    )
    for path in targets:
        if not path.exists():
            continue
        source = path.read_text(errors="ignore")
        if "include!(" in source:
            errors.append(f"storage boundary uses include! instead of modules: {path.relative_to(root)}")
        if not re.search(r"(?m)^\s*(?:#\[path = [^]]+\]\s*)?mod\s+[A-Za-z_][A-Za-z0-9_]*;", source):
            errors.append(f"storage facade has no real child modules: {path.relative_to(root)}")
    return errors


def _check_transport_owner_imports(root: Path) -> list[str]:
    errors: list[str] = []
    m5_root, ws_root, _ = _roots(root)
    for relative in (
        "transport/sdhost/routing.rs", "transport/sdhost/clock.rs",
        "transport/sdhost/command.rs", "transport/sdhost/initialization.rs",
        "transport/sdhost/block.rs", "transport/sdhost/multi_block.rs",
        "transport/sdhost/multi_block/fifo.rs", "transport/sdhost/boot.rs",
    ):
        path = ws_root / relative
        source = path.read_text(errors="ignore") if path.exists() else ""
        if not re.search(r"use\s+super(?:::\s*super)*::registers::", source):
            errors.append(f"Waveshare SDHOST leaf bypasses its register owner: {path.relative_to(root)}")
        if re.search(r"use\s+super(?:::\s*super)*::\*", source):
            errors.append(f"Waveshare SDHOST leaf uses wildcard inheritance: {path.relative_to(root)}")

    m5_transport = m5_root / "transport"
    wire = m5_transport / "protocol/wire.rs"
    for path in m5_transport.rglob("*.rs"):
        source = path.read_text(errors="ignore")
        if re.search(r"use\s+super(?:::\s*super)*::\*", source):
            errors.append(f"M5 SD transport leaf uses wildcard inheritance: {path.relative_to(root)}")
        for forbidden in (
            "0x6002_", "SPI2_CLOCK_REG", "SPI2_USER_REG", "save_and_reclaim",
            "restore_spi_state", "GPIO_FUNC_OUT_SEL", "GPIO_ENABLE1_",
        ):
            if forbidden in source:
                errors.append(
                    f"M5 SD transport bypasses the shared SPI2 owner with {forbidden}: "
                    f"{path.relative_to(root)}"
                )
        if path != wire and "m5stack::spi_bus" in source:
            errors.append(
                f"M5 SD transport bypasses its wire owner: {path.relative_to(root)}"
            )
    wire_source = wire.read_text(errors="ignore") if wire.exists() else ""
    if "crate::hw::m5stack::spi_bus::with_sd_selected" not in wire_source:
        errors.append("M5 SD wire layer no longer uses the shared SPI2 owner")
    return errors



def _check_cores3_spi_ownership(root: Path) -> list[str]:
    errors: list[str] = []
    firmware = root / "apps/signer-firmware/src"
    m5 = firmware / "hw/m5stack"
    spi_root = m5 / "spi_bus"
    boot = (firmware / "boot/m5stack/mod.rs").read_text(errors="ignore")
    display = (m5 / "display.rs").read_text(errors="ignore")
    state = (spi_root / "state.rs").read_text(errors="ignore")
    config = (spi_root / "config.rs").read_text(errors="ignore")
    gpio35 = (spi_root / "gpio35.rs").read_text(errors="ignore")

    hw_selector = (firmware / "hw/mod.rs").read_text(errors="ignore")
    protocol_root = m5 / "storage/transport/protocol"
    protocol_mod = (protocol_root / "mod.rs").read_text(errors="ignore")
    protocol_init = (protocol_root / "initialization.rs").read_text(errors="ignore")
    protocol_wire = (protocol_root / "wire.rs").read_text(errors="ignore")

    if "pub(crate) use active_board::spi_bus::initialize as initialize_cores3_spi;" not in hw_selector:
        errors.append("CoreS3 SPI2 initializer must be exposed through the hw board-selection facade")
    if "$crate::hw::m5stack::" in boot:
        errors.append("CoreS3 boot macro must not expand through the private hw::m5stack module")

    transport_visibility = "pub(in crate::hw::m5stack::storage::transport)"
    if "pub(super) use initialization::initialize_card;" not in protocol_mod:
        errors.append("CoreS3 SD protocol facade lost initialize_card re-export")
    if f"{transport_visibility} fn initialize_card" not in protocol_init:
        errors.append("CoreS3 SD initialize_card visibility must be scoped to the transport ancestor")
    for helper in (
        "command_data", "finish_transaction", "read_exact",
        "require_success", "transfer_byte", "write_all",
    ):
        if f"{transport_visibility} fn {helper}" not in protocol_wire:
            errors.append(
                f"CoreS3 SD protocol helper visibility must reach transport siblings: {helper}"
            )

    if boot.count("Spi::new(") != 1 or "$peripherals.SPI2" not in boot:
        errors.append("CoreS3 boot must construct exactly one HAL-owned SPI2 bus")
    for marker in (
        ".with_sck($peripherals.GPIO36)",
        ".with_mosi($peripherals.GPIO37)",
        ".with_miso($peripherals.GPIO35)",
        "initialize_cores3_spi(spi, sd_cs)",
    ):
        if marker not in boot:
            errors.append(f"CoreS3 shared SPI2 boot contract missing: {marker}")
    owner_at = boot.find("initialize_cores3_spi(spi, sd_cs)")
    sd_at = boot.find("m5stack::sd::initialize")
    display_at = boot.find("m5stack::display::initialize")
    if min(owner_at, sd_at, display_at) < 0 or not (owner_at < sd_at < display_at):
        errors.append("CoreS3 SPI2 owner must initialize before SD and display clients")

    if "lcd_device(cs_pin)?" not in display:
        errors.append("CoreS3 display must be a client of the shared SPI2 owner")
    for marker in (
        "StaticCell<SharedBus>", "AtomicPtr<SharedBus>", "try_borrow_mut()",
        "CoreS3 SPI2 bus re-entry", "frequency_hz: Cell<u32>",
    ):
        if marker not in state:
            errors.append(f"CoreS3 SPI2 serialization contract missing: {marker}")
    for marker in ("ensure_frequency", "apply_config", "current_hz.get() == frequency_hz"):
        if marker not in config:
            errors.append(f"CoreS3 SPI2 configuration contract missing: {marker}")
    if "critical_section::with" in state:
        errors.append("CoreS3 SPI2 transfers must not mask interrupts for whole SD/LCD transactions")
    for marker in ("select_lcd_dc", "select_sd_miso", "GPIO_ENABLE1_W1TC"):
        if marker not in gpio35:
            errors.append(f"CoreS3 GPIO35 ownership contract missing: {marker}")

    retired = (
        m5 / "storage/transport/registers.rs",
        m5 / "storage/transport/gpio.rs",
        m5 / "storage/transport/bitbang",
    )
    for path in retired:
        if path.exists():
            errors.append(f"retired CoreS3 SPI2-reclaim path returned: {path.relative_to(root)}")

    for path in m5.rglob("*.rs"):
        source = path.read_text(errors="ignore")
        if path.is_relative_to(spi_root):
            continue
        for forbidden in (
            "SPI2_CLOCK_REG", "SPI2_USER_REG", "save_and_reclaim",
            "restore_spi_state", "0x6002_400C", "0x6002_4010",
        ):
            if forbidden in source:
                errors.append(
                    f"CoreS3 module bypasses shared SPI2 ownership with {forbidden}: "
                    f"{path.relative_to(root)}"
                )

    for path in firmware.rglob("*.rs"):
        source = path.read_text(errors="ignore")
        if "spi_bus" in source and ("#[handler]" in source or "#[esp_hal::handler]" in source):
            errors.append(f"interrupt handler must not access CoreS3 shared SPI2: {path.relative_to(root)}")
    return errors


def check(root: Path) -> list[str]:
    return [
        *_check_sdcard_layout(root),
        *_check_shared_fat32_policy(root),
        *_check_real_module_boundaries(root),
        *_check_transport_owner_imports(root),
        *_check_cores3_spi_ownership(root),
    ]
