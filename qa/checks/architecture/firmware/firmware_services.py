"""Hard boundaries for firmware security and entropy services."""

from __future__ import annotations

from pathlib import Path


def _require_modules(root: Path, relative_root: str, names: set[str], maximum: int) -> list[str]:
    errors: list[str] = []
    directory = root / relative_root
    actual = {path.name for path in directory.glob("*.rs")} if directory.exists() else set()
    if actual != names:
        errors.append(
            f"{relative_root} module inventory changed: expected {sorted(names)}, got {sorted(actual)}"
        )
    for path in directory.glob("*.rs") if directory.exists() else ():
        lines = len(path.read_text(errors="ignore").splitlines())
        if lines > maximum:
            errors.append(f"firmware service exceeds {maximum}-line SRP limit: {path.relative_to(root)} ({lines})")
    return errors


def _check_entropy(root: Path) -> list[str]:
    errors = _require_modules(
        root,
        "apps/signer-firmware/src/services/entropy",
        {"mod.rs", "ambient.rs", "collection.rs", "health.rs", "imu.rs", "mixer.rs", "platform.rs", "seed.rs", "touch.rs", "trng.rs"},
        150,
    )
    errors += _require_modules(
        root,
        "apps/signer-firmware/src/services/entropy/camera",
        {"mod.rs", "dvp.rs", "waveshare.rs"},
        150,
    )
    controller = root / "apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs"
    source = controller.read_text(errors="ignore")
    if "crate::services::entropy::collect(" not in source:
        errors.append("seed-generation controller must delegate entropy collection to services::entropy")
    collection = (root / "apps/signer-firmware/src/services/entropy/collection.rs").read_text(errors="ignore")
    event_touch = (root / "apps/signer-firmware/src/runtime/event_loop/touch.rs").read_text(errors="ignore")
    event_loop = (root / "apps/signer-firmware/src/runtime/event_loop/mod.rs").read_text(errors="ignore")
    event_idle = (root / "apps/signer-firmware/src/runtime/event_loop/runner/idle.rs").read_text(errors="ignore")
    waveshare_boot = (root / "apps/signer-firmware/src/boot/waveshare/mod.rs").read_text(errors="ignore")
    m5stack_boot = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "apps/signer-firmware/src/boot/m5stack").glob("*.rs")
    )
    imu_service = (root / "apps/signer-firmware/src/services/entropy/imu.rs").read_text(errors="ignore")
    for required in (
        "trng::enable_hardware_rng()?",
        "validate_seed_entropy",
        "imu::collect_seed_sample",
        "imu::mix_seed_sample",
        "ambient::mix_staged",
        "imu::mix_staged",
    ):
        if required not in collection:
            errors.append(f"entropy collection lost restored fail-closed/source behavior: {required}")
    if "stage_ambient_touch" not in event_touch:
        errors.append("runtime touch loop must stage changed ambient touch observations")
    if "runner::restage_imu" not in event_loop or "stage_idle_imu" not in event_idle:
        errors.append("runtime must restage healthy board IMU observations through the runner-owned idle stage")
    if "initialize_imu" not in waveshare_boot:
        errors.append("Waveshare boot must initialize the production QMI entropy source")
    if "initialize_imu" not in m5stack_boot:
        errors.append("M5Stack boot must initialize the production BMI270 entropy source")
    for required in ("count == sample.len()", "buffer_is_healthy", "mixer::zeroize(sample)"):
        if required not in imu_service:
            errors.append(f"production IMU entropy path lost point-of-use health/cleanup: {required}")
    for forbidden in ("SYSTIMER", "efuse", "ADC", "SHA256", "read_volatile"):
        if forbidden in source:
            errors.append(f"seed-generation controller retains entropy hardware concern: {forbidden}")
    return errors


def _check_firmware_update(root: Path) -> list[str]:
    # Runtime SD/QR firmware-image verification was deliberately retired. The
    # production update model is host-assisted USB flashing followed by the
    # independent boot-time verification/anti-rollback boundary.
    errors = _require_modules(
        root,
        "apps/signer-firmware/src/services/fw_update",
        {"mod.rs", "metadata.rs"},
        150,
    )
    if (root / "apps/signer-firmware/src/services/fw_update.rs").exists():
        errors.append("monolithic services/fw_update.rs must not return")
    service_root = root / "apps/signer-firmware/src/services/fw_update"
    for retired in ("image_hash.rs", "layout.rs", "verification.rs"):
        if (service_root / retired).exists():
            errors.append(f"retired runtime firmware-update module must not return: {retired}")

    facade = (service_root / "mod.rs").read_text(errors="ignore")
    for forbidden in ("verify_image", "hash_firmware_file", "parse_update_qr"):
        if forbidden in facade:
            errors.append(f"USB-only firmware-update facade must not expose retired runtime verifier: {forbidden}")

    # QR firmware-update payloads are rejected rather than reviving the retired
    # SD/QR installer.
    dispatch = (root / "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch.rs").read_text(errors="ignore")
    required_notice = "Firmware update QR ignored; use Settings -> Advanced -> Firmware Update and USB"
    if required_notice not in dispatch:
        errors.append("firmware-update QR payloads must remain rejected with USB guidance")
    for forbidden in ("sdcard::with_sd_card!(", "fw_update::verify_image(", "hash_firmware_file("):
        if forbidden in dispatch:
            errors.append(f"camera QR dispatch must not revive firmware image I/O: {forbidden}")

    guidance = (root / "apps/signer-firmware/src/ui/screens/dialogs/firmware_update.rs").read_text(errors="ignore")
    for required in ("USB FIRMWARE UPDATE", "Connect USB-C to computer", "make flash BOARD=m5stack", "Firmware is verified after reboot"):
        if required not in guidance:
            errors.append(f"firmware-update Settings guidance lost required host-assisted instruction: {required}")

    redraw = (root / "apps/signer-firmware/src/ui/redraw/system.rs").read_text(errors="ignore")
    if "fw_update::verify_image(" in redraw or "hash_firmware_file(" in redraw:
        errors.append("firmware update image I/O must not run inside the presentation renderer")
    return errors


def _check_boot_verification(root: Path) -> list[str]:
    errors = _require_modules(
        root,
        "apps/signer-firmware/src/services/verify",
        {"mod.rs", "anti_rollback.rs", "boot_security.rs", "format.rs", "mapped_segment.rs", "policy.rs", "signature.rs", "types.rs"},
        180,
    )
    if (root / "apps/signer-firmware/src/services/verify.rs").exists():
        errors.append("monolithic services/verify.rs must not return")
    source = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "apps/signer-firmware/src/services/verify").glob("*.rs")
    )
    for required in ("verify_firmware", "verify_signature", "do_verify_mapped_code"):
        if required not in source:
            errors.append(f"firmware verification split lost required behavior: {required}")
    return errors



def _check_argon2_psram(root: Path) -> list[str]:
    errors = _require_modules(
        root,
        "apps/signer-firmware/src/services/memory",
        {"mod.rs", "password_kdf.rs", "psram.rs"},
        220,
    )
    memory_root = root / "apps/signer-firmware/src/services/memory"
    psram = (memory_root / "psram.rs").read_text(errors="ignore")
    firmware_kdf = (memory_root / "password_kdf.rs").read_text(errors="ignore")
    main = (root / "apps/signer-firmware/src/main.rs").read_text(errors="ignore")
    bench = (root / "apps/signer-firmware/src/diagnostics/argon2_bench.rs").read_text(errors="ignore")
    firmware_source = "\n".join(
        path.read_text(errors="ignore")
        for path in (root / "apps/signer-firmware/src").rglob("*.rs")
        if "services/memory/password_kdf.rs" not in path.as_posix()
    )

    for required in (
        "esp_hal::psram::psram_raw_parts(peripheral)",
        "MemoryCapability::External.into()",
        "HEAP.alloc_caps",
        "has_valid_provenance",
        "shared_signer::bytes::zeroize_bytes(self.as_mut_bytes())",
    ):
        if required not in psram:
            errors.append(f"PSRAM provenance allocator contract missing: {required}")
    for forbidden in ("0x3c", "0x3d", "psram_allocator!"):
        if forbidden in psram.lower() or forbidden in main.lower():
            errors.append(f"PSRAM provenance must not hard-code/map via convenience fallback: {forbidden}")
    if "initialize_or_halt(&peripherals.PSRAM)" not in main:
        errors.append("firmware boot must retain the runtime ESP-HAL PSRAM region before password KDF use")

    for required in (
        "Argon2Workspace::allocate(parameters)",
        "workspace.info()?",
        "derive_key_32_with_workspace",
        "checked_mul(WORKSPACE_BLOCK_BYTES)",
        "full_buffer_integrity_test",
        "read_volatile",
        "write_volatile",
    ):
        if required not in firmware_kdf:
            errors.append(f"firmware Argon2 PSRAM workspace contract missing: {required}")
    for forbidden in ("Vec::<PasswordKdfBlock>", "try_reserve_exact", "m_cost_kib -", "m_cost_kib / 2"):
        if forbidden in firmware_kdf:
            errors.append(f"firmware Argon2 workspace must never heap-fallback or downgrade: {forbidden}")

    for required in (
        "runtime_psram=0x", "workspace=0x", "workspace_bytes={}",
        "provenance={}", "integrity={}", "vector={}", "watchdog_ok={}",
        "probe_largest_allocatable",
    ):
        if required not in bench:
            errors.append(f"Argon2 benchmark provenance report missing: {required}")

    for path in (root / "apps/signer-firmware/src").rglob("*.rs"):
        if path == memory_root / "password_kdf.rs":
            continue
        for line in path.read_text(errors="ignore").splitlines():
            stripped = line.strip()
            if "password_kdf::derive_key_32" not in stripped:
                continue
            if "crate::services::memory::password_kdf::derive_key_32" in stripped:
                continue
            errors.append(
                f"current firmware password KDF bypasses PSRAM provenance adapter: {path.relative_to(root)}"
            )
            break
    return errors



def _check_panic_free_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    production_roots = (
        root / "apps/signer-firmware/src/services",
        root / "crates/offline-signer/src",
        root / "crates/shared-signer/src",
        root / "crates/signer-firmware-core/src",
    )
    forbidden = ("panic!(", ".unwrap(", ".expect(", "unreachable!(")
    for source_root in production_roots:
        for path in source_root.rglob("*.rs") if source_root.exists() else ():
            if "unit_tests" in path.parts or path.name.endswith("_tests.rs"):
                continue
            source = path.read_text(errors="ignore")
            for token in forbidden:
                if token in source:
                    errors.append(
                        f"panic-capable construct is forbidden in production service/domain code: "
                        f"{path.relative_to(root)}: {token}"
                    )
    frame = (root / "crates/signer-firmware-core/src/backup/stego_picture/frame.rs").read_text(errors="ignore")
    for required in ("checked_add", "checked_mul", "ok_or(PictureError::Malformed)"):
        if required not in frame:
            errors.append(f"external JPEG/stego parser lost checked malformed-input handling: {required}")
    fuzz_manifest = (root / "qa/fuzz/Cargo.toml").read_text(errors="ignore")
    fuzz_target = root / "qa/fuzz/stego_picture_parser.rs"
    if 'name = "stego_picture_parser"' not in fuzz_manifest or not fuzz_target.exists():
        errors.append("external JPEG/stego parser must remain host-fuzzable")
    psram = (root / "apps/signer-firmware/src/services/memory/psram.rs").read_text(errors="ignore")
    if "panic!(" in psram or "FATAL: PSRAM provenance initialization failed" not in psram:
        errors.append("fatal PSRAM initialization must fail closed without unwinding/panic")
    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_entropy(root), *_check_firmware_update(root), *_check_boot_verification(root),
        *_check_argon2_psram(root), *_check_panic_free_boundaries(root),
    ]
