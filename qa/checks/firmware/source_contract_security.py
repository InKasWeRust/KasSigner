"""Focused firmware source-contract checks."""
from source_contract_support import read, require

def check_hardware_test_contract(errors: list[str]) -> None:
    manifest = read("apps/signer-firmware/Cargo.toml")
    require(
        errors,
        'hardware-tests = ["verbose-boot", "test-psram", "developer-ui", "argon2-bench"]' in manifest,
        "signer-firmware: hardware-tests feature must enable boot tests and the full Argon2/PSRAM benchmark",
    )

    main = read("apps/signer-firmware/src/main.rs")
    boot_tests = read("apps/signer-firmware/src/runtime/unit_tests/boot.rs")
    require(
        errors,
        'KASSIGNER_HARDWARE_TESTS: {}' in boot_tests,
        "signer-firmware: missing machine-readable hardware result marker",
    )
    require(
        errors,
        '#[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]\n    boot::security::post_boot_lockdown();' in main,
        "signer-firmware: both boards must apply post-boot lockdown outside hardware tests",
    )

    # Host launcher/monitor behavior is covered by executable tooling tests
    # (`test_master_launcher` and `test_hardware_device_runner`). Keep this
    # source contract focused on firmware-side feature and lockdown invariants.

def check_advanced_security_feature_gates(errors: list[str]) -> None:
    state = read("apps/signer-firmware/src/runtime/input/state.rs")
    for variant in (
        "AdvancedRtcEntry",
        "AdvancedTimeLockWarning",
        "AdvancedTimeLockEntry",
        "AdvancedTimeLockConfirm",
        "AdvancedWeeklyWarning",
        "AdvancedWeeklyEntry",
        "AdvancedWeeklyConfirm",
    ):
        require(
            errors,
            f'#[cfg(feature = "m5stack")]\n    {variant},' in state,
            f"runtime/input/state.rs: {variant} must remain M5Stack-only",
        )

    controller = read("apps/signer-firmware/src/runtime/interactions/settings/advanced/mod.rs")
    for module in ("clock", "time"):
        require(
            errors,
            f'#[cfg(feature = "m5stack")]\nmod {module};' in controller,
            f"advanced settings {module} controller must remain M5Stack-only",
        )

    secure_time = read("apps/signer-firmware/src/services/secure_time.rs")
    require(
        errors,
        '#[cfg(feature = "waveshare")]\npub fn set_utc' not in secure_time,
        "Waveshare must not compile an unreachable hardware-RTC setter",
    )

    persistence = read("apps/signer-firmware/src/services/persistent_wallet/advanced.rs")
    require(
        errors,
        "pub const fn credential_kind(&self)" not in persistence,
        "persistent wallet must not retain the unused credential_kind accessor",
    )
    for method in ("enable_not_before", "enable_weekly_windows"):
        require(
            errors,
            f'#[cfg(feature = "m5stack")]\n    pub fn {method}' in persistence,
            f"persistent-wallet advanced API {method} must remain M5Stack-only",
        )

    screen = read("apps/signer-firmware/src/ui/screens/device/advanced_security.rs")
    require(
        errors,
        '#[cfg(feature = "m5stack")]\nuse super::super::draw_lato_body;' in screen,
        "advanced-security draw_lato_body import must remain M5Stack-only",
    )
    for method in (
        "draw_advanced_final_warning",
        "draw_advanced_text_entry",
        "draw_time_lock_confirmation",
        "draw_weekly_confirmation",
        "draw_weekly_policy_readonly",
    ):
        require(
            errors,
            f'#[cfg(feature = "m5stack")]\n    pub fn {method}' in screen,
            f"advanced-security renderer {method} must remain M5Stack-only",
        )
