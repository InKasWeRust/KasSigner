"""Feature-boundary checks for firmware boot-time software self-tests."""

from __future__ import annotations

from pathlib import Path


def check_boot_self_test_feature_contract(root: Path, errors: list[str]) -> None:
    """Reject test-only firmware code that leaks into ordinary board builds."""

    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    input_facade = read("apps/signer-firmware/src/runtime/input.rs")
    require(
        'all(feature = "verbose-boot", not(feature = "skip-tests"))'
        in input_facade,
        "runtime/input.rs: embedded input tests must be limited to verbose boot builds",
    )
    require(
        '#[cfg(not(feature = "skip-tests"))]\n#[path = "unit_tests/input_tests.rs"]'
        not in input_facade,
        "runtime/input.rs: input tests leak into ordinary firmware builds",
    )
    test_cfg = '#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]\n'
    require(
        test_cfg + "pub use button::Button;" in input_facade,
        "runtime/input.rs: Button must remain test/verbose-only",
    )
    require(
        test_cfg + "pub use wallet_app::Action;" in input_facade,
        "runtime/input.rs: Action must remain test/verbose-only",
    )
    require(
        "pub use button::{Button, ButtonEvent};" not in input_facade
        and "pub use wallet_app::{Action, WalletApp};" not in input_facade,
        "runtime/input.rs: test-only exports leak into ordinary builds",
    )
    require(
        "pub use button::ButtonEvent;" in input_facade
        and "pub use wallet_app::WalletApp;" in input_facade,
        "runtime/input.rs: production input facade exports regressed",
    )

    button = read("apps/signer-firmware/src/runtime/input/button.rs")
    button_core = read("crates/signer-firmware-core/src/input/button.rs")
    require(
        '#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]\n'
        'pub use signer_firmware_core::input::button::Button;' in button
        and "pub const fn new_pir()" in button_core,
        "button state machine must remain host-owned with a feature-gated firmware façade",
    )

    unit_tests = read("apps/signer-firmware/src/runtime/unit_tests/mod.rs")
    require(
        '#[cfg(all(feature = "verbose-boot", not(feature = "skip-tests")))]\n'
        "mod software;" in unit_tests,
        "runtime/unit_tests/mod.rs: verbose software tests need a feature boundary",
    )
    require(
        '#[cfg(all(feature = "verbose-boot", not(feature = "skip-tests")))]\n'
        "pub mod wallet_session;" in unit_tests,
        "runtime/unit_tests/mod.rs: wallet session tests leak into ordinary builds",
    )

    qr_encoder = read("apps/signer-firmware/src/qr/encoder/mod.rs")
    require(
        '#[cfg(any(test, all(feature = "verbose-boot", not(feature = "skip-tests"))))]\n'
        '#[path = "../unit_tests/encoder_tests.rs"]' in qr_encoder,
        "qr/encoder/mod.rs: encoder self-tests leak into ordinary builds",
    )
    require(
        "pub use matrix::version::select_version;" not in qr_encoder,
        "qr/encoder/mod.rs: internal version selector leaked through the public facade",
    )
    qr_tests = read("apps/signer-firmware/src/qr/unit_tests/encoder_tests.rs")
    require(
        "matrix::version::select_version" in qr_tests,
        "qr encoder self-tests must import the version selector from its owning module",
    )

    boot = read("apps/signer-firmware/src/runtime/unit_tests/boot.rs")
    require(
        "wallet::mnemonic" not in boot and "wallet::seed_manager" not in boot,
        "runtime/unit_tests/boot.rs: verbose-only wallet imports leaked into normal builds",
    )
    require(
        "let mut all_passed = test_results.all_passed;" not in boot,
        "runtime/unit_tests/boot.rs: normal builds retain conditional-only mutability",
    )
    require(
        "let all_passed = super::software::run(all_passed);" in boot,
        "runtime/unit_tests/boot.rs: verbose software tests must delegate",
    )
    require(
        '#[cfg(not(feature = "skip-tests"))]' in boot
        and 'pub fn run_boot_tests()' in boot,
        "runtime/unit_tests/boot.rs: silent builds must retain the called boot-test entry point",
    )
    require(
        '#[cfg(all(not(feature = "silent"), not(feature = "skip-tests")))]' not in boot,
        "runtime/unit_tests/boot.rs: run_boot_tests must not be gated out of silent builds",
    )
    require(
        "tx.network = offline_signer::address::KaspaNetwork::Mainnet;" in boot,
        "runtime/unit_tests/boot.rs: M5Stack signing HIL fixture must bind the KSPT v4 network",
    )
    require(
        "signing/serialization error: {:?}" in boot
        and "signing produced 0 bytes" not in boot,
        "runtime/unit_tests/boot.rs: HIL signing failures must preserve the underlying KSPT error",
    )

    state = read("apps/signer-firmware/src/runtime/input/state.rs")
    for obsolete in ("ViewSeed", "SignMsgScanQr", "Bip85Deriving"):
        require(
            obsolete not in state,
            f"runtime/input/state.rs: unreachable state {obsolete} must not return",
        )

    software = read("apps/signer-firmware/src/runtime/unit_tests/software.rs")
    require(
        "pub(super) fn run(initial_result: bool) -> bool" in software,
        "runtime/unit_tests/software.rs: missing scoped software self-test runner",
    )
    require(
        "backup_tests::run_tests()" not in software,
        "runtime/unit_tests/software.rs: memory-hard backup compatibility batch must not execute on device boot",
    )
    require(
        'log!("   Backup compatibility tests: host QA (memory-hard batch not run at boot)");'
        in software,
        "runtime/unit_tests/software.rs: boot log must explicitly report the host-owned backup compatibility batch",
    )
    service_tests = read("apps/signer-firmware/src/services/unit_tests/mod.rs")
    require(
        '#[cfg(test)]\npub mod backup_tests;' in service_tests
        and 'feature = "verbose-boot"' not in service_tests.split("pub mod backup_tests;")[0].splitlines()[-1],
        "services/unit_tests/mod.rs: backup compatibility module must be host-test-only",
    )
    hardware_tests = read("apps/signer-firmware/src/services/unit_tests/hardware.rs")
    require(
        '#[cfg(all(feature = "hardware-tests", feature = "argon2-bench"))]' in hardware_tests
        and "crate::diagnostics::argon2_bench::run" in hardware_tests,
        "services/unit_tests/hardware.rs: physical HIL must retain automated Argon2/PSRAM qualification",
    )
