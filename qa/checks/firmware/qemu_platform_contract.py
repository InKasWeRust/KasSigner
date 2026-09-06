"""Source contracts for the ESP32-S3 QEMU platform and test backend."""

from __future__ import annotations

from pathlib import Path


def check_qemu_platform_contract(root: Path, errors: list[str]) -> None:
    """Keep QEMU explicit, isolated, test-enforced, and non-default."""

    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    check_features(read, require)
    check_guest_tests(read, require)
    check_bootstrap(read, require)
    check_host_runner(root, read, require)
    check_qa_registration(read, require)


def check_features(read, require) -> None:
    manifest = read("apps/signer-firmware/Cargo.toml")
    require(
        'default = ["waveshare"]' in manifest,
        "signer-firmware: real Waveshare hardware must remain the default platform",
    )
    require(
        'qemu = ["esp-println/uart"]' in manifest,
        "signer-firmware: QEMU must select UART logging without selecting a board",
    )
    require(
        'qemu-tests = ["qemu", "verbose-boot"]' in manifest,
        "signer-firmware: the QEMU test image must enable boot known-answer tests",
    )

    main = read("apps/signer-firmware/src/main.rs")
    for fragment in (
        "mod feature_policy;",
        '#[cfg(feature = "qemu")]\nmod qemu;',
        '#[cfg(any(not(feature = "qemu"), feature = "qemu-tests"))]\nmod self_test;',
    ):
        require(fragment in main, f"signer-firmware: missing QEMU gate: {fragment}")

    policy = read("apps/signer-firmware/src/feature_policy.rs")
    for fragment in (
        "platform features are mutually exclusive",
        "select one platform feature",
        "qemu cannot be combined with non-QEMU firmware features",
        "qemu verbose boot tests require the qemu-tests feature",
    ):
        require(fragment in policy, f"signer-firmware: missing feature policy: {fragment}")


def check_guest_tests(read, require) -> None:
    qemu_mod = read("apps/signer-firmware/src/qemu/mod.rs")
    for fragment in (
        "let _peripherals = esp_hal::init(config);",
        '#[cfg(feature = "qemu-tests")]\n    allocator::initialize();',
        "let delay = Delay::new();",
        "let (display, touch) = boot::initialize();",
        '#[cfg(feature = "qemu-tests")]\n    let (display, delay) = {',
        "if !validation::run(&mut display, &mut delay)",
        "validation::halt(&mut delay)",
    ):
        require(fragment in qemu_mod, f"QEMU entry point is missing {fragment}")
    for forbidden in ("let mut delay = Delay::new();", "let (mut display, touch)"):
        require(forbidden not in qemu_mod, f"QEMU entry point has unconditional mutability: {forbidden}")

    allocator = read("apps/signer-firmware/src/qemu/allocator.rs")
    for fragment in (
        "esp_alloc::HEAP.add_region(HeapRegion::new",
        "const QEMU_TEST_HEAP_BYTES: usize = 128 * 1024",
        "StaticCell<[u8; QEMU_TEST_HEAP_BYTES]>",
        "QEMU_TEST_HEAP.init_with",
        "pub(crate) fn probe() -> bool",
    ):
        require(fragment in allocator, f"QEMU test allocator is missing {fragment}")

    qr_encoder = read("apps/signer-firmware/src/qr/encoder/mod.rs")
    require(
        qr_encoder.count('#[cfg(not(feature = "qemu"))]') >= 2,
        "QEMU QR test build must not expose hardware-only QR facade exports",
    )

    report = read("apps/signer-firmware/src/qemu/validation/report.rs")
    for marker in (
        "KASSIGNER_QEMU_TESTS_PASS",
        "KASSIGNER_QEMU_TESTS_FAIL",
        "QEMU test summary",
    ):
        require(marker in report, f"QEMU guest report is missing {marker}")

    soc = read("apps/signer-firmware/src/qemu/validation/soc.rs")
    for check in (
        "internal SRAM volatile patterns",
        "internal heap allocation",
        "mapped SPI flash segment",
        "system timer and blocking delay",
        "RNG register stream sanity",
        "atomic compare/exchange",
    ):
        require(check in soc, f"QEMU SoC suite is missing {check}")

    target = read("apps/signer-firmware/src/qemu/validation/target.rs")
    for check in ("BIP39", "BIP32", "Schnorr", "KSPT", "QR encoder"):
        require(check in target, f"QEMU target KAT suite is missing {check}")

    unsupported = read("apps/signer-firmware/src/qemu/validation/unsupported.rs")
    for peripheral in ("PSRAM", "LCD", "camera", "SD card", "physical entropy"):
        require(
            peripheral in unsupported,
            f"QEMU coverage accounting is missing unsupported {peripheral}",
        )


def check_bootstrap(read, require) -> None:
    setup = read("scripts/linux/qemu/setup.sh")
    for fragment in (
        "install_qemu_host_packages",
        "install_rustup_if_missing",
        "install_esp_rust_toolchain",
        "install_espflash",
        "install_espressif_qemu",
    ):
        require(fragment in setup, f"QEMU setup facade is missing {fragment}")

    packages = read("scripts/linux/lib/qemu-packages.sh")
    for manager in ("apt-get", "dnf", "pacman"):
        require(manager in packages, f"QEMU host setup lost {manager} support")

    espressif = read("scripts/linux/lib/qemu-espressif.sh")
    require(
        'python3 "${idf_tools}" install qemu-xtensa' in espressif,
        "QEMU setup must install Espressif's Xtensa emulator",
    )
    require(
        "install-python-env" not in espressif and "export.sh" not in espressif,
        "QEMU setup must not activate unrelated full ESP-IDF tooling",
    )

    admin = read("scripts/linux/lib/admin.sh")
    for graphical_prompt in ("notify-send", "kdialog", "\\033]9;"):
        require(
            graphical_prompt not in admin,
            "administrator-access explanation must remain terminal-only",
        )


def check_host_runner(root: Path, read, require) -> None:
    build = read("tools/firmware/qemu/build.sh")
    for fragment in ("--features qemu-tests", "espflash save-image", "--merge"):
        require(fragment in build, f"QEMU build tool is missing {fragment}")

    require(
        not (root / "tools/firmware/qemu/run.sh").exists(),
        "QEMU test execution must live under qa/, not tools/",
    )
    runner = read("qa/checks/firmware/qemu/run.py")
    for fragment in (
        "KASSIGNER_QEMU_TESTS_BEGIN",
        "KASSIGNER_QEMU_UART_PROBE",
        "KASSIGNER_QEMU_TESTS_PASS",
        "KASSIGNER_QEMU_TESTS_FAIL",
        "--keep-running",
    ):
        require(fragment in runner, f"QEMU host runner is missing {fragment}")

    run_script = read("scripts/linux/qemu/run.sh")
    for fragment in (
        "tools/firmware/qemu/build.sh",
        "qa/checks/firmware/qemu/run.py",
        "--keep-running",
    ):
        require(fragment in run_script, f"QEMU run facade is missing {fragment}")


def check_qa_registration(read, require) -> None:
    matrix = read("tools/build/firmware/build_matrix.py")
    for build in ('FirmwareBuild("qemu")', 'FirmwareBuild("qemu-tests")'):
        require(build in matrix, f"firmware matrix is missing {build}")

    makefile = read("Makefile")
    require(
        "scripts/common/lib/make_tasks.py" in makefile,
        "Makefile must route through the shared cross-platform make helper",
    )
    for target, entrypoint in (
        ("firmware-qemu-setup", "qemu-setup"),
        ("firmware-qemu", "qemu-build"),
        ("firmware-qemu-test", "qemu-test"),
    ):
        require(
            f"{target}:" in makefile and f"$(MAKE_TASK) entrypoint {entrypoint}" in makefile,
            f"Makefile must route {target} through native entrypoint {entrypoint}",
        )
    require("firmware-qemu-run:" not in makefile, "QEMU run/keep-open is an internal implementation detail, not a public Make target")

    catalog = read("qa/config/run_all_steps.tsv")
    linux_dispatch = read("qa/linux/runner/catalog.sh")
    require(
        "qa\temulation\tsigner-firmware\temulation.signer-firmware-qemu\t" in catalog
        and "scripts/linux/qemu/test.sh" in linux_dispatch,
        "master QA catalog must execute the QEMU software-emulation suite",
    )
