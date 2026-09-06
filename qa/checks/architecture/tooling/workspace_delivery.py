"""Firmware delivery and master-runner workspace contracts."""

from __future__ import annotations

from pathlib import Path
import os
import tomllib

from architecture.core.common import has_exact_child


def _requires_posix_executable_mode() -> bool:
    """POSIX execute bits are not meaningful on native Windows filesystems."""
    return os.name != "nt"


def _check_firmware_delivery_paths(root: Path) -> list[str]:
    errors: list[str] = []
    firmware_root = root / "apps/signer-firmware"
    manifest_path = firmware_root / "Cargo.toml"
    lock_path = firmware_root / "Cargo.lock"
    shim_manifest_path = root / "external/serde-yaml-ng-adapter/Cargo.toml"
    shim_source_path = root / "external/serde-yaml-ng-adapter/src/lib.rs"
    installer_path = root / "install.sh"
    installer_parts = sorted((root / "tools/install/macos").glob("*.sh"))
    expected_installer_parts = {"common.sh", "device.sh", "environment.sh", "firmware.sh", "flash.sh"}
    actual_installer_parts = {path.name for path in installer_parts}
    if has_exact_child(root, "Install.sh"):
        errors.append("mixed-case monolithic Install.sh must not return")
    if actual_installer_parts != expected_installer_parts:
        errors.append(
            f"installer module inventory changed: expected {sorted(expected_installer_parts)}, "
            f"got {sorted(actual_installer_parts)}"
        )
    if not installer_path.is_file() or len(installer_path.read_text(errors="ignore").splitlines()) > 40:
        errors.append("install.sh must remain a small lowercase façade")
    for part in installer_parts:
        if len(part.read_text(errors="ignore").splitlines()) > 220:
            errors.append(f"installer module exceeds 220-line SRP limit: {part.relative_to(root)}")

    manifest = tomllib.loads(manifest_path.read_text())
    expected_patch = {"path": "../../external/serde-yaml-ng-adapter"}
    actual_patch = manifest.get("patch", {}).get("crates-io", {}).get("serde_yaml")
    if actual_patch != expected_patch:
        errors.append("firmware must route esp-config YAML through the vendored serde_yaml_ng adapter")

    if not shim_manifest_path.is_file() or not shim_source_path.is_file():
        errors.append("firmware serde_yaml compatibility package is incomplete")
    else:
        shim_manifest = tomllib.loads(shim_manifest_path.read_text())
        package = shim_manifest.get("package", {})
        dependencies = shim_manifest.get("dependencies", {})
        if package.get("name") != "serde_yaml" or package.get("version") != "0.9.34":
            errors.append("serde_yaml compatibility package must preserve esp-config's package contract")
        if dependencies.get("serde_yaml_ng") != "=0.10.0":
            errors.append("serde_yaml compatibility package must pin maintained serde_yaml_ng")
        if "pub use serde_yaml_ng::*;" not in shim_source_path.read_text(errors="ignore"):
            errors.append("serde_yaml compatibility package must re-export serde_yaml_ng")

    lock_source = lock_path.read_text(errors="ignore")
    if "0.9.34+deprecated" in lock_source:
        errors.append("firmware lockfile still contains deprecated serde_yaml registry package")
    if 'name = "serde_yaml_ng"' not in lock_source:
        errors.append("firmware lockfile is missing maintained serde_yaml_ng")

    installer = installer_path.read_text(errors="ignore") + "\n" + "\n".join(
        path.read_text(errors="ignore") for path in installer_parts
    )
    for required in ("espflash erase-flash", "espflash flash", "espflash write-bin"):
        if required not in installer:
            errors.append(f"installer lost supported firmware command: {required}")

    delivery_sources = {
        "install.sh and tools/install/macos": installer,
        "README.md": (root / "README.md").read_text(errors="ignore"),
        "Dockerfile": (root / "Dockerfile").read_text(errors="ignore"),
        "build/flash guide": (root / "docs/development/BUILD_FLASH_GUIDE.md").read_text(errors="ignore"),
        "eFuse runbook": (root / "docs/EFUSE_RUNBOOK.md").read_text(errors="ignore"),
    }
    forbidden_paths = (
        "esptool.py", "python3 -m esptool", "erase_flash", "write_flash",
        "pip3 install esptool", "grep -v \"DEPRECATED",
    )
    for owner, delivery_source in delivery_sources.items():
        for forbidden in forbidden_paths:
            if forbidden in delivery_source:
                errors.append(f"{owner} retains deprecated firmware path: {forbidden}")
    return errors


def _check_master_test_runner(root: Path) -> list[str]:
    errors: list[str] = []
    runner = root / "qa/linux/run-all.sh"
    terminal_helper = root / "qa/linux/lib/terminal_pause.sh"
    library_root = root / "qa/linux/runner"
    regression = root / "qa/tests/tooling/test_architecture_imports.py"
    if not runner.is_file():
        return ["master repository test runner is missing: qa/linux/run-all.sh"]
    if not terminal_helper.is_file():
        errors.append("Linux QA terminal pause helper is missing: qa/linux/lib/terminal_pause.sh")
    else:
        helper_source = terminal_helper.read_text(errors="ignore")
        for token in (
            "KASSIGNER_QA_LAUNCHER_ACTIVE",
            "KASSIGNER_QA_NO_PAUSE",
            "MAKELEVEL",
            "CI",
            "Press Enter to close this terminal",
            "PASS: %s completed successfully",
            "FAIL: %s exited with code %s",
        ):
            if token not in helper_source:
                errors.append(f"Linux QA terminal pause helper lost contract: {token}")

    launchers = (
        "qa/linux/run-all.sh",
        "qa/linux/run-funded-testnet-e2e.sh",
        "qa/linux/run-m5stack-security-hil.sh",
        "qa/linux/run-pinned-branch-coverage.sh",
        "qa/linux/run-production-hardening.sh",
        "qa/linux/run-real-node-integration.sh",
        "qa/linux/run-release-readiness.sh",
        "qa/linux/run-security-fuzz.sh",
        "qa/linux/release/generate_software_assurance.sh",
    )
    for relative in launchers:
        source_path = root / relative
        if not source_path.is_file():
            errors.append(f"Linux QA launcher is missing: {relative}")
            continue
        source = source_path.read_text(errors="ignore")
        if "terminal_pause.sh" not in source or "kassigner_qa_install_exit_handler" not in source:
            errors.append(f"Linux QA launcher lacks terminal result/pause handling: {relative}")
    expected_library = {"catalog.sh", "commands.sh", "environment.sh"}
    actual_library = {path.name for path in library_root.glob("*.sh")}
    if actual_library != expected_library:
        errors.append(
            f"master test-runner support inventory changed: expected "
            f"{sorted(expected_library)}, got {sorted(actual_library)}"
        )
    sources = [runner.read_text(errors="ignore")]
    sources.extend(
        (library_root / name).read_text(errors="ignore")
        for name in sorted(expected_library)
        if (library_root / name).is_file()
    )
    combined = "\n".join(sources)
    if _requires_posix_executable_mode() and not runner.stat().st_mode & 0o111:
        errors.append("master repository test runner must be executable")
    required_tokens = (
        "--resume-from", "--only", "--workspace", "--test", "--fuzz-passes",
        "initialize_test_environment", "CARGO_HOME", ".espup/export-esp.sh",
        "unit.shared-signer", "unit.signer-firmware-core", "unit.offline-signer", "unit.online-watcher",
        "unit.kassee-web", "unit.signer-firmware",
        "integration.shared-signer-conformance", "integration.repository-layout",
        "unit.kassee-ios-core", "unit.kassee-android-core",
        "integration.kassee-ios-quality", "integration.kassee-android-quality",
        "bench.shared-signer-protocol-throughput", "fuzz.repository-security-targets",
    )
    for token in required_tokens:
        if token not in combined:
            errors.append(f"master repository test runner lost required contract: {token}")
    catalog_path = root / "qa/config/run_all_steps.tsv"
    if not catalog_path.is_file():
        errors.append("canonical master test catalog is missing: qa/config/run_all_steps.tsv")
    else:
        rows = [
            line.split("\t", 4)
            for line in catalog_path.read_text(errors="ignore").splitlines()
            if line and not line.startswith("#")
        ]
        ids = [row[3] for row in rows if len(row) == 5]
        try:
            bench_offset = ids.index("bench.shared-signer-protocol-throughput")
            fuzz_offset = ids.index("fuzz.repository-security-targets")
        except ValueError:
            errors.append("master repository test catalog lost benchmark/fuzz stable IDs")
        else:
            if fuzz_offset < bench_offset:
                errors.append("master repository test runner must keep fuzz targets after benches")
    launcher_regression = root / "qa/tests/tooling/test_master_launcher.py"
    if not launcher_regression.is_file():
        errors.append("master launcher regression test is missing")
    elif "test_runner_loads_cargo_from_user_environment" not in launcher_regression.read_text(errors="ignore"):
        errors.append("master launcher Cargo-environment regression coverage is missing")
    if not regression.is_file():
        errors.append("architecture grouped-import regression test is missing")
    else:
        regression_source = regression.read_text(errors="ignore")
        for token in (
            "test_expands_direct_and_grouped_imports",
            "test_rejects_grouped_stale_wallet_import",
            "test_accepts_current_wallet_domain_imports",
        ):
            if token not in regression_source:
                errors.append(f"architecture import regression coverage is missing: {token}")
    return errors
