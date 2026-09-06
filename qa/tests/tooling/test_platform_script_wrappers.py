#!/usr/bin/env python3
"""Regression coverage for organized native platform script trees."""
from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
LINUX = SCRIPTS / "linux"
WINDOWS = SCRIPTS / "windows"
MAC = SCRIPTS / "mac"
COMMON = SCRIPTS / "common"
MAKEFILE = ROOT / "Makefile"
CATEGORIES = {"build", "install", "lib", "qemu", "quality"}
PUBLIC = {
    "install/install",
    "quality/run-all",
    "quality/funded-testnet-e2e",
    "quality/pinned-branch-coverage",
    "quality/production-hardening",
    "quality/real-node-integration",
    "quality/release-readiness",
    "quality/security-fuzz",
    "quality/software-assurance",
    "quality/crap",
    "quality/branch-coverage-setup",
    "build/kassee-web-build",
    "build/sdk-build",
    "build/android-studio",
    "build/android-build",
    "build/android-runtime-sync",
    "build/ios-runtime-sync",
    "build/ios-build",
    "build/reproducible-build",
    "build/firmware-build",
    "build/firmware-build-production",
    "build/firmware-owner-build",
    "build/sdk-distribution-check",
    "qemu/setup",
    "qemu/build",
    "qemu/test",
    "qemu/run",
    "qemu/firmware-build",
}


class PlatformScriptWrapperTests(unittest.TestCase):
    def test_windows_native_capture_preserves_nonzero_native_exit_codes(self) -> None:
        common = (WINDOWS / "lib/common.ps1").read_text(encoding="utf-8")
        start = common.index("function Invoke-KasSignerCapture")
        end = common.index("function Remove-KasSignerPath", start)
        capture = common[start:end]
        self.assertIn("$savedPreference = $ErrorActionPreference", capture)
        self.assertIn("$ErrorActionPreference = 'Continue'", capture)
        self.assertIn("$ErrorActionPreference = $savedPreference", capture)
        self.assertIn("$LASTEXITCODE", capture)
        self.assertIn("2>&1 | Out-String", capture)
        self.assertIn("catch [System.Management.Automation.CommandNotFoundException]", capture)
        self.assertIn("$code = 127", capture)

    def test_windows_zero_argument_real_node_facade_does_not_forward_empty_array(self) -> None:
        facade = (WINDOWS / "quality/real-node-integration.ps1").read_text(encoding="utf-8")
        dispatcher = (WINDOWS / "lib/_invoke.ps1").read_text(encoding="utf-8")
        self.assertIn("if (@($args).Count -ne 0)", facade)
        self.assertIn("-Target 'qa/windows/run-real-node-integration.ps1'", facade)
        self.assertNotIn("-CommandArguments", facade)
        self.assertIn("if (@($CommandArguments).Count -eq 0)", dispatcher)
        self.assertIn("-File $targetPath\n", dispatcher)
        self.assertIn("-File $targetPath @CommandArguments", dispatcher)

    def test_windows_real_node_canonical_script_is_truly_zero_argument(self) -> None:
        path = ROOT / "qa/windows/run-real-node-integration.ps1"
        source = path.read_text(encoding="utf-8")
        self.assertNotIn("ValueFromRemainingArguments", source)
        self.assertNotIn("$RemainingArgs", source)
        self.assertIn("if (@($args).Count -ne 0)", source)
        self.assertIn("public-node resolver only; no local-node mode exists", source)

    def test_windows_zero_argument_funded_e2e_facade_does_not_forward_empty_array(self) -> None:
        facade = (WINDOWS / "quality/funded-testnet-e2e.ps1").read_text(encoding="utf-8")
        dispatcher = (WINDOWS / "lib/_invoke.ps1").read_text(encoding="utf-8")
        self.assertIn("if (@($args).Count -ne 0)", facade)
        self.assertIn("-Target 'qa/windows/run-funded-testnet-e2e.ps1'", facade)
        self.assertNotIn("-CommandArguments", facade)
        self.assertIn("if (@($CommandArguments).Count -eq 0)", dispatcher)

    def test_windows_funded_e2e_canonical_script_is_truly_zero_argument(self) -> None:
        path = ROOT / "qa/windows/run-funded-testnet-e2e.ps1"
        source = path.read_text(encoding="utf-8")
        self.assertNotIn("ValueFromRemainingArguments", source)
        self.assertNotIn("$RemainingArgs", source)
        self.assertIn("if (@($args).Count -ne 0)", source)
        self.assertIn("asks for the public Kaspa testnet interactively", source)

    def test_windows_funded_e2e_preserves_interactive_prompts_and_skip_exit_77(self) -> None:
        source = (ROOT / "qa/windows/run-funded-testnet-e2e.ps1").read_text(encoding="utf-8")
        self.assertIn("& $python 'qa/checks/integration/funded_testnet_e2e.py'", source)
        self.assertIn("$LASTEXITCODE", source)
        self.assertIn("@(0,77) -notcontains $status", source)
        self.assertIn("exit $status", source)
        self.assertNotIn("Invoke-KasSignerCommand -Command $python -Arguments @('qa/checks/integration/funded_testnet_e2e.py')", source)
        self.assertNotIn("| Out-Null", source[source.index("$python = Get-KasSignerPython"):])

    def test_windows_qemu_test_facade_does_not_forward_empty_argument_splat(self) -> None:
        source = (WINDOWS / "qemu/test.ps1").read_text(encoding="utf-8")
        self.assertIn("if (@($args).Count -eq 0)", source)
        zero_argument_branch = source[source.index("if (@($args).Count -eq 0)"):source.index("} else {")]
        self.assertIn("& $runScript -TestOnly", zero_argument_branch)
        self.assertNotIn("@args", zero_argument_branch)
        self.assertIn("& $runScript -TestOnly @args", source)

    def test_windows_qemu_run_filters_phantom_null_remaining_arguments(self) -> None:
        source = (WINDOWS / "qemu/run.ps1").read_text(encoding="utf-8")
        self.assertIn("$unsupportedArgs = @($RemainingArgs | Where-Object", source)
        self.assertIn("[string]::IsNullOrEmpty($_)", source)
        self.assertIn("$unsupportedArgs.Count -gt 0", source)
        self.assertIn("$unsupportedArgs[0]", source)
        self.assertNotIn("$RemainingArgs[0]", source)

    def test_windows_optional_tool_probes_can_bootstrap_missing_espflash(self) -> None:
        qemu = (WINDOWS / "lib/qemu-common.ps1").read_text(encoding="utf-8")
        self.assertIn("Invoke-KasSignerCapture -Command 'espflash'", qemu)
        self.assertIn("'install','espflash','--version',$env:KASSIGNER_ESPFLASH_VERSION", qemu)
        self.assertLess(
            qemu.index("Invoke-KasSignerCapture -Command 'espflash'"),
            qemu.index("Require-KasSignerCommand espflash"),
        )

    def test_windows_python_selector_requires_tomllib_capable_runtime(self) -> None:
        common = (WINDOWS / "lib/common.ps1").read_text(encoding="utf-8")
        start = common.index("function Get-KasSignerPython")
        end = common.index("function Require-KasSignerCommand", start)
        selector = common[start:end]
        self.assertIn("Get-Command 'py.exe'", selector)
        self.assertIn("'3.13','3.12','3.11'", selector)
        self.assertIn("sys.version_info >= (3, 11)", selector)
        self.assertIn("Python 3.11 or newer is required", selector)
        self.assertIn("Run make install", selector)

    def test_windows_standalone_lock_repair_does_not_require_python(self) -> None:
        locks = (WINDOWS / "lib/cargo_locks.ps1").read_text(encoding="utf-8")
        start = locks.index("function Get-KasSignerLockPackageCount")
        end = locks.index("function Invoke-KasSignerHostCargoMetadata", start)
        counter = locks[start:end]
        self.assertNotIn("Get-KasSignerPython", counter)
        self.assertNotIn("tomllib", counter)
        self.assertIn("Select-String", counter)
        self.assertIn(r"\[\[package\]\]", counter)

    def test_windows_cargo_metadata_compatibility_avoids_powershell_json_case_collision(self) -> None:
        locks = (WINDOWS / "lib/cargo_locks.ps1").read_text(encoding="utf-8")
        self.assertNotIn("$Json | ConvertFrom-Json", locks)
        self.assertIn("cargo_metadata_compat.py", locks)
        self.assertIn("Write-KasSignerUtf8NoBom", locks)

        helper = ROOT / "scripts/common/lib/cargo_metadata_compat.py"
        metadata = {
            "packages": [
                {
                    "name": "caseful",
                    "version": "1.0.0",
                    "rust_version": "1.84",
                    "metadata": {"Default": True, "default": False},
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            metadata_path = Path(temporary) / "metadata.json"
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            compatible = subprocess.run(
                [sys.executable, str(helper), "--metadata", str(metadata_path), "--max-rust", "1.85"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(compatible.returncode, 0, compatible.stderr)
            incompatible = subprocess.run(
                [sys.executable, str(helper), "--metadata", str(metadata_path), "--max-rust", "1.83"],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(incompatible.returncode, 1, incompatible.stderr)
            self.assertIn("caseful 1.0.0 requires Rust 1.84", incompatible.stdout)

    def test_windows_runner_lock_creates_fresh_target_parent_tree(self) -> None:
        runner_path = ROOT / "qa/windows/runner/run_all.py"
        spec = importlib.util.spec_from_file_location("windows_run_all_fresh_lock", runner_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        marker_name = "KASSIGNER_QA_RUN_ALL_LOCK_ROOT"
        previous_marker = os.environ.pop(marker_name, None)
        original_root = module.ROOT
        handle = None
        try:
            with tempfile.TemporaryDirectory() as temporary:
                fresh_root = Path(temporary) / "fresh-repository"
                fresh_root.mkdir()
                module.ROOT = fresh_root
                handle = module.acquire_lock()
                self.assertTrue((fresh_root / "target/qa/state/release-workflow.lock").is_file())
                self.assertIsNotNone(handle)
                handle.close()
                handle = None
        finally:
            if handle is not None:
                handle.close()
            module.ROOT = original_root
            if previous_marker is None:
                os.environ.pop(marker_name, None)
            else:
                os.environ[marker_name] = previous_marker

    def test_scripts_root_contains_only_platform_directories(self) -> None:
        self.assertEqual({p.name for p in SCRIPTS.iterdir()}, {"common", "linux", "mac", "windows"})
        self.assertTrue(all(p.is_dir() for p in SCRIPTS.iterdir()))

    def test_platform_trees_have_same_top_level_categories(self) -> None:
        for tree in (LINUX, WINDOWS):
            self.assertEqual({p.name for p in tree.iterdir() if p.is_dir()}, CATEGORIES)
            self.assertFalse(any(p.is_file() for p in tree.iterdir()))

    def test_macos_tree_is_ios_scoped_and_has_setup_wrappers(self) -> None:
        self.assertEqual({p.name for p in MAC.iterdir()}, {"build", "install.sh", "setup-macos.command", "run-ios.command"})
        self.assertEqual(
            {p.name for p in (MAC / "build").iterdir()},
            {"ios-build.sh", "ios-runtime-sync.sh"},
        )
        installer = (MAC / "install.sh").read_text(encoding="utf-8")
        setup = (MAC / "setup-macos.command").read_text(encoding="utf-8")
        for source in (installer, setup):
            self.assertIn("apps/kassee-ios/setup-macos.command", source)
        self.assertIn("--no-pause", installer)
        launcher = (MAC / "run-ios.command").read_text(encoding="utf-8")
        for token in (
            "xcrun simctl list devices",
            "xcrun simctl boot",
            "xcrun simctl bootstatus",
            "xcrun simctl install",
            "xcrun simctl launch",
            "-derivedDataPath",
            "target/ios-simulator",
            "org.kassigner.KasSigner",
            "KASSIGNER_IOS_RUNTIME_SYNCED=1",
        ):
            self.assertIn(token, launcher)
        self.assertIn('SIMULATOR_NAME="${KASSIGNER_IOS_SIMULATOR_NAME:-iPhone 16 Pro}"', launcher)
        self.assertIn('[[ "$(uname -s)" == "Darwin" ]]', launcher)

    def test_public_entrypoints_are_mirrored_by_relative_path(self) -> None:
        linux = {
            p.relative_to(LINUX).with_suffix("").as_posix()
            for p in LINUX.rglob("*.sh")
            if p.parent.name in {"build", "install", "qemu", "quality"}
        }
        windows = {
            p.relative_to(WINDOWS).with_suffix("").as_posix()
            for p in WINDOWS.rglob("*.ps1")
            if p.parent.name in {"build", "install", "qemu", "quality"}
        }
        self.assertEqual(PUBLIC, linux)
        self.assertEqual(PUBLIC, windows)

    def test_make_helpers_have_one_common_owner(self) -> None:
        helper = COMMON / "lib/make_tasks.py"
        self.assertTrue(helper.is_file())
        for name in ("make_tasks.py", "serial_access.py", "esp_toolchain.py", "make_public.py", "make_clean.py"):
            self.assertTrue((COMMON / "lib" / name).is_file())
            self.assertFalse((LINUX / "lib" / name).exists())
            self.assertFalse((WINDOWS / "lib" / name).exists())
        helper_source = helper.read_text(encoding="utf-8")
        self.assertIn('selected_port = port.strip() or None', helper_source)
        self.assertIn("prepare_serial_command", helper_source)
        self.assertIn('DEFAULT_SCRIPT_ROOT = ROOT / "scripts" / ("windows" if IS_WINDOWS else "linux")', helper_source)
        self.assertIn('MAC_NATIVE_ENTRYPOINTS = {"ios-runtime-sync", "ios-build"}', helper_source)
        source = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("scripts/common/lib/make_tasks.py", source)
        self.assertNotIn("SCRIPT_PLATFORM", source)
        self.assertNotIn("scripts/platform.py", source)
        self.assertNotIn("scripts/entrypoints.json", source)


    def test_windows_runner_forces_utf8_for_child_python(self) -> None:
        source = (ROOT / "qa/windows/runner/run_all.py").read_text(encoding="utf-8")
        self.assertIn('os.environ["PYTHONUTF8"] = "1"', source)
        self.assertIn('os.environ["PYTHONIOENCODING"] = "utf-8"', source)

    def test_posix_only_tooling_execution_is_platform_scoped(self) -> None:
        expectations = {
            "test_master_launcher.py": "Linux master-launcher tests are POSIX-specific",
            "test_reproducible_build_runner.py": "Linux reproducible-build runner tests are POSIX-specific",
        }
        tooling = ROOT / "qa/tests/tooling"
        for filename, reason in expectations.items():
            source = (tooling / filename).read_text(encoding="utf-8")
            self.assertIn(reason, source, filename)
        qemu = (tooling / "test_qemu_runner.py").read_text(encoding="utf-8")
        self.assertIn("QemuRunnerPortabilityTests", qemu)
        self.assertIn('QEMU fake guest fixture is POSIX-specific', qemu)
        self.assertNotIn('QEMU host marker runner uses POSIX pipe/fd semantics', qemu)

    def test_windows_sources_never_bridge_to_wsl_or_bash(self) -> None:
        forbidden = ("wsl.exe", "wslpath", "_invoke-wsl", "bash.exe", "/bin/bash")
        for path in WINDOWS.rglob("*.ps1"):
            source = path.read_text(encoding="utf-8").lower()
            for token in forbidden:
                self.assertNotIn(token, source, f"{path.relative_to(ROOT)}: {token}")

    def test_linux_dispatcher_preserves_arguments_and_exit_code(self) -> None:
        fixture_dir = ROOT / "target/qa/platform-wrapper-test"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        fixture = fixture_dir / "fixture.sh"
        fixture.write_text(
            "#!/usr/bin/env bash\n"
            "printf '<%s>\\n' \"$@\"\n"
            "exit 23\n",
            encoding="utf-8",
        )
        try:
            result = subprocess.run(
                [
                    "bash",
                    str(LINUX / "lib/_invoke.sh"),
                    fixture.relative_to(ROOT).as_posix(),
                    "alpha beta",
                    "--flag=value",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 23, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["<alpha beta>", "<--flag=value>"])
        finally:
            shutil.rmtree(fixture_dir, ignore_errors=True)

    def test_dispatchers_fail_closed_on_target_escape(self) -> None:
        self.assertIn('"$TARGET" != *".."*', (LINUX / "lib/_invoke.sh").read_text(encoding="utf-8"))
        windows = (WINDOWS / "lib/_invoke.ps1").read_text(encoding="utf-8")
        self.assertIn("[System.IO.Path]::IsPathRooted($Target)", windows)

    def test_make_helper_maps_to_organized_platform_paths(self) -> None:
        helper = COMMON / "lib/make_tasks.py"
        spec = importlib.util.spec_from_file_location("make_tasks", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.ENTRYPOINTS["run-all"], "quality/run-all")
        self.assertEqual(module.ENTRYPOINTS["android-build"], "build/android-build")
        self.assertEqual(module.ENTRYPOINTS["qemu-test"], "qemu/test")
        self.assertEqual(module.ENTRYPOINTS["sdk-build"], "build/sdk-build")

        calls = []
        original_run = module.run
        original_macos = module.IS_MACOS
        original_windows = module.IS_WINDOWS
        original_default_script_root = module.DEFAULT_SCRIPT_ROOT
        try:
            module.IS_MACOS = True
            module.IS_WINDOWS = False
            module.DEFAULT_SCRIPT_ROOT = module.ROOT / "scripts" / "linux"
            module.run = lambda command, **kwargs: calls.append(command) or 0
            self.assertEqual(module.platform("ios-build", ["build"]), 0)
            self.assertIn("scripts/mac/build/ios-build.sh", calls.pop()[1].replace("\\", "/"))
            self.assertEqual(module.platform("kassee-web-build", []), 0)
            self.assertIn("scripts/linux/build/kassee-web-build.sh", calls.pop()[1].replace("\\", "/"))
        finally:
            module.run = original_run
            module.IS_MACOS = original_macos
            module.IS_WINDOWS = original_windows
            module.DEFAULT_SCRIPT_ROOT = original_default_script_root

    def test_android_portable_smoke_skips_without_standalone_kotlin_cli(self) -> None:
        runner = ROOT / "qa/checks/android/run_core_tests.py"
        spec = importlib.util.spec_from_file_location("android_portable_core", runner)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module.shutil, "which", return_value=None):
            self.assertEqual(module.main(), 77)

    def test_android_qa_accepts_optional_helper_skip_after_gradle_tests(self) -> None:
        helper = COMMON / "lib/make_tasks.py"
        spec = importlib.util.spec_from_file_location("make_tasks_android_qa", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        calls: list[list[str]] = []
        results = iter((0, 77, 0, 0, 0))
        with mock.patch.object(module, "platform", return_value=0), mock.patch.object(
            module.shutil, "which", return_value="/toolchain/bin/tool"
        ), mock.patch.object(
            module, "run", side_effect=lambda command, **_kwargs: calls.append(command) or next(results)
        ):
            self.assertEqual(module.android_action("qa"), 0)
        self.assertEqual(len(calls), 5)
        self.assertTrue(any(command[-1].endswith("run_core_tests.py") for command in calls))

    def test_android_qa_skips_portable_smoke_before_invocation_without_global_kotlin_cli(self) -> None:
        helper = COMMON / "lib/make_tasks.py"
        spec = importlib.util.spec_from_file_location("make_tasks_android_qa_no_kotlinc", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        calls: list[list[str]] = []
        with mock.patch.object(module, "platform", return_value=0), mock.patch.object(
            module.shutil, "which", side_effect=lambda name: None if name in {"kotlinc", "java"} else f"/{name}"
        ), mock.patch.object(
            module, "run", side_effect=lambda command, **_kwargs: calls.append(command) or 0
        ):
            self.assertEqual(module.android_action("qa"), 0)
        self.assertEqual(len(calls), 4)
        self.assertFalse(any(command[-1].endswith("run_core_tests.py") for command in calls))

    def test_flash_release_uses_only_existing_checksum_verified_signed_image(self) -> None:
        helper = COMMON / "lib/make_tasks.py"
        spec = importlib.util.spec_from_file_location("make_tasks_flash_release", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as td:
            release = Path(td)
            image = release / "kassigner-m5stack-full.bin"
            image.write_bytes(b"signed-merged-release-fixture")
            digest = __import__("hashlib").sha256(image.read_bytes()).hexdigest()
            (release / "SHA256SUMS").write_text(
                f"{digest}  {image.name}\n", encoding="utf-8"
            )
            board_result = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="--chip\nesp32s3\n--before\nusb-reset\n"
            )
            flashed: list[list[str]] = []
            with mock.patch.object(module.subprocess, "run", return_value=board_result), \
                 mock.patch.object(module, "prepare_serial_command", side_effect=lambda command, _port: command), \
                 mock.patch.object(module, "run", side_effect=lambda command, **_kwargs: flashed.append(command) or 0):
                self.assertEqual(module.flash_release("m5stack", "COM7", str(release)), 0)

            self.assertEqual(len(flashed), 1)
            command = flashed[0]
            self.assertEqual(command[0:2], ["espflash", "write-bin"])
            self.assertIn("--port", command)
            self.assertIn("COM7", command)
            self.assertEqual(command[-2:], ["0x0", str(image)])
            self.assertNotIn("flash", command[1:])
            self.assertFalse(any("unsigned" in token for token in command))

            image.write_bytes(b"tampered")
            flashed.clear()
            with mock.patch.object(module, "run", side_effect=lambda command, **_kwargs: flashed.append(command) or 0):
                self.assertEqual(module.flash_release("m5stack", "", str(release)), 2)
            self.assertEqual(flashed, [])

    def test_secure_release_profiles_are_nonflashing_and_owner_only_drops_vendor_identity(self) -> None:
        helper = COMMON / "lib/make_firmware_profiles.py"
        spec = importlib.util.spec_from_file_location("make_firmware_profiles_test", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as td:
            temp = Path(td)
            owner = temp / "owner.pem"
            vendor = temp / "vendor.pem"
            schnorr = temp / "vendor.schnorr"
            owner.write_text("owner-rsa-fixture", encoding="utf-8")
            vendor.write_text("vendor-rsa-fixture", encoding="utf-8")
            schnorr.write_bytes(b"v" * 32)
            calls: list[tuple[list[str], dict[str, str]]] = []

            def record(command, **kwargs):
                calls.append((command, dict(kwargs["env"])))
                return 0

            base_env = {"KASSIGNER_SIGNING_KEY": "inherited-vendor-key"}
            with mock.patch.object(module, "prepare_esp_build_environment", return_value=base_env.copy()), \
                 mock.patch.object(module.shutil, "which", side_effect=lambda name: "/bin/bash" if name == "bash" else None):
                self.assertEqual(
                    module.secure_release_profile(ROOT, False, record, "owner-only", str(temp / "owner-out"), str(owner), ""),
                    0,
                )
            command, env = calls.pop()
            self.assertIn("--owner-only", command)
            self.assertTrue(command[-1].endswith("owner-out"))
            self.assertEqual(env["KASSIGNER_OWNER_SECURE_BOOT_KEY"], str(owner.resolve()))
            self.assertNotIn("KASSIGNER_SIGNING_KEY", env)
            self.assertFalse(any(token in command for token in ("flash", "espefuse", "espflash")))

            with mock.patch.object(module, "prepare_esp_build_environment", return_value={}), \
                 mock.patch.object(module.shutil, "which", side_effect=lambda name: "/bin/bash" if name == "bash" else None):
                self.assertEqual(
                    module.secure_release_profile(ROOT, False, record, "dual", str(temp / "dual-out"), str(vendor), str(schnorr)),
                    0,
                )
            command, env = calls.pop()
            self.assertNotIn("--owner-only", command)
            self.assertEqual(env["KASSIGNER_SECURE_BOOT_SIGNING_KEY"], str(vendor.resolve()))
            self.assertEqual(env["KASSIGNER_SIGNING_KEY"], str(schnorr.resolve()))

            with mock.patch.object(module, "prepare_esp_build_environment", return_value={"KASSIGNER_SIGNING_KEY": "inherited"}), \
                 mock.patch.object(module.shutil, "which", side_effect=lambda name: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe" if name == "powershell.exe" else None):
                self.assertEqual(
                    module.secure_release_profile(ROOT, True, record, "owner-only", str(temp / "win-owner-out"), str(owner), ""),
                    0,
                )
            command, env = calls.pop()
            self.assertIn("prepare_m5stack_secure_release.ps1", " ".join(command).replace("\\", "/"))
            self.assertIn("-OwnerOnly", command)
            self.assertNotIn("KASSIGNER_SIGNING_KEY", env)

    def test_secure_release_preparation_rejects_stale_opposite_policy_artifacts(self) -> None:
        script = ROOT / "tools/build/firmware/prepare_m5stack_secure_release.sh"
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "kassigner-m5stack-secure-provisioning.bin").write_bytes(b"stale-dual")
            result = subprocess.run(
                ["bash", str(script), "--owner-only", str(out)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("stale dual-authority artifact", result.stderr)

        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "kassigner-m5stack-secure-owner-only.bin").write_bytes(b"stale-owner")
            result = subprocess.run(
                ["bash", str(script), str(out)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("stale owner-only artifact", result.stderr)

    def test_make_is_the_stable_public_developer_facade(self) -> None:
        source = MAKEFILE.read_text(encoding="utf-8")
        expected = {
            "kassee", "sdk", "ios", "ios-release", "ios-test", "ios-qa",
            "android", "android-release", "android-test", "android-qa",
            "firmware", "flash", "flash-release", "secure-provisioning", "secure-owner-only",
            "firmware-mirror", "owner-firmware", "test-hardware",
            "workflow-e2e", "workflow-hil", "firmware-qemu-setup",
            "firmware-qemu", "firmware-qemu-test", "test", "qa",
            "release", "release-readiness", "clean", "help",
        }
        targets = {
            match.group(1)
            for match in re.finditer(r"(?m)^([A-Za-z0-9_.-]+):(?:\s|$)", source)
            if match.group(1) != ".PHONY"
        }
        self.assertEqual(targets, expected)
        for forbidden in (
            "test-fast", "reproducible-build", "real-node-integration", "branch-coverage-setup",
            "branch-coverage-bundle", "all", "firmware-qemu-run", "firmware-dev",
            "firmware-m5", "firmware-check", "firmware-lint", "architecture",
            "crap-check", "health-check", "security-invariants", "branch-ratchets",
            "mutation-critical", "mutation-certify", "fuzz-security", "firmware-features",
        ):
            self.assertNotRegex(source, rf"(?m)^{re.escape(forbidden)}:")
        self.assertIn('firmware:\n\t$(MAKE_TASK) firmware "$(BOARD)"', source)
        self.assertIn('flash:\n\t$(MAKE_TASK) flash "$(BOARD)" "$(PORT)"', source)
        self.assertIn('flash-release:\n\t$(MAKE_TASK) flash-release "$(BOARD)" "$(PORT)" "$(RELEASE_DIR)"', source)
        self.assertIn('secure-provisioning:\n\t$(MAKE_TASK) secure-release dual "$(SECURE_DIR)" "$(SECURE_BOOT_KEY)" "$(SIGNING_KEY)"', source)
        self.assertIn('secure-owner-only:\n\t$(MAKE_TASK) secure-release owner-only "$(SECURE_DIR)" "$(OWNER_KEY)" ""', source)
        self.assertIn('test:\n\t$(MAKE_TASK) test "$(STRICT_LOCKFILES)"', source)
        self.assertIn('qa:\n\t$(MAKE_TASK) qa "$(FUZZ_PASSES)" "$(STRICT_LOCKFILES)"', source)
        self.assertIn('release:\n\t$(MAKE_TASK) release', source)
        help_text = subprocess.run(["make", "help"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
        for command in ("make test", "make qa", "make firmware", "make flash", "make flash-release",
                        "make secure-provisioning", "make secure-owner-only", "make ios", "make android",
                        "make release", "make release-readiness"):
            self.assertIn(command, help_text)
        for forbidden in ("make architecture", "make crap-check", "make mutation-certify", "make reproducible-build", "make firmware-m5"):
            self.assertNotIn(forbidden, help_text)
        self.assertIn("BOARD defaults to m5stack", help_text)

    def test_mobile_make_targets_are_real_native_build_and_test_operations(self) -> None:
        makefile = MAKEFILE.read_text(encoding="utf-8")
        for recipe in (
            'ios:\n\t$(MAKE_TASK) ios build',
            'ios-release:\n\t$(MAKE_TASK) ios release',
            'ios-test:\n\t$(MAKE_TASK) ios test',
            'android:\n\t$(MAKE_TASK) android build',
            'android-release:\n\t$(MAKE_TASK) android release',
            'android-test:\n\t$(MAKE_TASK) android test',
        ):
            self.assertIn(recipe, makefile)
        ios = (LINUX / "build/ios-build.sh").read_text(encoding="utf-8")
        self.assertIn('[[ "$(uname -s)" != "Darwin" ]]', ios)
        mac_ios = (MAC / "build/ios-build.sh").read_text(encoding="utf-8")
        self.assertIn('[[ "$(uname -s)" != "Darwin" ]]', mac_ios)
        self.assertIn("xcodebuild", mac_ios)
        self.assertIn("-configuration Debug", mac_ios)
        self.assertIn("xcodebuild archive", mac_ios)
        self.assertIn("-configuration Release", mac_ios)
        self.assertGreaterEqual(mac_ios.count("KASSIGNER_IOS_RUNTIME_SYNCED=1"), 3)
        self.assertIn("XCTest", (COMMON / "lib/make_help.txt").read_text(encoding="utf-8"))
        windows_ios = (WINDOWS / "build/ios-build.ps1").read_text(encoding="utf-8")
        self.assertIn("requires macOS with Xcode", windows_ios)
        android = (LINUX / "build/android-build.sh").read_text(encoding="utf-8")
        self.assertIn("assembleDebug", android)
        self.assertIn("assembleRelease", android)
        self.assertIn("testDebugUnitTest", android)
        self.assertIn("app/build/outputs/apk/$MODE", android)
        self.assertIn("Built artifact", android)
        self.assertNotIn("lintDebug", android)
        windows_android = (WINDOWS / "build/android-build.ps1").read_text(encoding="utf-8")
        self.assertIn("app/build/outputs/apk/$Mode", windows_android)
        self.assertIn("Built artifact", windows_android)
        for ios_build in (ios, mac_ios):
            self.assertIn('-derivedDataPath "$DERIVED_DATA"', ios_build)
            self.assertIn("Built artifact", ios_build)
            self.assertIn("Built archive:", ios_build)
            self.assertIn("Test result bundle:", ios_build)

    @unittest.skipUnless(os.name == "posix", "mobile artifact-reporting fixture uses POSIX shell stubs")
    def test_mobile_build_wrappers_print_concrete_artifact_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir(parents=True)

            # Android: use a project-local fake Gradle that creates the same
            # release APK location produced by the Android Gradle plugin.
            android_script = root / "scripts/linux/build/android-build.sh"
            android_script.parent.mkdir(parents=True)
            shutil.copy2(LINUX / "build/android-build.sh", android_script)
            android_script.chmod(0o755)
            android = root / "apps/kassee-android"
            wrapper = android / "gradle/wrapper/gradle-wrapper.properties"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.0-bin.zip\n"
                "distributionSha256Sum=553c78f50dafcd54d65b9a444649057857469edf836431389695608536d6b746\n",
                encoding="utf-8",
            )
            daemon_jvm = android / "gradle/gradle-daemon-jvm.properties"
            daemon_jvm.write_text("toolchainVersion=25\n", encoding="utf-8")
            toolchains = root / "qa/config/toolchains.env"
            toolchains.parent.mkdir(parents=True)
            toolchains.write_text("KASSIGNER_ANDROID_JDK=25\n", encoding="utf-8")
            sdk_platform = root / "sdk/platforms/android-37"
            sdk_platform.mkdir(parents=True)
            (sdk_platform / "android.jar").write_bytes(b"")
            (sdk_platform / "source.properties").write_text("AndroidVersion.ApiLevel = 37\n", encoding="utf-8")
            gradle = fake_bin / "gradle"
            gradle.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "if [[ \"${1:-}\" == \"--version\" ]]; then echo 'Gradle 9.5.0'; exit 0; fi\n"
                "project=''\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  if [[ \"$1\" == '--project-dir' ]]; then project=\"$2\"; shift 2; continue; fi\n"
                "  shift\n"
                "done\n"
                "mkdir -p \"$project/app/build/outputs/apk/release\"\n"
                ": > \"$project/app/build/outputs/apk/release/app-release-unsigned.apk\"\n",
                encoding="utf-8",
            )
            gradle.chmod(0o755)
            fake_jdk = root / "fake-jdk"
            java = fake_jdk / "bin/java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "#!/usr/bin/env bash\n"
                "echo 'openjdk version \"25.0.0\"' >&2\n",
                encoding="utf-8",
            )
            java.chmod(0o755)
            env = os.environ.copy()
            env.update({
                "KASSIGNER_ANDROID_SDK_ROOT": str(root / "sdk"),
                "GRADLE_BIN": str(gradle),
                "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
                "JAVA_HOME": str(fake_jdk),
            })
            android_run = subprocess.run(
                ["bash", str(android_script), "release"], cwd=root, env=env,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(android_run.returncode, 0, android_run.stdout + android_run.stderr)
            expected_apk = android / "app/build/outputs/apk/release/app-release-unsigned.apk"
            self.assertIn("Built artifact:", android_run.stdout)
            self.assertIn(str(expected_apk), android_run.stdout)

            # iOS: fake Darwin/Xcode and make xcodebuild materialize the
            # deterministic target/ios paths owned by the wrapper.
            ios_script = root / "scripts/mac/build/ios-build.sh"
            ios_script.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(MAC / "build/ios-build.sh", ios_script)
            ios_script.chmod(0o755)
            runtime_sync = root / "scripts/mac/build/ios-runtime-sync.sh"
            runtime_sync.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            runtime_sync.chmod(0o755)
            uname = fake_bin / "uname"
            uname.write_text("#!/usr/bin/env bash\necho Darwin\n", encoding="utf-8")
            uname.chmod(0o755)
            xcodebuild = fake_bin / "xcodebuild"
            xcodebuild.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "archive=''\n"
                "derived=''\n"
                "result=''\n"
                "mode=build\n"
                "[[ \" ${*} \" == *' archive '* ]] && mode=archive\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case \"$1\" in\n"
                "    -archivePath) archive=\"$2\"; shift 2 ;;\n"
                "    -derivedDataPath) derived=\"$2\"; shift 2 ;;\n"
                "    -resultBundlePath) result=\"$2\"; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "if [[ -n \"$archive\" ]]; then mkdir -p \"$archive\"; fi\n"
                "if [[ -n \"$derived\" ]]; then mkdir -p \"$derived/Build/Products/Debug-iphonesimulator/KasSigner.app\"; fi\n"
                "if [[ -n \"$result\" ]]; then mkdir -p \"$result\"; fi\n",
                encoding="utf-8",
            )
            xcodebuild.chmod(0o755)
            ios_env = os.environ.copy()
            ios_env["PATH"] = str(fake_bin) + os.pathsep + ios_env.get("PATH", "")
            ios_debug = subprocess.run(
                ["bash", str(ios_script), "build"], cwd=root, env=ios_env,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(ios_debug.returncode, 0, ios_debug.stdout + ios_debug.stderr)
            expected_app = root / "target/ios/DerivedData/Build/Products/Debug-iphonesimulator/KasSigner.app"
            self.assertIn("Built artifact:", ios_debug.stdout)
            self.assertIn(str(expected_app), ios_debug.stdout)

            ios_env["KASSIGNER_IOS_DEVELOPMENT_TEAM"] = "TESTTEAM"
            ios_release = subprocess.run(
                ["bash", str(ios_script), "release"], cwd=root, env=ios_env,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(ios_release.returncode, 0, ios_release.stdout + ios_release.stderr)
            expected_archive = root / "target/ios/KasSigner.xcarchive"
            self.assertIn("Built archive:", ios_release.stdout)
            self.assertIn(str(expected_archive), ios_release.stdout)

    def test_public_make_device_commands_have_explicit_profiles_and_monitor_semantics(self) -> None:
        helper = (COMMON / "lib/make_tasks.py").read_text(encoding="utf-8")
        firmware_body = helper.split("def firmware(board: str) -> int:", 1)[1].split("def flash_firmware", 1)[0]
        flash_body = helper.split("def flash_firmware(board: str, port: str) -> int:", 1)[1].split("def workflow_e2e", 1)[0]
        self.assertNotIn("espflash", firmware_body)
        self.assertIn("Build only: no device was flashed", firmware_body)
        self.assertIn('features = "waveshare,workflow-tests,argon2-bench"', helper)
        self.assertIn('features = "m5stack,workflow-tests,argon2-bench"', helper)
        self.assertNotIn('workflow-test-auto', firmware_body)
        self.assertIn('command = ["espflash", "flash", "--monitor"', flash_body)
        self.assertIn("press CTRL+C to exit", flash_body)
        self.assertNotIn('reset_command = ["espflash", "reset"', flash_body)

        hardware = (ROOT / "qa/checks/firmware/run_hardware_tests.py").read_text(encoding="utf-8")
        workflow = (ROOT / "qa/checks/firmware/run_workflow_tests.py").read_text(encoding="utf-8")
        self.assertIn('f"{feature},hardware-tests"', hardware)
        self.assertIn('f"{feature},{profile}"', workflow)
        self.assertIn('"workflow-runtime-auto" if board == "m5stack"', workflow)
        self.assertIn("flash_and_monitor", hardware)
        self.assertIn("flash_and_monitor", workflow)

    def test_public_make_helper_translates_only_facade_parameters(self) -> None:
        helper = COMMON / "lib/make_public.py"
        spec = importlib.util.spec_from_file_location("make_public_contract", helper)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        calls: list[tuple[str, list[str] | None]] = []

        def platform(name: str, args: list[str] | None = None) -> int:
            calls.append((name, args))
            return 0

        self.assertEqual(module.run_all_profile(platform, "full", "250000", "1"), 0)
        self.assertEqual(calls.pop(), ("run-all", ["--profile", "full", "--fuzz-passes", "250000", "--strict-lockfiles"]))
        self.assertEqual(module.run_all_profile(platform, "test", "999", ""), 0)
        self.assertEqual(calls.pop(), ("run-all", ["--profile", "test"]))
        self.assertEqual(module.run_all_profile(platform, "full", "100000", "", "unit.repository-python-qa"), 0)
        self.assertEqual(calls.pop(), ("run-all", ["--profile", "full", "--fuzz-passes", "100000", "--resume-from", "unit.repository-python-qa"]))
        self.assertEqual(module.test_hardware(platform, "m5stack", "/dev/ttyACM0", "300", ""), 0)
        self.assertEqual(
            calls.pop(),
            ("run-all", ["--category", "hardware", "--hardware", "m5stack", "--hardware-timeout", "300", "--hardware-port", "/dev/ttyACM0"]),
        )
        self.assertEqual(module.release_build(platform, False, "release-out", "key.bin", "1"), 0)
        self.assertEqual(
            calls.pop(),
            ("reproducible-build", ["--output-dir", "release-out", "--signing-key", "key.bin", "--refresh-inputs"]),
        )
        self.assertEqual(calls, [])
        self.assertEqual(module.release_build(platform, True, "release-out", "key.bin", "1"), 0)
        self.assertEqual(
            calls.pop(),
            ("reproducible-build", ["-OutputDir", "release-out", "-SigningKey", "key.bin", "-RefreshInputs"]),
        )
        self.assertEqual(calls, [])

    def test_normal_test_profile_is_one_filter_over_the_canonical_catalog(self) -> None:
        profile = ROOT / "qa/config/run_all_test_steps.txt"
        test_ids = [
            line.strip() for line in profile.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(test_ids), len(set(test_ids)))
        linux_list = subprocess.run(
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--list"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout
        catalog_ids = [line.split()[0] for line in linux_list.splitlines()[2:] if line.strip()]
        self.assertTrue(set(test_ids).issubset(catalog_ids))
        for excluded in (
            "preflight.crap-check",
            "preflight.security-assurance",
            "preflight.firmware-source-contracts",
            "unit.repository-python-qa",
            "integration.repository-architecture",
            "integration.kassee-ios-quality",
            "integration.kassee-android-quality",
            "integration.signer-firmware-builds",
            "integration.signer-firmware-lints",
            "emulation.signer-firmware-qemu",
            "hardware.signer-firmware-device",
            "bench.shared-signer-protocol-throughput",
            "fuzz.repository-security-targets",
        ):
            self.assertNotIn(excluded, test_ids)

        expected = [step_id for step_id in catalog_ids if step_id in set(test_ids)]
        linux = subprocess.run(
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--profile", "test", "--dry-run"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout
        windows = subprocess.run(
            [str(Path(__import__("sys").executable)), str(ROOT / "qa/windows/runner/run_all.py"),
             "--profile", "test", "--dry-run"],
            cwd=ROOT, text=True, capture_output=True, check=True,
        ).stdout

        def selected(text: str) -> list[str]:
            return [
                match.group(1)
                for line in text.splitlines()
                if (match := re.match(r"^\[([^]]+)\]", line))
            ]

        self.assertEqual(selected(linux), expected)
        self.assertEqual(selected(windows), expected)

    def test_windows_full_qa_dry_run_is_tool_independent_through_fuzz(self) -> None:
        runner = ROOT / "qa/windows/runner/run_all.py"
        environment = os.environ.copy()
        environment["PATH"] = ""
        result = subprocess.run(
            [
                sys.executable, str(runner), "--profile", "full",
                "--dry-run", "--fuzz-passes", "1",
            ],
            cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("integration.funded-testnet-e2e", result.stdout)
        self.assertIn("mutation.repository-security-fresh", result.stdout)
        self.assertIn("fuzz.repository-security-targets", result.stdout)

        expected = []
        for raw in (ROOT / "qa/config/run_all_steps.tsv").read_text(encoding="utf-8").splitlines():
            if not raw or raw.startswith("#"):
                continue
            scope, _category, _workspace, step_id, _description = raw.split("\t", 4)
            if scope == "qa":
                expected.append(step_id)

        selected = [
            match.group(1)
            for line in result.stdout.splitlines()
            if (match := re.match(r"^\[([^]]+)\]", line))
        ]
        self.assertEqual(selected, expected)
        self.assertIn(
            f"{len(expected)} passed, 0 skipped, {len(expected)} selected test sections completed",
            result.stdout,
        )

    def test_windows_qa_tail_uses_repository_local_mutation_and_fuzz_tools(self) -> None:
        source = (ROOT / "qa/windows/runner/run_all.py").read_text(encoding="utf-8")
        compact = source.replace(" ", "")
        self.assertIn('ROOT / "target/development-tools"', source)
        self.assertIn('env["CARGO_INSTALL_ROOT"] = str(root)', source)
        self.assertIn('"cargo-mutants", toolchain, version', source)
        self.assertIn('"cargo-fuzz", toolchain, version', source)
        self.assertIn('"--root",str(tool_root)', compact)
        self.assertIn('env=mutation_tool_environment()', compact)

    def test_mutation_setup_preserves_local_plugin_priority_and_explicit_install_root(self) -> None:
        support_path = ROOT / "qa/checks/security/mutation_support.py"
        spec = importlib.util.spec_from_file_location("mutation_support_windows_local_tools", support_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as temporary:
            local_root = Path(temporary) / "local-mutants"
            local_bin = local_root / "bin"
            cargo_bin = Path(temporary) / "cargo-home/bin"
            original_path = os.pathsep.join((str(local_bin), str(cargo_bin)))
            environment = {
                "PATH": original_path,
                "CARGO_HOME": str(cargo_bin.parent),
                "CARGO_INSTALL_ROOT": str(local_root),
            }
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                module.shutil, "which", side_effect=lambda name: str(cargo_bin / "rustup") if name == "rustup" else None
            ):
                self.assertEqual(module.ensure_rustup(), 0)
                self.assertEqual(os.environ["PATH"], original_path)

            commands: list[list[str]] = []
            expected = "cargo-mutants 27.1.0"
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(module, "ensure_rustup", return_value=0),
                mock.patch.object(module, "reconcile_root_lock", return_value=0),
                mock.patch.object(module, "captured", side_effect=["cargo-mutants 0.0.0", expected]),
                mock.patch.object(module, "run", side_effect=lambda command, **_kwargs: commands.append(list(command))),
            ):
                self.assertEqual(
                    module.setup({"toolchain": "1.95.0", "cargo_mutants_version": "27.1.0"}),
                    0,
                )
            install = next(command for command in commands if "cargo-mutants" in command)
            self.assertIn("--root", install)
            self.assertEqual(install[install.index("--root") + 1], str(local_root))

    def test_windows_funded_skip_77_is_nonfatal_in_master_catalog(self) -> None:
        runner_path = ROOT / "qa/windows/runner/run_all.py"
        spec = importlib.util.spec_from_file_location("windows_run_all_funded_skip", runner_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        namespace = type("Args", (), {"dry_run": False})()
        with mock.patch.object(module, "run", return_value=77) as call:
            module.run_step("integration.funded-testnet-e2e", namespace)
        self.assertTrue(module.STEP_SKIPPED)
        self.assertEqual(call.call_args.kwargs["allowed"], (0, 77))

    def test_windows_fuzz_bootstrap_is_self_contained_and_local(self) -> None:
        runner_path = ROOT / "qa/windows/runner/run_all.py"
        spec = importlib.util.spec_from_file_location("windows_run_all_fuzz_bootstrap", runner_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cargo-fuzz-local"
            bin_dir = root / "bin"
            bin_dir.mkdir(parents=True)
            environment = {
                "KASSIGNER_STABLE_RUST": "1.95.0",
                "KASSIGNER_BRANCH_RUST": "nightly-2026-07-31",
                "KASSIGNER_CARGO_FUZZ_VERSION": "0.13.2",
                "PATH": "",
            }
            probes = [
                subprocess.CompletedProcess([], 0, "rustc stable", ""),
                subprocess.CompletedProcess([], 0, "rustc nightly", ""),
                subprocess.CompletedProcess([], 1, "", "missing"),
                subprocess.CompletedProcess([], 0, "cargo-fuzz 0.13.2", ""),
            ]
            commands: list[list[str]] = []
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(module, "require"),
                mock.patch.object(module, "configure_fuzz_tool_environment", return_value=(root, bin_dir)),
                mock.patch.object(module, "capture", side_effect=probes),
                mock.patch.object(module, "run", side_effect=lambda command, **_kwargs: commands.append(list(command)) or 0),
            ):
                module.ensure_fuzz_toolchain(False)
            self.assertIn(
                ["rustup", "component", "add", "llvm-tools-preview", "--toolchain", "nightly-2026-07-31"],
                commands,
            )
            install = next(command for command in commands if "cargo-fuzz" in command)
            self.assertIn("--root", install)
            self.assertEqual(install[install.index("--root") + 1], str(root))

    def test_windows_fuzz_registry_failure_is_not_mistaken_for_empty_success(self) -> None:
        runner_path = ROOT / "qa/windows/runner/run_all.py"
        spec = importlib.util.spec_from_file_location("windows_run_all_fuzz_registry", runner_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        namespace = type("Args", (), {"fuzz_target": "", "dry_run": False, "fuzz_passes": 1})()
        failed = subprocess.CompletedProcess([], 1, "ERROR: broken registry", "")
        with mock.patch.object(module, "ensure_fuzz_toolchain"), mock.patch.object(module, "capture", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "fuzz target registry validation failed"):
                module.run_fuzz(namespace)

    def test_windows_and_linux_master_catalogs_have_same_step_ids(self) -> None:
        linux = subprocess.run(
            ["bash", str(ROOT / "qa/linux/run-all.sh"), "--list"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        windows = subprocess.run(
            [str(Path(__import__("sys").executable)), str(ROOT / "qa/windows/runner/run_all.py"), "--list"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        ).stdout

        def ids(text: str) -> list[str]:
            return [line.split()[0] for line in text.splitlines()[2:] if line.strip()]

        self.assertEqual(ids(windows), ids(linux))

    def test_powershell_unscoped_variables_are_delimited_before_colons(self) -> None:
        invalid = re.compile(
            r"\$(?!(?:env|script|global|local|private|variable|function|alias):)"
            r"[A-Za-z_][A-Za-z0-9_]*:"
        )
        failures: list[str] = []
        for path in ROOT.rglob("*.ps1"):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if invalid.search(line):
                    failures.append(f"{path.relative_to(ROOT)}:{line_number}: {line.strip()}")
        self.assertEqual(failures, [], "invalid PowerShell variable/colon interpolation:\n" + "\n".join(failures))

    def test_powershell_sources_parse_when_available(self) -> None:
        powershell = next(
            (path for name in ("pwsh", "powershell.exe", "powershell") if (path := shutil.which(name))),
            None,
        )
        if not powershell:
            self.skipTest("PowerShell parser is not installed on this host")
        sources = sorted(str(path) for path in ROOT.rglob("*.ps1"))
        parser = (
            "$paths=Get-Content -LiteralPath $env:KASSIGNER_PS1_PARSE_LIST -Encoding UTF8; "
            "$failed=$false; foreach($path in $paths){"
            "$tokens=$null; $errors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile([string]$path,[ref]$tokens,[ref]$errors)|Out-Null; "
            "if($errors.Count){$failed=$true; foreach($parseError in @($errors)){"
            "$message=[string]$parseError.Message; [Console]::Error.WriteLine(([string]$path + ': ' + $message))}}}; "
            "if($failed){exit 1}"
        )
        with tempfile.TemporaryDirectory() as temporary:
            parse_list = Path(temporary) / "powershell-sources.txt"
            parse_list.write_text("\n".join(sources) + "\n", encoding="utf-8")
            environment = os.environ.copy()
            environment["KASSIGNER_PS1_PARSE_LIST"] = str(parse_list)
            result = subprocess.run(
                [powershell, "-NoProfile", "-NonInteractive", "-Command", parser],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_installers_are_first_class_and_root_facades_are_thin(self) -> None:
        linux = (LINUX / "install/install.sh").read_text(encoding="utf-8")
        windows = (WINDOWS / "install/install.ps1").read_text(encoding="utf-8")
        root_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
        root_ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("qa/linux/run-all.sh", linux)
        self.assertIn("qa/windows/run-all.ps1", windows)
        self.assertIn("scripts/linux/install/install.sh", root_sh)
        self.assertIn("scripts/windows/install/install.ps1", root_ps1)
        self.assertIn("tools/install/macos/common.sh", root_sh)
        for token in ("make", "python", "git", "node", "npm", "rustup", "cargo", "espup", "espflash", "gradle", "kotlinc"):
            self.assertIn(token, linux.lower())
            self.assertIn(token, windows.lower())
        self.assertIn("android-${KASSIGNER_ANDROID_API}", linux)
        self.assertIn("KASSIGNER_ANDROID_API", windows)


    def test_installers_verify_pinned_native_readiness(self) -> None:
        linux = (LINUX / "install/install.sh").read_text(encoding="utf-8")
        windows = (WINDOWS / "install/install.ps1").read_text(encoding="utf-8")
        environment = (ROOT / "qa/linux/runner/environment.sh").read_text(encoding="utf-8")
        for token in (
            "KASSIGNER_CARGO_MUTANTS_VERSION", "KASSIGNER_CARGO_FUZZ_VERSION",
            "KASSIGNER_CARGO_LLVM_COV_VERSION", "KASSIGNER_CARGO_CRAP_VERSION",
            "KASSIGNER_ANDROID_BUILD_TOOLS",
        ):
            self.assertIn(token, linux)
            self.assertIn(token, windows)
        self.assertIn("KASSIGNER_ANDROID_CMDLINE_TOOLS_LINUX_SHA256", linux)
        self.assertIn("KASSIGNER_ANDROID_CMDLINE_TOOLS_WINDOWS_SHA256", windows)
        self.assertIn('prepend_path_once "${HOME}/.local/bin"', environment)
        self.assertIn("KASSIGNER_ANDROID_JDK", environment)
        self.assertIn("ANDROID_SDK_ROOT", environment)

    @unittest.skipUnless(os.name == "posix", "Linux bootstrap environment execution is POSIX-specific")
    def test_linux_runner_discovers_managed_bootstrap_without_reopening_shell(self) -> None:
        fixture = ROOT / "target/qa/bootstrap-environment-test"
        shutil.rmtree(fixture, ignore_errors=True)
        jdk_bin = fixture / ".local/share/kassigner/jdk-25/bin"
        jdk_bin.mkdir(parents=True)
        java = jdk_bin / "java"
        java.write_text("#!/bin/sh\nexit 0\n")
        java.chmod(0o755)
        (fixture / "Android/Sdk/platform-tools").mkdir(parents=True)
        (fixture / "Android/Sdk/cmdline-tools/latest/bin").mkdir(parents=True)
        command = (
            f'export HOME="{fixture}"; export PATH="/usr/bin:/bin"; '
            f'ROOT_DIR="{ROOT}"; source "{ROOT / "qa/linux/runner/environment.sh"}"; '
            'initialize_test_environment; '
            'printf "%s\\n%s\\n%s\\n" "$JAVA_HOME" "$ANDROID_SDK_ROOT" "$PATH"'
        )
        try:
            result = subprocess.run(["bash", "-c", command], cwd=ROOT, text=True, capture_output=True, check=True)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], str(fixture / ".local/share/kassigner/jdk-25"))
            self.assertEqual(lines[1], str(fixture / "Android/Sdk"))
            self.assertIn(str(fixture / "Android/Sdk/platform-tools"), lines[2])
            self.assertIn(str(fixture / ".local/share/kassigner/jdk-25/bin"), lines[2])
        finally:
            shutil.rmtree(fixture, ignore_errors=True)

    def test_windows_installer_requires_native_msvc_asan(self) -> None:
        windows = (WINDOWS / "install/install.ps1").read_text(encoding="utf-8")
        self.assertIn("Microsoft.VisualStudio.Component.VC.Tools.x86.x64", windows)
        self.assertIn("Microsoft.VisualStudio.Component.VC.ASAN", windows)
        self.assertNotIn("wsl", windows.lower())

    def test_windows_fuzz_uses_native_msvc_mode(self) -> None:
        self.assertIn("--no-include-main-msvc", (ROOT / "qa/windows/run-security-fuzz.ps1").read_text(encoding="utf-8"))
        self.assertIn("--no-include-main-msvc", (ROOT / "qa/windows/runner/run_all.py").read_text(encoding="utf-8"))

    def test_macos_installer_is_outside_scripts_platform_trees(self) -> None:
        self.assertTrue((ROOT / "tools/install/macos/environment.sh").is_file())

    def test_macos_installer_keeps_original_native_flow_and_flat_archive_support(self) -> None:
        root_install = (ROOT / "install.sh").read_text(encoding="utf-8")
        firmware = (ROOT / "tools/install/macos/firmware.sh").read_text(encoding="utf-8")
        common = (ROOT / "tools/install/macos/common.sh").read_text(encoding="utf-8")
        self.assertIn('Darwin)', root_install)
        self.assertIn('set +e', root_install)
        self.assertIn('set +u', root_install)
        self.assertIn('export INSTALL_ROOT="$ROOT_DIR"', root_install)
        self.assertIn('$INSTALL_ROOT/apps/signer-firmware', firmware)
        self.assertIn('~/KasSigner_build/apps/signer-firmware/Cargo.toml', firmware)
        self.assertIn('${2:-}', common)

    def test_ios_xcode_runtime_sync_is_not_linux_bound(self) -> None:
        project = (ROOT / "apps/kassee-ios/KasSigner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        helper = (ROOT / "tools/build/ios/sync_runtime.py").read_text(encoding="utf-8")
        self.assertIn('tools/build/web/build_kassee_runtime.py', project)
        self.assertIn('tools/build/ios/sync_runtime.py', project)
        self.assertNotIn('scripts/linux/build/ios-runtime-sync.sh', project)
        self.assertIn('shutil.copytree', helper)
        self.assertIn('kassee_web_bg.wasm', helper)


if __name__ == "__main__":
    unittest.main()
