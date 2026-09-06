#!/usr/bin/env python3
"""Regression tests for the double-click master test launcher."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

if os.name == "posix":
    import fcntl
else:
    fcntl = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))
from toolchains import load_toolchains  # noqa: E402

PINS = load_toolchains()
QA_DIR = ROOT / "qa/linux"


@unittest.skipUnless(os.name == "posix", "Linux master-launcher tests are POSIX-specific")
class MasterTestLauncherTests(unittest.TestCase):
    def test_desktop_launcher_targets_sibling_runner(self) -> None:
        launcher = QA_DIR / "run-all.desktop"
        source = launcher.read_text()

        self.assertTrue(os.access(launcher, os.X_OK))
        self.assertIn("Type=Application", source)
        self.assertIn("Terminal=true", source)
        self.assertIn('qa_dir=$(dirname "$desktop_file")', source)
        self.assertIn('exec "$qa_dir/run-all.sh" --pause', source)
        self.assertIn("bash %k", source)

    def test_runner_supports_terminal_pause(self) -> None:
        runner = QA_DIR / "run-all.sh"
        source = runner.read_text()

        helper = QA_DIR / "lib/terminal_pause.sh"
        helper_source = helper.read_text()

        self.assertTrue(os.access(runner, os.X_OK))
        self.assertIn("--pause", source)
        self.assertIn('source "${SCRIPT_DIR}/lib/terminal_pause.sh"', source)
        self.assertIn("kassigner_qa_install_exit_handler", source)
        self.assertIn("trap kassigner_qa_exit_handler EXIT", helper_source)
        self.assertIn("Press Enter to close this terminal", helper_source)
        self.assertIn("KASSIGNER_QA_NO_PAUSE", helper_source)


    def test_cargo_preflight_resolves_full_dependency_graph(self) -> None:
        commands = (QA_DIR / "runner/commands.sh").read_text()
        self.assertIn("cargo metadata", commands)
        self.assertIn("--locked", commands)
        self.assertNotIn("--no-deps", commands)


    def test_runner_loads_cargo_from_user_environment(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(
                f'export PATH="{bin_dir}:$PATH"\n'
            )

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(runner),
                    "--only",
                    "unit.shared-signer",
                    "--skip-fuzz",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: unit.shared-signer", result.stdout)
            self.assertIn("test --manifest-path Cargo.toml", log.read_text())


    def test_nested_run_all_reuses_parent_qa_workflow_lock_without_deadlock(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text("#!/usr/bin/env bash\nexit 0\n")
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "PATH": "/usr/bin:/bin",
                    "KASSIGNER_QA_RUN_ALL_LOCK_ROOT": str(ROOT),
                }
            )

            lock_handle = None
            if os.environ.get("KASSIGNER_QA_RUN_ALL_LOCK_ROOT") != str(ROOT):
                lock_path = ROOT / "target/qa/state/release-workflow.lock"
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                lock_handle = lock_path.open("a+")
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                result = subprocess.run(
                    ["bash", str(runner), "--only", "preflight.cargo-resolution"],
                    cwd=ROOT,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
            finally:
                if lock_handle is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                    lock_handle.close()

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("waiting for it to finish", result.stdout)
            self.assertIn("PASS: preflight.cargo-resolution", result.stdout)

    def test_cargo_preflight_repairs_stale_lockfiles_and_stops_on_failure(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            marker = home / "refreshed"
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                "if [[ \"$*\" == *metadata* && \"$*\" == *--locked* && ! -e \"$FAKE_CARGO_MARKER\" ]]; then exit 101; fi\n"
                "if [[ \"$*\" == *metadata* && \"$*\" != *--locked* ]]; then touch \"$FAKE_CARGO_MARKER\"; fi\n"
                "exit 0\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "FAKE_CARGO_MARKER": str(marker),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                ["bash", str(runner), "--only", "preflight.cargo-resolution"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Locked graph is stale", result.stdout)
            self.assertIn("Refreshed and verified", result.stdout)
            self.assertTrue(marker.exists())

    def test_tools_unit_revalidates_tools_lockfile_when_resumed_directly(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            marker = home / "refreshed"
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                "if [[ \"$*\" == *metadata* && \"$*\" == *--locked* && ! -e \"$FAKE_CARGO_MARKER\" ]]; then exit 101; fi\n"
                "if [[ \"$*\" == *metadata* && \"$*\" != *--locked* ]]; then touch \"$FAKE_CARGO_MARKER\"; fi\n"
                "exit 0\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')
            environment = os.environ.copy()
            environment.update({
                "HOME": str(home), "CARGO_HOME": str(cargo_home),
                "FAKE_CARGO_LOG": str(log), "FAKE_CARGO_MARKER": str(marker),
                "PATH": "/usr/bin:/bin",
            })
            result = subprocess.run(
                ["bash", str(runner), "--only", "unit.tools", "--skip-fuzz"],
                cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = log.read_text().splitlines()
            test_index = next(index for index, call in enumerate(calls) if call.startswith("test "))
            self.assertTrue(any("metadata" in call and "--locked" in call for call in calls[:test_index]))
            self.assertTrue(marker.exists())

    def test_benchmark_revalidates_qa_lockfile_when_resumed_directly(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            marker = home / "refreshed"
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                "if [[ \"$*\" == *metadata* && \"$*\" == *--locked* && ! -e \"$FAKE_CARGO_MARKER\" ]]; then exit 101; fi\n"
                "if [[ \"$*\" == *metadata* && \"$*\" != *--locked* ]]; then touch \"$FAKE_CARGO_MARKER\"; fi\n"
                "exit 0\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "FAKE_CARGO_MARKER": str(marker),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                ["bash", str(runner), "--only", "bench.shared-signer-protocol-throughput"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Locked graph is stale", result.stdout)
            calls = log.read_text().splitlines()
            bench_index = next(index for index, call in enumerate(calls) if call.startswith("bench "))
            self.assertTrue(any("metadata" in call and "--locked" in call for call in calls[:bench_index]))
            self.assertTrue(marker.exists())

    def test_strict_lockfile_preflight_forces_pinned_host_toolchain(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s|%s|%s\n' \"$PWD\" \"${RUSTUP_TOOLCHAIN:-}\" \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                "if [[ \"$PWD\" == */apps/signer-firmware && \"${RUSTUP_TOOLCHAIN:-}\" != \"$EXPECTED_STABLE_RUST\" ]]; then\n"
                "  echo 'custom toolchain esp is not installed' >&2\n"
                "  exit 101\n"
                "fi\n"
                "exit 0\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "EXPECTED_STABLE_RUST": PINS["KASSIGNER_STABLE_RUST"],
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(runner),
                    "--only",
                    "preflight.cargo-resolution",
                    "--strict-lockfiles",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: preflight.cargo-resolution", result.stdout)
            calls = log.read_text().splitlines()
            self.assertEqual(len(calls), 5)
            for call in calls:
                _, toolchain, args = call.split("|", 2)
                self.assertEqual(toolchain, PINS["KASSIGNER_STABLE_RUST"])
                self.assertIn("metadata", args)
                self.assertIn("--locked", args)

    def test_strict_lockfile_preflight_propagates_first_failure(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                "exit 101\n"
            )
            fake_cargo.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(runner),
                    "--only",
                    "preflight.cargo-resolution",
                    "--strict-lockfiles",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 101)
            self.assertIn("strict-lockfiles", result.stderr)
            self.assertNotIn("PASS: preflight.cargo-resolution", result.stdout)
            self.assertEqual(len(log.read_text().splitlines()), 1)


    def test_fuzz_runner_uses_central_nightly_policy(self) -> None:
        self.assertFalse((ROOT / "qa/fuzz/rust-toolchain.toml").exists())
        self.assertFalse((ROOT / "rust-toolchain.toml").exists())

        commands = (QA_DIR / "runner/commands.sh").read_text()
        self.assertIn('run_in_directory "${ROOT_DIR}/qa/fuzz"', commands)
        self.assertIn('rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz run "$target"', commands)
        self.assertNotIn(PINS["KASSIGNER_BRANCH_RUST"], commands)

    def test_fuzz_stage_invokes_nightly_cargo(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            log = home / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_CARGO_LOG\"\n"
                f"if [[ \"$1 $2\" == \"fuzz --version\" ]]; then echo 'cargo-fuzz {PINS['KASSIGNER_CARGO_FUZZ_VERSION']}'; fi\n"
            )
            fake_cargo.chmod(0o755)
            fake_rustup = bin_dir / "rustup"
            fake_rustup.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1\" == \"run\" && \"$3\" == \"cargo\" ]]; then shift 3; exec \"$CARGO_HOME/bin/cargo\" \"$@\"; fi\n"
                "exit 0\n"
            )
            fake_rustup.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_CARGO_LOG": str(log),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(runner),
                    "--only",
                    "fuzz.repository-security-targets",
                    "--fuzz-passes",
                    "7",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "fuzz run unwrap_qr_payload -- -runs=7",
                log.read_text(),
            )

    def test_fuzz_stage_installs_missing_nightly(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            cargo_home = home / ".cargo"
            bin_dir = cargo_home / "bin"
            bin_dir.mkdir(parents=True)
            marker = home / "nightly-installed"
            rustup_log = home / "rustup.log"

            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env bash\n"
                f"if [[ \"$1 $2\" == \"fuzz --version\" ]]; then echo 'cargo-fuzz {PINS['KASSIGNER_CARGO_FUZZ_VERSION']}'; fi\n"
                "exit 0\n"
            )
            fake_cargo.chmod(0o755)
            fake_rustup = bin_dir / "rustup"
            fake_rustup.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_RUSTUP_LOG\"\n"
                f"if [[ \"$1 $2 $3\" == \"run {PINS['KASSIGNER_BRANCH_RUST']} rustc\" && ! -e \"$FAKE_RUSTUP_MARKER\" ]]; then exit 1; fi\n"
                f"if [[ \"$1 $2 $3\" == \"toolchain install {PINS['KASSIGNER_BRANCH_RUST']}\" ]]; then touch \"$FAKE_RUSTUP_MARKER\"; fi\n"
                "if [[ \"$1\" == \"run\" && \"$3\" == \"cargo\" ]]; then shift 3; exec \"$CARGO_HOME/bin/cargo\" \"$@\"; fi\n"
                "exit 0\n"
            )
            fake_rustup.chmod(0o755)
            (cargo_home / "env").write_text(f'export PATH="{bin_dir}:$PATH"\n')

            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CARGO_HOME": str(cargo_home),
                    "FAKE_RUSTUP_LOG": str(rustup_log),
                    "FAKE_RUSTUP_MARKER": str(marker),
                    "PATH": "/usr/bin:/bin",
                }
            )
            result = subprocess.run(
                [
                    "bash",
                    str(runner),
                    "--only",
                    "fuzz.repository-security-targets",
                    "--fuzz-passes",
                    "1",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(marker.exists())
            self.assertIn(
                f"toolchain install {PINS['KASSIGNER_BRANCH_RUST']} --profile minimal",
                rustup_log.read_text(),
            )
            self.assertIn("Pinned nightly is missing", result.stdout)


    def test_hardware_stage_is_opt_in(self) -> None:
        runner = QA_DIR / "run-all.sh"
        default_run = subprocess.run(
            ["bash", str(runner), "--dry-run", "--skip-fuzz"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(default_run.returncode, 0, default_run.stderr)
        self.assertNotIn("hardware.signer-firmware-device", default_run.stdout)
        self.assertNotIn("run_hardware_tests.py", default_run.stdout)

        hardware_run = subprocess.run(
            [
                "bash",
                str(runner),
                "--dry-run",
                "--skip-fuzz",
                "--hardware",
                "waveshare",
                "--hardware-port",
                "/dev/ttyACM0",
                "--hardware-timeout",
                "90",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(hardware_run.returncode, 0, hardware_run.stderr)
        self.assertIn("hardware.signer-firmware-device", hardware_run.stdout)
        self.assertIn("run_hardware_tests.py", hardware_run.stdout)
        self.assertIn("--board waveshare", hardware_run.stdout)
        self.assertIn("--port /dev/ttyACM0", hardware_run.stdout)
        self.assertIn("--timeout 90", hardware_run.stdout)

    def test_hardware_flag_rejects_unknown_board(self) -> None:
        runner = QA_DIR / "run-all.sh"
        result = subprocess.run(
            ["bash", str(runner), "--hardware", "unknown"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid hardware board", result.stderr)


    def test_multi_command_architecture_step_propagates_first_failure(self) -> None:
        runner = QA_DIR / "run-all.sh"
        with tempfile.TemporaryDirectory() as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            log = Path(temporary) / "python.log"
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\n' \"$*\" >> \"$FAKE_PYTHON_LOG\"\n"
                "if [[ \"$*\" == *qa/checks/check_architecture.py* ]]; then exit 37; fi\n"
                "exit 0\n"
            )
            fake_python.chmod(0o755)

            environment = os.environ.copy()
            environment.update({
                "FAKE_PYTHON_LOG": str(log),
                "PATH": f"{fake_bin}:/usr/bin:/bin",
            })
            result = subprocess.run(
                ["bash", str(runner), "--only", "integration.repository-architecture"],
                cwd=ROOT, env=environment, text=True, capture_output=True, check=False,
            )

            self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
            self.assertIn("FAIL: integration.repository-architecture (exit 37)", result.stderr)
            self.assertNotIn("PASS: integration.repository-architecture", result.stdout)
            calls = log.read_text().splitlines()
            self.assertEqual(calls, ["qa/checks/check_architecture.py"])

    def test_multi_command_catalog_and_helpers_explicitly_propagate_failures(self) -> None:
        catalog = (QA_DIR / "runner/catalog.sh").read_text()
        commands = (QA_DIR / "runner/commands.sh").read_text()
        required_catalog = (
            "build_web_index.py --check || return $?",
            "build_app_css.py --check || return $?",
            "build_constellation_assets.py --check || return $?",
            "check_web_dom_contract.py || return $?",
            "check_web_runtime.mjs || return $?",
            "check_web_covenant_interactions.mjs || return $?",
            "check_web_critical_paths.mjs || return $?",
            "qa/checks/check_architecture.py || return $?",
        )
        for marker in required_catalog:
            self.assertIn(marker, catalog)
        coverage = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        self.assertIn("run_web_recovery_coverage.py", coverage)
        self.assertIn("run_web_runtime_coverage.py", coverage)
        self.assertIn("set -Eeuo pipefail", coverage)
        self.assertIn("generate_browser_recovery_coverage", coverage)
        self.assertIn("generate_web_runtime_coverage", coverage)
        self.assertIn("features waveshare,verbose-boot || return $?", commands)
        self.assertIn("features m5stack,verbose-boot || return $?", commands)
        self.assertIn('"-runs=${FUZZ_PASSES}"', commands)
        self.assertIn('statuses.tsv', commands)
        self.assertIn('qa/checks/security/fuzz_results.py', commands)
        self.assertIn('--runs "$FUZZ_PASSES"', commands)
        self.assertIn('target_status=${PIPESTATUS[0]}', commands)


if __name__ == "__main__":
    unittest.main()
