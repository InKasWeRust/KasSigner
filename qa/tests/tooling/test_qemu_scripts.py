#!/usr/bin/env python3
"""Regression coverage for the self-provisioning QEMU workflow."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]

import sys
sys.path.insert(0, str(ROOT / "qa/checks"))
from toolchains import load_toolchains  # noqa: E402

PINS = load_toolchains()


class QemuScriptTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text()

    def test_setup_installs_all_required_layers(self) -> None:
        setup = self.read("scripts/linux/qemu/setup.sh")
        for function in (
            "install_qemu_host_packages",
            "install_rustup_if_missing",
            "install_esp_rust_toolchain",
            "install_espflash",
            "install_espressif_qemu",
        ):
            self.assertIn(function, setup)

    def test_espressif_setup_installs_xtensa_qemu(self) -> None:
        source = self.read("scripts/linux/lib/qemu-espressif.sh")
        self.assertIn('python3 "${idf_tools}" install qemu-xtensa', source)
        self.assertIn("qemu-system-xtensa", source)
        self.assertIn("KASSIGNER_ESP_IDF_VERSION", self.read("scripts/linux/lib/qemu-common.sh"))

    def test_espressif_setup_does_not_activate_full_idf(self) -> None:
        source = self.read("scripts/linux/lib/qemu-espressif.sh")
        self.assertNotIn("install-python-env", source)
        self.assertNotIn("export.sh", source)
        self.assertIn("find_installed_xtensa_qemu", source)
        self.assertIn("QEMU_SYSTEM_XTENSA", source)
        self.assertLess(
            source.index('if [[ -d "${search_root}" ]]'),
            source.index("command -v qemu-system-xtensa"),
        )

    @unittest.skipUnless(os.name == "posix", "Espressif QEMU setup execution is POSIX-specific")
    def test_espressif_setup_resolves_qemu_without_idf_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            idf_path = root / "esp-idf"
            idf_tools = idf_path / "tools/idf_tools.py"
            tools_root = root / "idf-tools"
            idf_tools.parent.mkdir(parents=True)
            idf_tools.write_text(
                "from pathlib import Path\n"
                "import os\n"
                "import sys\n"
                "assert sys.argv[1:] == ['install', 'qemu-xtensa']\n"
                "binary = (Path(os.environ['IDF_TOOLS_PATH']) / "
                "'tools/qemu-xtensa/v1/qemu/bin/qemu-system-xtensa')\n"
                "binary.parent.mkdir(parents=True, exist_ok=True)\n"
                "binary.write_text('#!/bin/sh\\necho qemu-stub\\n')\n"
                "binary.chmod(0o755)\n"
            )

            command = (
                f'source "{ROOT}/scripts/linux/lib/qemu-common.sh"\n'
                f'source "{ROOT}/scripts/linux/lib/qemu-espressif.sh"\n'
                "install_espressif_qemu\n"
                "printf 'SELECTED=%s\\n' \"$QEMU_SYSTEM_XTENSA\"\n"
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "PATH": "/usr/bin:/bin",
                    "KASSIGNER_IDF_PATH": str(idf_path),
                    "IDF_TOOLS_PATH": str(tools_root),
                }
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            expected = (
                tools_root
                / "tools/qemu-xtensa/v1/qemu/bin/qemu-system-xtensa"
            )
            self.assertIn(f"SELECTED={expected}", completed.stdout)
            self.assertNotIn("Activating ESP-IDF", completed.stdout)

    def test_build_and_run_preserve_setup_environment(self) -> None:
        build = self.read("scripts/linux/qemu/build.sh")
        self.assertIn('source "${SCRIPT_DIR}/setup.sh"', build)
        self.assertIn("tools/firmware/qemu/build.sh", build)

        run = self.read("scripts/linux/qemu/run.sh")
        self.assertIn('source "${SCRIPT_DIR}/setup.sh"', run)
        self.assertIn("tools/firmware/qemu/build.sh", run)
        self.assertIn("qa/checks/firmware/qemu/run.py", run)
        self.assertFalse((ROOT / "tools/firmware/qemu/run.sh").exists())

    def test_make_routes_qemu_through_self_provisioning_scripts(self) -> None:
        makefile = self.read("Makefile")
        self.assertIn("firmware-qemu-setup:\n\t$(MAKE_TASK) entrypoint qemu-setup", makefile)
        self.assertIn("firmware-qemu:\n\t$(MAKE_TASK) entrypoint qemu-build", makefile)
        self.assertIn("firmware-qemu-test:\n\t$(MAKE_TASK) entrypoint qemu-test", makefile)
        self.assertNotIn("firmware-qemu-run:", makefile)

    def test_qemu_build_enables_guest_tests(self) -> None:
        build = self.read("tools/firmware/qemu/build.sh")
        self.assertIn("--features qemu-tests", build)
        manifest = self.read("apps/signer-firmware/Cargo.toml")
        self.assertIn('qemu-tests = ["qemu", "verbose-boot"]', manifest)

    def test_qemu_test_image_initializes_internal_heap(self) -> None:
        qemu_entry = self.read("apps/signer-firmware/src/qemu/mod.rs")
        self.assertIn('\n    allocator::initialize();', qemu_entry)

        allocator = self.read("apps/signer-firmware/src/qemu/allocator.rs")
        self.assertIn("esp_alloc::HEAP.add_region(HeapRegion::new", allocator)
        self.assertIn("const QEMU_TEST_HEAP_BYTES: usize = 128 * 1024", allocator)
        self.assertIn("StaticCell<[u8; QEMU_TEST_HEAP_BYTES]>", allocator)
        self.assertIn("QEMU_TEST_HEAP.init_with", allocator)
        self.assertIn("pub(crate) fn probe() -> bool", allocator)

        soc = self.read("apps/signer-firmware/src/qemu/validation/soc.rs")
        self.assertIn("internal heap allocation", soc)
        self.assertIn("crate::qemu::allocator::probe()", soc)

    def test_qemu_qr_facade_exports_only_used_surface(self) -> None:
        encoder = self.read("apps/signer-firmware/src/qr/encoder/mod.rs")
        self.assertIn("pub use modes::byte_mode::encode;", encoder)
        self.assertGreaterEqual(
            encoder.count('#[cfg(not(feature = "qemu"))]'),
            2,
        )

    def test_master_qa_catalog_runs_qemu_emulation(self) -> None:
        catalog = self.read("qa/linux/runner/catalog.sh")
        self.assertIn("emulation.signer-firmware-qemu", catalog)
        self.assertIn("scripts/linux/qemu/test.sh", catalog)
        runner = self.read("qa/linux/run-all.sh")
        self.assertIn("--skip-qemu", runner)
        self.assertIn("emulation|hardware", runner)

    def test_admin_prompt_explains_reason_before_sudo(self) -> None:
        admin = self.read("scripts/linux/lib/admin.sh")
        self.assertIn("KasSigner needs administrator access", admin)
        self.assertIn("Reason: %s", admin)
        self.assertIn("The next prompt is from sudo", admin)
        self.assertNotIn("notify-send", admin)
        self.assertNotIn("kdialog", admin)
        self.assertNotIn("\\033]9;", admin)
        self.assertLess(admin.index("explain_admin_access"), admin.index("sudo -v"))

        packages = self.read("scripts/linux/lib/qemu-packages.sh")
        self.assertIn('run_as_root "${reason}" apt-get update', packages)
        self.assertIn("Install missing %s packages required", packages)

    def test_sudo_is_centralized_behind_terminal_helper(self) -> None:
        offenders = []
        for path in (ROOT / "scripts").rglob("*.sh"):
            if path == ROOT / "scripts/linux/lib/admin.sh":
                continue
            if "sudo " in path.read_text():
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_existing_esp_toolchain_directory_is_accepted(self) -> None:
        rust = self.read("scripts/linux/lib/qemu-rust.sh")
        self.assertIn("toolchains/esp", rust)
        self.assertIn("rustup run esp rustc --version", rust)
        self.assertIn("${toolchain_dir}/bin/rustc", rust)
        self.assertNotIn("rustup toolchain list | grep", rust)

    def test_debian_t64_replacements_are_recognized(self) -> None:
        packages = self.read("scripts/linux/lib/qemu-packages.sh")
        self.assertIn("${package}t64", packages)
        self.assertNotIn("libnotify-bin", packages)

    def test_existing_esp_directory_passes_runtime_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            bin_dir = home / "bin"
            toolchain_bin = home / ".rustup/toolchains/esp/bin"
            bin_dir.mkdir()
            toolchain_bin.mkdir(parents=True)

            (bin_dir / "rustup").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = run ]; then exit 1; fi\n"
                "exit 0\n"
            )
            (bin_dir / "cargo").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = install ]; then exit 91; fi\n"
                f"echo 'cargo {PINS['KASSIGNER_STABLE_RUST']}'\n"
            )
            (toolchain_bin / "rustc").write_text(
                f"#!/bin/sh\necho 'rustc {PINS['KASSIGNER_ESP_RUST']} (esp)'\n"
            )
            for executable in (
                bin_dir / "rustup",
                bin_dir / "cargo",
                toolchain_bin / "rustc",
            ):
                executable.chmod(0o755)

            command = (
                f'source "{ROOT}/scripts/linux/lib/qemu-common.sh"\n'
                f'source "{ROOT}/scripts/linux/lib/qemu-rust.sh"\n'
                "install_esp_rust_toolchain\n"
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                    "RUSTUP_HOME": str(home / ".rustup"),
                    "CARGO_HOME": str(home / ".cargo"),
                }
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stdout + completed.stderr,
            )
            self.assertIn("ESP Rust toolchain ready", completed.stdout)

    def test_admin_explanation_precedes_password_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bin_dir = Path(temporary) / "bin"
            bin_dir.mkdir()
            sudo = bin_dir / "sudo"
            sudo.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = -n ]; then exit 1; fi\n"
                "if [ \"$1\" = -v ]; then echo SUDO_VALIDATE >&2; exit 0; fi\n"
                "exit 0\n"
            )
            sudo.chmod(0o755)

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                    "DISPLAY": "",
                    "WAYLAND_DISPLAY": "",
                    "DBUS_SESSION_BUS_ADDRESS": "",
                }
            )
            command = (
                f'source "{ROOT}/scripts/linux/lib/admin.sh"; '
                'request_admin_access "Install QEMU host libraries."'
            )
            completed = subprocess.run(
                ["bash", "-c", command],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertLess(
                completed.stderr.index("Reason: Install QEMU host libraries."),
                completed.stderr.index("SUDO_VALIDATE"),
            )


if __name__ == "__main__":
    unittest.main()
