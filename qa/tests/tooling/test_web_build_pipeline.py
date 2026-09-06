#!/usr/bin/env python3
"""Ensure every KasSee runtime consumer shares one pinned cross-platform builder."""

from pathlib import Path
import importlib.util
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
BUILDER = ROOT / "tools/build/web/build_kassee_runtime.py"
LINUX_FACADE = ROOT / "apps/kassee-web/build.sh"
WINDOWS_FACADE = ROOT / "apps/kassee-web/build.ps1"


class WebBuildPipelineTests(unittest.TestCase):
    def test_web_asset_generators_are_utf8_explicit_under_ascii_locale(self) -> None:
        env = os.environ.copy()
        env.update({"PYTHONUTF8": "0", "LC_ALL": "C", "LANG": "C"})
        for builder in (
            "tools/build/web/build_web_index.py",
            "tools/build/web/build_app_css.py",
            "tools/build/web/build_constellation_assets.py",
        ):
            result = subprocess.run(
                [sys.executable, str(ROOT / builder), "--check"],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"{builder}:\n{result.stdout}")

    def test_web_dom_contract_is_utf8_explicit_under_ascii_locale(self) -> None:
        env = os.environ.copy()
        env.update({
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "LC_ALL": "C",
            "LANG": "C",
        })
        result = subprocess.run(
            [sys.executable, str(ROOT / "qa/checks/web/check_web_dom_contract.py")],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)


    def test_safe_html_checker_normalizes_windows_paths_and_utf8(self) -> None:
        checker = ROOT / "qa/checks/web/check_safe_html.py"
        source = checker.read_text(encoding="utf-8")
        self.assertIn("replace('\\\\', '/')", source)
        self.assertIn("read_text(encoding='utf-8', errors='replace')", source)

        # Reproduce the Windows path form that previously bypassed the QR allowlist.
        windows_rel = r"features\transactions\send\review.js"
        normalized = windows_rel.replace("\\", "/")
        self.assertEqual(normalized, "features/transactions/send/review.js")

        env = os.environ.copy()
        env.update({
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "LC_ALL": "C",
            "LANG": "C",
        })
        result = subprocess.run(
            [sys.executable, str(checker)],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_all_asset_generators_run_before_wasm_build(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        wasm = source.index('"build",')
        for builder in (
            "tools/build/web/build_web_index.py",
            "tools/build/web/build_app_css.py",
            "tools/build/web/build_constellation_assets.py",
        ):
            self.assertLess(source.index(builder), wasm)

    def test_full_qa_runs_crap_before_the_normal_kassee_build(self) -> None:
        catalog = (ROOT / "qa/config/run_all_steps.tsv").read_text(encoding="utf-8")
        dispatch = (ROOT / "qa/linux/runner/catalog.sh").read_text(encoding="utf-8")
        ids = [line.split("\t")[3] for line in catalog.splitlines() if line and not line.startswith("#")]
        self.assertEqual(ids[0], "preflight.crap-check")
        self.assertLess(ids.index("preflight.crap-check"), ids.index("preflight.kassee-build"))
        self.assertIn('run_in_directory "$ROOT_DIR" bash scripts/linux/build/kassee-web-build.sh', dispatch)
        self.assertNotIn('run_in_directory "$ROOT_DIR" make kassee', dispatch)
        self.assertIn('require_command rustup', dispatch)

    def test_browser_stage_persists_recovery_coverage(self) -> None:
        coverage = (ROOT / "scripts/linux/quality/crap.sh").read_text(encoding="utf-8")
        self.assertIn("run_web_recovery_coverage.py", coverage)
        runner = (ROOT / "qa/checks/web/run_web_recovery_coverage.py").read_text(encoding="utf-8")
        self.assertIn("NODE_V8_COVERAGE", runner)
        self.assertIn("thresholds_enforced_by", runner)
        self.assertIn("expected - measured", runner)

    def test_wasm_package_is_rebuilt_from_clean_generated_output(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        clean = source.index('shutil.rmtree(authored / "pkg"')
        bindgen = source.index('"--target", "web"')
        mirror = source.index("sync_local_web_package(site)")
        self.assertLess(clean, bindgen)
        self.assertLess(bindgen, mirror)
        self.assertIn('ROOT / "target/kassee-web/site"', source)
        self.assertIn('local = APP / "web" / "pkg"', source)
        self.assertIn('shutil.copytree(source, local)', source)

    def test_local_web_runtime_sync_copies_generated_bindings(self) -> None:
        spec = importlib.util.spec_from_file_location("build_kassee_runtime_test", BUILDER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module.APP = root / "apps" / "kassee-web"
            site = root / "target" / "kassee-web" / "site"
            (site / "pkg").mkdir(parents=True)
            (site / "pkg" / "kassee_web.js").write_text("export default function init() {}\n")
            (site / "pkg" / "kassee_web_bg.wasm").write_bytes(b"wasm")
            local = module.APP / "web" / "pkg"
            local.mkdir(parents=True)
            (local / "stale.js").write_text("stale\n")

            module.sync_local_web_package(site)

            self.assertFalse((local / "stale.js").exists())
            self.assertEqual((local / "kassee_web.js").read_text(encoding="utf-8"), "export default function init() {}\n")
            self.assertEqual((local / "kassee_web_bg.wasm").read_bytes(), b"wasm")

    def test_build_facades_delegate_without_duplicating_runtime_logic(self) -> None:
        for facade in (LINUX_FACADE, WINDOWS_FACADE):
            source = facade.read_text(encoding="utf-8")
            self.assertIn("build_kassee_runtime.py", source)
            self.assertNotIn("cargo build", source)
            self.assertNotIn("wasm-bindgen-cli", source)

    def test_builder_fails_closed_on_unknown_mode(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn('choices=("release", "dev")', source)
        self.assertIn("return 2", source)

    def test_web_build_uses_direct_wasm_bindgen_not_wasm_pack(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        manifest = (ROOT / "apps/kassee-web/Cargo.toml").read_text(encoding="utf-8")
        self.assertNotIn("wasm-pack", source)
        self.assertNotIn("package.metadata.wasm-pack", manifest)
        self.assertIn('"--target", "web"', source)
        self.assertIn('"--out-name", "kassee_web"', source)

    def test_web_build_resolves_lock_for_wasm_target_with_msrv_fallback(self) -> None:
        source = (ROOT / "tools/build/web/build_kassee_runtime.py").read_text()
        self.assertIn('"--filter-platform"', source)
        self.assertIn('WASM_TARGET', source)
        self.assertIn('CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS', source)
        self.assertIn('"fallback"', source)
        self.assertIn("ensure_cargo_toolchain(toolchain, env)", source)
        self.assertIn('cargo_args(toolchain, "--version")', source)

    def test_web_build_verifies_kassee_lock_with_pinned_cargo(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("ensure_lock_current", source)
        self.assertIn('"metadata"', source)
        self.assertIn('"--locked"', source)
        self.assertIn("reconciling transactionally", source)
        self.assertIn('"--offline"', source)
        self.assertIn("lock.write_bytes(original)", source)

    def test_web_build_pins_wasm_bindgen_cli_and_host_rust(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        pins = (ROOT / "qa/config/toolchains.env").read_text(encoding="utf-8")
        self.assertIn("KASSIGNER_WASM_BINDGEN_CLI_VERSION=0.2.117", pins)
        self.assertIn("ensure_wasm_bindgen", source)
        self.assertIn('env["RUSTUP_TOOLCHAIN"] = toolchain', source)
        self.assertIn("wasm-bindgen-cli", source)
        self.assertIn('"--root"', source)
        self.assertIn("XDG_CACHE_HOME", source)

    def test_wasm_bindgen_cli_pin_matches_kassee_lock(self) -> None:
        lock = tomllib.loads((ROOT / "apps/kassee-web/Cargo.lock").read_text(encoding="utf-8"))
        versions = {package["version"] for package in lock["package"] if package["name"] == "wasm-bindgen"}
        self.assertEqual(versions, {"0.2.117"})
        source = BUILDER.read_text(encoding="utf-8")
        self.assertIn("locked_wasm_bindgen_version", source)
        self.assertIn("wasm-bindgen crate/CLI mismatch", source)

    def test_browser_build_strips_firmware_rust_overrides(self) -> None:
        source = BUILDER.read_text(encoding="utf-8")
        for name in ("RUSTC", "RUSTDOC", "CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            self.assertIn(f'"{name}"', source)
        self.assertIn('build_env["CARGO_TARGET_DIR"]', source)

    def test_gradle_and_xcode_consume_the_same_builder(self) -> None:
        gradle = (ROOT / "apps/kassee-android/app/build.gradle.kts").read_text(encoding="utf-8")
        project = (ROOT / "apps/kassee-ios/KasSigner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        self.assertIn("tools/build/web/build_kassee_runtime.py", gradle)
        self.assertIn("tools/build/web/build_kassee_runtime.py", project)
        self.assertNotIn('"bash", "-lc"', gradle)


if __name__ == "__main__":
    unittest.main()
