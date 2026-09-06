#!/usr/bin/env python3
"""Regression coverage for the single pinned toolchain/version policy."""

from pathlib import Path
import json
import tomllib
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from toolchains import REQUIRED, load_toolchains  # noqa: E402
from architecture.tooling import toolchain_policy  # noqa: E402
from security.fuzz_targets import registered_targets, validate_targets  # noqa: E402


class ToolchainPolicyTests(unittest.TestCase):
    def test_central_policy_is_complete_and_unique(self) -> None:
        pins = load_toolchains()
        self.assertEqual(set(pins), REQUIRED)
        for key, value in pins.items():
            self.assertTrue(value.strip(), key)

    def test_architecture_toolchain_policy_is_green(self) -> None:
        self.assertEqual(toolchain_policy.check(ROOT), [])

    def test_fuzz_manifest_is_the_only_target_registry(self) -> None:
        targets = registered_targets()
        self.assertEqual(len(targets), 10)
        self.assertEqual(validate_targets(), [])
        policy = json.loads((ROOT / "qa/checks/security/policy.json").read_text())
        self.assertNotIn("targets", policy["fuzz"])
        runner = (ROOT / "qa/linux/run-security-fuzz.sh").read_text()
        commands = (ROOT / "qa/linux/runner/commands.sh").read_text()
        for source in (runner, commands):
            self.assertIn("fuzz_targets.py", source)

    def test_ci_keeps_required_push_pr_job_fast_and_fuzz_separate(self) -> None:
        workflows = {
            name: (ROOT / f".github/workflows/{name}").read_text()
            for name in ("core.yml", "kassee-ci.yml", "android.yml", "ios.yml", "rqrr.yml", "fuzz.yml")
        }
        core = workflows["core.yml"]
        fuzz = workflows["fuzz.yml"]
        self.assertIn('make test STRICT_LOCKFILES=1', core)
        self.assertNotIn('make qa', core)
        exporter = "grep -E '^[A-Za-z_][A-Za-z0-9_]*=' qa/config/toolchains.env >> \"$GITHUB_ENV\""
        for name in ("core.yml", "kassee-ci.yml", "android.yml", "ios.yml", "rqrr.yml"):
            self.assertIn(exporter, workflows[name], name)
            self.assertNotIn('cat qa/config/toolchains.env >> "$GITHUB_ENV"', workflows[name], name)
            self.assertIn('actions/checkout@v6', workflows[name], name)
        self.assertIn('actions/checkout@v6', fuzz)
        self.assertIn('actions/upload-artifact@v6', fuzz)
        for name in ("core.yml", "kassee-ci.yml"):
            self.assertIn('--component rustfmt --component clippy', workflows[name], name)
        self.assertIn('FUZZ_SECONDS=300 bash scripts/linux/quality/security-fuzz.sh', fuzz)
        self.assertNotIn('make qa', fuzz)

        esp_action = 'uses: esp-rs/xtensa-toolchain@v1.7.0'
        self.assertIn(esp_action, core)
        self.assertIn('version: ${{ env.KASSIGNER_ESP_RUST }}', core)
        self.assertIn('buildtargets: esp32s3', core)
        self.assertIn('override: false', core)
        self.assertIn('default: false', core)
        self.assertIn('export: true', core)
        self.assertIn('GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}', core)
        native_step = '- name: Install Core CI native dependencies'
        self.assertIn(native_step, core)
        for package in (
            'libudev-dev',
            'libwayland-cursor0',
            'libwayland-dev',
            'libxkbcommon-dev',
            'pkg-config',
        ):
            self.assertIn(package, core)
        self.assertIn('sudo apt-get update', core)
        self.assertIn('sudo apt-get install -y --no-install-recommends', core)
        self.assertLess(core.index(native_step), core.index('make test STRICT_LOCKFILES=1'))
        self.assertLess(core.index(esp_action), core.index('make test STRICT_LOCKFILES=1'))

    def test_core_ci_skips_mobile_only_source_changes(self) -> None:
        core = (ROOT / ".github/workflows/core.yml").read_text()
        trigger_block = core.split("\njobs:", 1)[0]
        for platform_path in ("apps/kassee-android/**", "apps/kassee-ios/**"):
            self.assertEqual(trigger_block.count(f"'{platform_path}'"), 2, platform_path)
        self.assertEqual(trigger_block.count("    paths-ignore:\n"), 2)
        self.assertIn("  workflow_dispatch:\n", trigger_block)

    def test_android_ci_uses_pinned_jdk_and_sdk_policy(self) -> None:
        android = (ROOT / ".github/workflows/android.yml").read_text()
        self.assertIn('actions/setup-java@v6', android)
        self.assertIn('java-version: ${{ steps.toolchains.outputs.android_jdk }}', android)
        self.assertIn('KASSIGNER_ANDROID_JDK', android)
        self.assertIn('KASSIGNER_ANDROID_CMDLINE_TOOLS', android)
        self.assertIn('KASSIGNER_ANDROID_CMDLINE_TOOLS_LINUX_SHA256', android)
        self.assertIn('commandlinetools-linux-${KASSIGNER_ANDROID_CMDLINE_TOOLS}_latest.zip', android)
        self.assertIn('--list --channel=3', android)
        self.assertIn('"platforms;android-${KASSIGNER_ANDROID_API}"', android)
        self.assertIn('"platforms;android-${KASSIGNER_ANDROID_API}.0"', android)
        self.assertIn('--sdk_root="$sdk_root" --channel=3', android)
        self.assertIn('if (value == candidate) found=1', android)
        self.assertNotIn('grep -Fq "$candidate"', android)
        self.assertIn('build-tools;${KASSIGNER_ANDROID_BUILD_TOOLS}', android)
        self.assertNotIn('command -v sdkmanager', android)
        self.assertNotIn("java-version: '21'", android)
        self.assertIn('rustup toolchain install "$KASSIGNER_STABLE_RUST" --profile minimal', android)

    def test_root_lock_tracks_wasm_target_dependencies_used_by_workspace_members(self) -> None:
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        packages = {package["name"]: package for package in lock["package"]}
        protocol_dependencies = {entry.split()[0] for entry in packages["kassigner-protocol"].get("dependencies", [])}
        sdk_dependencies = {entry.split()[0] for entry in packages["kassigner-sdk"].get("dependencies", [])}
        # Cargo generates a workspace lock as if all features of every
        # workspace member and all target-specific dependencies are enabled.
        self.assertIn("js-sys", protocol_dependencies)
        self.assertIn("wasm-bindgen", protocol_dependencies)
        self.assertIn("js-sys", sdk_dependencies)
        self.assertIn("wasm-bindgen", sdk_dependencies)

    def test_root_lock_retains_ark_ff_edges(self) -> None:
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        packages = {package["name"]: package for package in lock["package"]}
        for name in (
            "ark-bn254",
            "ark-crypto-primitives",
            "ark-ec",
            "ark-groth16",
            "ark-poly",
            "ark-relations",
            "ark-snark",
        ):
            dependencies = {entry.split()[0] for entry in packages[name].get("dependencies", [])}
            self.assertIn("ark-ff", dependencies, name)

    def test_rqrr_is_independent_workspace_with_own_lock(self) -> None:
        root = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]
        self.assertNotIn("external/rqrr-nostd", root["members"])
        self.assertIn("external/rqrr-nostd", root["exclude"])
        rqrr_manifest = tomllib.loads((ROOT / "external/rqrr-nostd/Cargo.toml").read_text())
        self.assertEqual(rqrr_manifest["workspace"]["resolver"], "2")
        rqrr_lock = tomllib.loads((ROOT / "external/rqrr-nostd/Cargo.lock").read_text())
        self.assertEqual([(p["name"], p["version"]) for p in rqrr_lock["package"]], [("rqrr", "0.10.1-nostd")])

    def test_refactored_repository_retains_dedicated_rqrr_ci(self) -> None:
        rqrr = (ROOT / ".github/workflows/rqrr.yml").read_text()
        self.assertIn('name: rqrr CI', rqrr)
        self.assertIn('external/rqrr-nostd/**', rqrr)
        self.assertIn('working-directory: external/rqrr-nostd', rqrr)
        self.assertIn('cargo build --release --locked', rqrr)
        self.assertIn('cargo test --all-features --locked', rqrr)
        self.assertIn('cargo clippy --all-targets --all-features --locked', rqrr)

    def test_rqrr_documents_intentional_no_std_clippy_exceptions(self) -> None:
        source = (ROOT / "external/rqrr-nostd/src/lib.rs").read_text()
        for lint in (
            "suspicious_arithmetic_impl",
            "suspicious_op_assign_impl",
            "result_unit_err",
            "manual_is_multiple_of",
            "manual_div_ceil",
        ):
            self.assertIn(f"#![allow(clippy::{lint})]", source, lint)
        self.assertIn("GF(2^n) addition is XOR", source)
        self.assertIn("older ESP toolchain", source)

    def test_kassee_ci_formats_only_the_kassee_package(self) -> None:
        workflow = (ROOT / ".github/workflows/kassee-ci.yml").read_text()
        self.assertIn(
            'cargo fmt --manifest-path apps/kassee-web/Cargo.toml --package kassee-web -- --check',
            workflow,
        )
        self.assertNotIn(
            'cargo fmt --manifest-path apps/kassee-web/Cargo.toml --all -- --check',
            workflow,
        )
        self.assertNotIn(
            'run: rustup run "$KASSIGNER_STABLE_RUST" cargo fmt --all -- --check',
            workflow,
        )

    def test_platform_ci_supports_manual_rerun(self) -> None:
        for name in ("core.yml", "kassee-ci.yml", "android.yml", "ios.yml", "rqrr.yml"):
            workflow = (ROOT / f".github/workflows/{name}").read_text()
            self.assertIn("  workflow_dispatch:\n", workflow, name)

    def test_fuzz_stays_nightly_manual_or_harness_change_only(self) -> None:
        fuzz = (ROOT / ".github/workflows/fuzz.yml").read_text()
        trigger_block = fuzz.split("\njobs:", 1)[0]
        self.assertIn("  schedule:\n", trigger_block)
        self.assertIn("  workflow_dispatch:\n", trigger_block)
        self.assertIn("  push:\n", trigger_block)
        self.assertNotIn("  pull_request:\n", trigger_block)
        self.assertIn("'qa/fuzz/**'", trigger_block)
        self.assertIn("'scripts/linux/quality/security-fuzz.sh'", trigger_block)
        self.assertNotIn("'.github/workflows/fuzz.yml'", trigger_block)
        self.assertIn("bounded-security-fuzz:", fuzz)



if __name__ == "__main__":
    unittest.main()
