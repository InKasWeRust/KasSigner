from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIRST_PARTY = (
    "apps/kassee-web/Cargo.toml",
    "apps/signer-firmware/Cargo.toml",
    "crates/kassigner-protocol/Cargo.toml",
    "crates/kassigner-sdk/Cargo.toml",
    "crates/offline-signer/Cargo.toml",
    "crates/online-watcher/Cargo.toml",
    "crates/shared-signer/Cargo.toml",
    "crates/signer-firmware-core/Cargo.toml",
    "qa/Cargo.toml",
    "qa/fuzz/Cargo.toml",
    "tools/Cargo.toml",
)
RELEASE_POLICY = ROOT / "apps/signer-firmware/release-policy.env"
DIAGNOSTICS = (
    "sentinel-scan", "e12-capture", "rng-probe", "wdev-capture", "sha-bench", "argon2-bench", "imu-dump",
    "icon-browser", "cam640", "boot-kats-full",
)


class ReleaseVersionAndDiagnosticsTests(unittest.TestCase):

    def test_release_policy_is_authoritative_and_self_consistent(self):
        values = dict(
            line.split("=", 1)
            for line in RELEASE_POLICY.read_text().splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        update_sequence = int(values["KASSIGNER_UPDATE_SEQUENCE"])
        security = int(values["KASSIGNER_SECURITY_VERSION"])
        self.assertGreater(update_sequence, 0)
        self.assertGreater(security, 0)
        self.assertRegex(values["KASSIGNER_ESPTOOL_VERSION"], r"^\d+\.\d+\.\d+$")


    def test_generated_release_evidence_defaults_to_root_target_qa(self):
        linux = (ROOT / "qa/linux/release/generate_software_assurance.sh").read_text()
        windows = (ROOT / "qa/windows/release/generate_software_assurance.ps1").read_text()
        readiness = (ROOT / "qa/linux/run-release-readiness.sh").read_text()
        self.assertIn("target/qa/release/evidence", linux)
        self.assertIn("target/qa/release/evidence", windows)
        self.assertNotIn("qa/evidence/release", linux)
        self.assertNotIn("qa/evidence/release", windows)
        self.assertIn("cannot be synthesized safely", readiness)

    def test_every_first_party_package_is_pinned_to_2_0_0(self):
        for relative in FIRST_PARTY:
            manifest = tomllib.loads((ROOT / relative).read_text())
            self.assertEqual(manifest["package"]["version"], "2.0.0", relative)

    def test_restored_diagnostics_are_opt_in_and_production_forbidden(self):
        manifest = tomllib.loads((ROOT / "apps/signer-firmware/Cargo.toml").read_text())
        features = manifest["features"]
        for feature in DIAGNOSTICS:
            self.assertIn(feature, features)
        policy = (ROOT / "apps/signer-firmware/src/feature_policy.rs").read_text()
        for feature in DIAGNOSTICS:
            self.assertIn(f'feature = "{feature}"', policy)
        self.assertIn("developer/QA firmware features are forbidden in production/silent builds", policy)
        e12 = (ROOT / "apps/signer-firmware/src/diagnostics/e12_capture.rs").read_text()
        self.assertIn("NIST SP 800-90B", e12)
        self.assertIn("ENTCAP_ BIN", e12)
        self.assertIn("never influences seed acceptance", e12)
        sentinel = (ROOT / "apps/signer-firmware/src/diagnostics/sentinel_scan.rs").read_text()
        self.assertIn("Synthetic remanence", sentinel)
        self.assertIn("count_stack_remanence", sentinel)
        self.assertIn("wipe_unused_stack_remanence", sentinel)
        self.assertIn("AtomicUsize", sentinel)
        self.assertIn("STACK_PROBE_LOW", sentinel)
        self.assertIn("approx_sp().saturating_sub(STACK_LIVE_MARGIN)", sentinel)
        self.assertNotIn("__stack_chk_guard", sentinel)
        self.assertNotIn("_stack_start", sentinel)
        self.assertIn("core::ptr::read_volatile", sentinel)
        self.assertIn("core::ptr::write_volatile", sentinel)
        self.assertNotIn("private_key_bytes", sentinel)
        self.assertNotIn("from_raw_parts", sentinel)
        wdev = (ROOT / "apps/signer-firmware/src/diagnostics/wdev_capture.rs").read_text()
        entropy = (ROOT / "apps/signer-firmware/src/services/entropy/trng.rs").read_text()
        self.assertIn("WORDS_PER_CAPTURE: usize = 1_000_000", wdev)
        self.assertIn("SPACINGS: [u32; 5] = [0, 16, 64, 256, 1024]", wdev)
        self.assertIn("wdev_capture_sample()", wdev)
        self.assertIn("SP 800-90B non-IID estimators", wdev)
        self.assertIn("0x6003_507C", entropy)
        self.assertIn("read_volatile(RNG_DATA_REG)", entropy)
        boot_tests = (ROOT / "apps/signer-firmware/src/runtime/unit_tests/boot.rs").read_text()
        self.assertIn('[boot-kats-full] expanded software/QR KATs', boot_tests)
        self.assertIn('crate::halt_forever(delay);', boot_tests)

    def test_diagnostic_builds_are_in_the_compile_matrix(self):
        matrix = (ROOT / "tools/build/firmware/build_matrix.py").read_text()
        for feature in DIAGNOSTICS:
            self.assertIn(feature, matrix)

    def test_cam640_excludes_the_480_only_ov5640_path(self):
        initialization = (ROOT / "apps/signer-firmware/src/hw/waveshare/cameras/ov5640/initialization.rs").read_text()
        registers = (ROOT / "apps/signer-firmware/src/hw/waveshare/cameras/ov5640/registers.rs").read_text()
        self.assertIn('#[cfg(not(feature = "cam640"))]\npub fn init_480', initialization)
        self.assertIn('#[cfg(not(feature = "cam640"))]\npub(super) static OV5640_480_OVERRIDES', registers)

    def test_real_node_and_funded_e2e_consume_the_canonical_generated_site(self):
        for relative in (
            "qa/checks/integration/real_node_browser.py",
            "qa/checks/integration/funded_testnet_e2e.py",
            "qa/checks/integration/browser_real_node_case.mjs",
            "qa/checks/integration/funded_testnet_e2e_case.mjs",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn("target/kassee-web/site", source, relative)
            self.assertNotIn("apps/kassee-web/web/pkg", source, relative)

    def test_fuzz_scratch_is_cleaned_from_the_source_tree(self):
        standalone = (ROOT / "qa/linux/run-security-fuzz.sh").read_text()
        master = (ROOT / "qa/linux/run-all.sh").read_text()
        hardening = (ROOT / "qa/linux/run-production-hardening.sh").read_text()
        windows = (ROOT / "qa/windows/runner/run_all.py").read_text()
        for source in (standalone, master, windows):
            self.assertIn("qa/fuzz/artifacts", source)
            self.assertIn("qa/fuzz/corpus", source)
        self.assertIn('run-all.sh" --profile full', hardening)
        self.assertIn("target/qa/fuzz", standalone)


if __name__ == "__main__":
    unittest.main()
