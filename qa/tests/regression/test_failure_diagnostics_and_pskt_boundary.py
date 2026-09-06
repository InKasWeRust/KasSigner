from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
TX = ROOT / "apps/signer-firmware/src/runtime/interactions/tx/transaction.rs"
PSKT_CONTEXT = ROOT / "apps/signer-firmware/src/runtime/interactions/tx/transaction/standard_pskt_context.rs"
STD_PSKT = ROOT / "crates/offline-signer/src/transaction/std_pskt"
CONNECTED = ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/mod.rs"
WALLET = ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/wallet.rs"
SIGNING = ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs"
SD_IMPORTS = ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/sd_workflows/imports.rs"
ERRORS = ROOT / "apps/signer-firmware/src/ui/screens/signing/errors.rs"
PERSIST = ROOT / "apps/signer-firmware/src/services/persistent_wallet/mod.rs"
ANDROID_TEST = ROOT / "apps/kassee-android/app/src/test/java/org/kassigner/kassigner/infrastructure/PersistenceRobolectricTest.kt"
ANDROID_GRADLE = ROOT / "apps/kassee-android/app/build.gradle.kts"
ANDROID_BUILD = ROOT / "scripts/linux/build/android-build.sh"


class FailureDiagnosticsAndPsktBoundaryTests(unittest.TestCase):
    def test_standard_pskt_wire_stays_network_field_free(self) -> None:
        files = sorted(STD_PSKT.rglob("*.rs"))
        joined = "\n".join(path.read_text() for path in files)
        self.assertNotIn('b"network"', joined)
        self.assertNotIn('"network":', joined)
        tx = TX.read_text()
        context = PSKT_CONTEXT.read_text()
        self.assertIn("standard_pskt_context::bind_selected_network(ad);", tx)
        self.assertIn("selected wallet/network is therefore local signing context only", context)
        self.assertIn("selected_network_matches_transaction(ad)", tx)  # compact KSPT still enforces its trailer

    def test_connected_failures_replay_actual_reason_catalog(self) -> None:
        connected = CONNECTED.read_text()
        wallet = WALLET.read_text()
        signing = SIGNING.read_text()
        sd = SD_IMPORTS.read_text()
        tx = TX.read_text() + "\n" + PSKT_CONTEXT.read_text()
        self.assertIn("CONNECTED FAILURE DETAILS BEGIN", connected)
        self.assertIn("CONNECTED FAILURE DETAILS END", connected)
        self.assertIn("wallet::replay_failure_detail();", connected)
        self.assertIn("CONNECTED FAILURE REASON WALLET", wallet)
        self.assertIn("workflow_replay_standard_pskt_failure_reason", signing)
        self.assertIn("workflow_replay_standard_pskt_failure_reason", sd)
        self.assertIn("CONNECTED FAILURE REASON STANDARD-PSKT", tx)
        self.assertIn("state={:?} total_inputs={} review_pages={}", signing)

    def test_error_surfaces_wrap_by_pixel_width_without_character_truncation(self) -> None:
        errors = ERRORS.read_text()
        persist = PERSIST.read_text()
        self.assertIn("const ERROR_TEXT_WIDTH: i32 = 280;", errors)
        self.assertIn("const ERROR_MAX_LINES: usize = 7;", errors)
        self.assertIn("fn wrap_error_text", errors)
        self.assertIn("measure_body(remaining) <= ERROR_TEXT_WIDTH", errors)
        self.assertNotIn("truncate_chars", errors)
        self.assertNotIn("split_recoverable_message", errors)
        self.assertIn("message,\n            Some(code)", errors)
        self.assertIn("Password must be at least 8 characters", persist)

    def test_robolectric_runs_on_supported_sdk_while_app_stays_api_37(self) -> None:
        test = ANDROID_TEST.read_text()
        gradle = ANDROID_GRADLE.read_text()
        build = ANDROID_BUILD.read_text()
        self.assertIn("@Config(sdk = [36])", test)
        self.assertIn('testImplementation("org.robolectric:robolectric:4.16.1")', gradle)
        self.assertIn("compileSdk = 37", gradle)
        self.assertIn("targetSdk = 37", gradle)
        self.assertIn('DAEMON_JVM_PROPERTIES="$ANDROID_APP/gradle/gradle-daemon-jvm.properties"', build)
        self.assertIn('required_java="${KASSIGNER_ANDROID_JDK:-}"', build)
        self.assertIn('[[ "$daemon_java" == "$required_java" ]]', build)
        self.assertNotIn("required_java=21", build)
        self.assertIn("sourceCompatibility = JavaVersion.VERSION_17", gradle)
        self.assertIn("targetCompatibility = JavaVersion.VERSION_17", gradle)


if __name__ == "__main__":
    unittest.main()
