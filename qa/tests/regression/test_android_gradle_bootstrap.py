from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class AndroidGradleBootstrapTests(unittest.TestCase):
    def test_protocol_extpubkey_compat_export_is_feature_scoped(self) -> None:
        source = (ROOT / "crates/kassigner-protocol/src/account/mod.rs").read_text()
        self.assertIn('#[cfg(feature = "kassee-compat")]\npub use bip32::ExtPubKey;', source)
        unconditional = re.search(r"pub use bip32::\{([^}]+)\};", source, re.S)
        self.assertIsNotNone(unconditional)
        self.assertNotIn("ExtPubKey", unconditional.group(1))

    def test_signing_authorization_quality_evidence_follows_firmware_core_owner(self) -> None:
        policy = json.loads((ROOT / "qa/checks/security/policy.json").read_text())
        self.assertIn(
            "crates/signer-firmware-core/src/unit_tests",
            policy["test_quality"]["critical_test_roots"],
        )
        requirement = next(
            item for item in policy["test_quality"]["required_evidence"]
            if item["id"] == "signing-state-authorization"
        )
        self.assertEqual(
            requirement["files"],
            [
                "crates/signer-firmware-core/src/unit_tests/security_tests.rs",
                "apps/signer-firmware/src/runtime/unit_tests/input_tests.rs",
            ],
        )
        self.assertIn("ReviewIncomplete", requirement["terms"])
        self.assertIn("review_authorized", requirement["terms"])

    def test_mixed_qr_quality_evidence_includes_canonical_protocol_decoder(self) -> None:
        policy = json.loads((ROOT / "qa/checks/security/policy.json").read_text())
        requirement = next(
            item for item in policy["test_quality"]["required_evidence"]
            if item["id"] == "mixed-qr-sessions"
        )
        self.assertIn("crates/kassigner-protocol/src/unit_tests/mod.rs", requirement["files"])
        self.assertIn("QrDecoder", requirement["terms"])

    def test_android_gradle_daemon_jvm_matches_central_jdk_pin(self) -> None:
        toolchains = {}
        for raw in (ROOT / "qa/config/toolchains.env").read_text(encoding="utf-8").splitlines():
            key, sep, value = raw.partition("=")
            if sep:
                toolchains[key.strip()] = value.strip()
        daemon = {}
        for raw in (ROOT / "apps/kassee-android/gradle/gradle-daemon-jvm.properties").read_text(encoding="utf-8").splitlines():
            key, sep, value = raw.partition("=")
            if sep:
                daemon[key.strip()] = value.strip()
        self.assertEqual(toolchains.get("KASSIGNER_ANDROID_JDK"), "25")
        self.assertEqual(daemon.get("toolchainVersion"), toolchains["KASSIGNER_ANDROID_JDK"])

    def test_linux_android_build_bootstraps_wrapper_distribution_with_sha256(self) -> None:
        source = (ROOT / "scripts/linux/build/android-build.sh").read_text()
        wrapper = (ROOT / "apps/kassee-android/gradle/wrapper/gradle-wrapper.properties").read_text()
        self.assertIn("distributionSha256Sum=", wrapper)
        self.assertIn("distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.0-bin.zip", wrapper)
        self.assertIn('Pinned Gradle $GRADLE_VERSION is not installed; downloading and verifying it', source)
        self.assertIn("urllib.request.urlopen(url)", source)
        self.assertIn("Gradle SHA-256 mismatch", source)
        self.assertIn('GRADLE_USER_HOME="${GRADLE_USER_HOME:-$HOME/.gradle}"', source)
        self.assertIn('DAEMON_JVM_PROPERTIES="$ANDROID_APP/gradle/gradle-daemon-jvm.properties"', source)
        self.assertIn('required_java="${KASSIGNER_ANDROID_JDK:-}"', source)
        self.assertIn('[[ "$daemon_java" == "$required_java" ]]', source)
        self.assertIn('$HOME/.local/share/kassigner/jdk-$required_java/bin/java', source)
        self.assertIn('install_managed_java()', source)
        self.assertIn('api.adoptium.net/v3/assets/latest/{major}/hotspot', source)
        self.assertIn('JDK SHA-256 mismatch', source)
        self.assertIn('java_bin="$(install_managed_java)"', source)
        self.assertNotIn('required_java=21', source)
        self.assertNotIn('required_java=17', source)
        self.assertNotIn('Install the verified Gradle 9.5.0 distribution before building.', source)

    def test_linux_android_build_discovers_project_and_common_sdk_locations(self) -> None:
        source = (ROOT / "scripts/linux/build/android-build.sh").read_text()
        self.assertIn('read_local_sdk_dir', source)
        self.assertIn('"/mnt/Extra/android-dev/sdk"', source)
        self.assertIn('AndroidVersion\\.ApiLevel', source)
        self.assertIn('api == 37', source)

    def test_windows_android_build_has_equivalent_verified_bootstrap(self) -> None:
        source = (ROOT / "scripts/windows/build/android-build.ps1").read_text()
        self.assertIn("distributionSha256Sum", source)
        self.assertIn("Invoke-WebRequest", source)
        self.assertIn("Get-FileHash", source)
        self.assertIn("Gradle SHA-256 mismatch", source)
        self.assertIn("Read-LocalSdk", source)
        self.assertIn("Find-Api37Jar", source)


    def test_windows_android_build_selects_managed_java_without_native_stderr_failure(self) -> None:
        source = (ROOT / "scripts/windows/build/android-build.ps1").read_text(encoding="utf-8")
        self.assertIn("Import-KasSignerToolchains $root", source)
        self.assertIn("$daemonJvmProperties = Join-Path $android 'gradle/gradle-daemon-jvm.properties'", source)
        self.assertIn("$requiredJava = [int]$centralJavaText", source)
        self.assertIn("if ([int]$daemonJavaText -ne $requiredJava)", source)
        self.assertIn(".kassigner/tools/jdk-$($env:KASSIGNER_ANDROID_JDK)/bin/java.exe", source)
        self.assertIn("Invoke-KasSignerCapture -Command $Java -Arguments @('-version')", source)
        self.assertIn("if (-not (Test-Path -LiteralPath $Java -PathType Leaf)) { return 0 }", source)
        self.assertIn("} catch {", source)
        self.assertIn("A stale or partially prepared managed JDK must be treated as absent", source)
        self.assertIn("$env:JAVA_HOME = Split-Path -Parent $javaBin", source)
        self.assertIn("function Install-ManagedJava([int]$RequiredMajor)", source)
        self.assertIn("api.adoptium.net/v3/assets/latest/$RequiredMajor/hotspot", source)
        self.assertIn("JDK SHA-256 mismatch", source)
        self.assertIn("$managed = Install-ManagedJava $RequiredMajor", source)
        self.assertIn("if ($major -eq $RequiredMajor)", source)
        self.assertNotIn("if ($major -ge $RequiredMajor)", source)
        self.assertNotIn("& java -version 2>&1", source)

    def test_windows_powershell_build_scripts_are_ascii_safe_for_windows_powershell_51(self) -> None:
        # Windows PowerShell 5.1 interprets UTF-8-without-BOM source as the active
        # ANSI code page. Non-ASCII punctuation can therefore become mojibake
        # containing typographic quote characters and change PowerShell parsing.
        for base in (ROOT / "scripts/windows", ROOT / "qa/windows"):
            for path in sorted(base.rglob("*")):
                if path.suffix.lower() not in {".ps1", ".psm1", ".psd1"}:
                    continue
                with self.subTest(path=path.relative_to(ROOT).as_posix()):
                    data = path.read_bytes()
                    try:
                        data.decode("ascii")
                    except UnicodeDecodeError as exc:
                        self.fail(
                            f"{path.relative_to(ROOT).as_posix()} contains non-ASCII source bytes; "
                            "native Windows PowerShell 5.1 runners must remain ASCII-safe: "
                            f"{exc}"
                        )

    def test_windows_android_bootstrap_probes_native_versions_through_safe_capture(self) -> None:
        installer = (ROOT / "scripts/windows/install/install.ps1").read_text(encoding="utf-8")
        studio = (ROOT / "scripts/windows/build/android-studio.ps1").read_text(encoding="utf-8")
        self.assertIn("Invoke-KasSignerCapture -Command $targetJava -Arguments @('-version')", installer)
        self.assertIn("Invoke-KasSignerCapture -Command $managedJava -Arguments @('-version')", installer)
        self.assertIn("Invoke-KasSignerCapture -Command 'gradle' -Arguments @('--version')", installer)
        self.assertIn("Invoke-KasSignerCapture -Command 'kotlinc' -Arguments @('-version')", installer)
        self.assertNotIn("& java -version 2>&1", installer)
        self.assertIn("Invoke-KasSignerCapture -Command $java -Arguments @('-version')", studio)


if __name__ == "__main__":
    unittest.main()
