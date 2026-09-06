from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]


class AndroidGradleExecutableRecoveryTests(unittest.TestCase):
    def test_linux_gradle_bootstraps_restore_verified_zip_modes(self) -> None:
        for relative in (
            "scripts/linux/build/android-build.sh",
            "scripts/linux/build/android-studio.sh",
        ):
            source = (ROOT / relative).read_text()
            self.assertIn("member.external_attr >> 16", source)
            self.assertIn("target.chmod(mode)", source)
            self.assertIn("launcher.stat().st_mode | 0o100", source)

    @unittest.skipUnless(os.name == "posix", "Gradle executable-mode recovery is POSIX-specific")
    def test_android_build_repairs_fresh_and_cached_non_executable_gradle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "scripts/linux/build/android-build.sh"
            script.parent.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/linux/build/android-build.sh", script)
            script.chmod(0o755)

            android = root / "apps/kassee-android"
            wrapper = android / "gradle/wrapper/gradle-wrapper.properties"
            wrapper.parent.mkdir(parents=True)
            (android / "gradle/gradle-daemon-jvm.properties").write_text("toolchainVersion=25\n", encoding="utf-8")
            toolchains = root / "qa/config/toolchains.env"
            toolchains.parent.mkdir(parents=True)
            toolchains.write_text("KASSIGNER_ANDROID_JDK=25\n", encoding="utf-8")
            sdk = root / "sdk"
            platform = sdk / "platforms/android-37"
            platform.mkdir(parents=True)
            (platform / "android.jar").write_bytes(b"")
            (platform / "source.properties").write_text("AndroidVersion.ApiLevel = 37\n")

            archive = root / "fixtures/gradle-9.5.0-bin.zip"
            archive.parent.mkdir(parents=True)
            launcher_text = """#!/usr/bin/env bash
set -eu
if [[ "${1:-}" == "--version" ]]; then
  printf 'Gradle 9.5.0\\n'
  exit 0
fi
exit 0
"""
            info = zipfile.ZipInfo("gradle-9.5.0/bin/gradle")
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o755) << 16
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
                package.writestr(info, launcher_text)
            digest = sha256(archive.read_bytes()).hexdigest()
            wrapper.write_text(
                "distributionBase=GRADLE_USER_HOME\n"
                "distributionPath=wrapper/dists\n"
                f"distributionUrl={archive.as_uri()}\n"
                f"distributionSha256Sum={digest}\n"
                "zipStoreBase=GRADLE_USER_HOME\n"
                "zipStorePath=wrapper/dists\n"
            )

            fake_jdk = root / "jdk-25"
            java = fake_jdk / "bin/java"
            java.parent.mkdir(parents=True)
            java.write_text(
                "#!/usr/bin/env bash\n"
                "echo 'openjdk version \"25.0.0\"' >&2\n",
                encoding="utf-8",
            )
            java.chmod(0o755)

            gradle_home = root / "gradle-home"
            env = os.environ.copy()
            env["KASSIGNER_ANDROID_SDK_ROOT"] = str(sdk)
            env["JAVA_HOME"] = str(fake_jdk)
            env["GRADLE_USER_HOME"] = str(gradle_home)
            env.pop("GRADLE_BIN", None)
            command = ["bash", str(script), "test"]

            first = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            installed = gradle_home / "kassigner/distributions/gradle-9.5.0/bin/gradle"
            self.assertTrue(os.access(installed, os.X_OK))

            installed.chmod(0o644)
            self.assertFalse(os.access(installed, os.X_OK))
            second = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertTrue(os.access(installed, os.X_OK))

    def test_gradle_pin_stays_wrapper_authoritative_and_verified(self) -> None:
        wrapper = (ROOT / "apps/kassee-android/gradle/wrapper/gradle-wrapper.properties").read_text()
        self.assertIn("gradle-9.5.0-bin.zip", wrapper)
        self.assertIn(
            "distributionSha256Sum=553c78f50dafcd54d65b9a444649057857469edf836431389695608536d6b746",
            wrapper,
        )


if __name__ == "__main__":
    unittest.main()
