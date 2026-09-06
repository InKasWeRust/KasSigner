from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
MUTATION = ROOT / "qa/checks/android/run_mutation_tests.py"


def load_module():
    spec = importlib.util.spec_from_file_location("android_mutation_toolchain", MUTATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AndroidMutationToolchainTests(unittest.TestCase):
    def test_mutation_discovers_project_sdk_and_cached_pinned_gradle_without_global_tools(self) -> None:
        module = load_module()
        original_sdk_root = os.environ.get("ANDROID_SDK_ROOT")
        original_android_home = os.environ.get("ANDROID_HOME")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "apps/kassee-android"
            wrapper = app / "gradle/wrapper/gradle-wrapper.properties"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.0-bin.zip\n"
                "distributionSha256Sum=" + "a" * 64 + "\n",
                encoding="utf-8",
            )

            daemon = app / "gradle/gradle-daemon-jvm.properties"
            daemon.parent.mkdir(parents=True, exist_ok=True)
            daemon.write_text("toolchainVersion=25\n", encoding="utf-8")

            jdk = root / "jdk-25"
            java = jdk / "bin" / ("java.exe" if module.IS_WINDOWS else "java")
            java.parent.mkdir(parents=True)
            java.write_text("#!/bin/sh\necho 'openjdk version \"25.0.1\"' >&2\n", encoding="utf-8")
            java.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            sdk = root / "sdk"
            platform = sdk / "platforms/android-37.0"
            platform.mkdir(parents=True)
            (platform / "android.jar").write_bytes(b"")
            (platform / "source.properties").write_text(
                "AndroidVersion.ApiLevel = 37\n",
                encoding="utf-8",
            )
            (app / "local.properties").write_text(
                f"sdk.dir={sdk}\n",
                encoding="utf-8",
            )

            gradle_home = root / "gradle-home"
            gradle_name = "gradle.bat" if module.IS_WINDOWS else "gradle"
            gradle = gradle_home / f"kassigner/distributions/gradle-9.5.0/bin/{gradle_name}"
            gradle.parent.mkdir(parents=True)
            gradle.write_text("#!/bin/sh\necho 'Gradle 9.5.0'\n", encoding="utf-8")
            gradle.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            environment = {
                "PATH": "",
                "GRADLE_USER_HOME": str(gradle_home),
                "JAVA_HOME": str(jdk),
            }
            with (
                mock.patch.object(module, "APP", app),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(module.Path, "home", side_effect=RuntimeError("no home")),
                mock.patch.object(module, "_java_major", return_value=25),
                mock.patch.object(module, "_gradle_version", return_value="9.5.0"),
            ):
                command = module.gradle_command()
                self.assertEqual(os.environ.get("ANDROID_SDK_ROOT"), str(sdk.resolve()))
                self.assertEqual(os.environ.get("ANDROID_HOME"), str(sdk.resolve()))

            self.assertIsNotNone(command)
            assert command is not None
            self.assertEqual(command[0], str(gradle))
            self.assertIn(":app:testDebugUnitTest", command)
            self.assertNotIn("-x", command)
            self.assertNotIn(":app:syncKasSeeWebUi", command)
            self.assertNotIn(":app:purgeLegacyKasSignerRuntime", command)
            self.assertEqual(os.environ.get("ANDROID_SDK_ROOT"), original_sdk_root)
            self.assertEqual(os.environ.get("ANDROID_HOME"), original_android_home)

    def test_mutation_rejects_wrong_global_gradle_and_prefers_pinned_cache(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "apps/kassee-android"
            wrapper = app / "gradle/wrapper/gradle-wrapper.properties"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text(
                "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.5.0-bin.zip\n",
                encoding="utf-8",
            )
            home = root / "home"
            cached = home / ".gradle/kassigner/distributions/gradle-9.5.0/bin/gradle"
            cached.parent.mkdir(parents=True)
            cached.write_text("#!/bin/sh\necho 'Gradle 9.5.0'\n", encoding="utf-8")
            cached.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            bad_bin = root / "bad-bin"
            bad_bin.mkdir()
            bad = bad_bin / "gradle"
            bad.write_text("#!/bin/sh\necho 'Gradle 8.8'\n", encoding="utf-8")
            bad.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            def fake_which(name: str) -> str | None:
                return str(bad) if name == "gradle" else None

            def fake_gradle_version(command: str) -> str | None:
                return "9.5.0" if Path(command) == cached else "8.8"

            with (
                mock.patch.object(module, "APP", app),
                mock.patch.object(module, "IS_WINDOWS", False),
                mock.patch.dict(os.environ, {"HOME": str(home), "PATH": str(bad_bin)}, clear=True),
                mock.patch.object(module.shutil, "which", side_effect=fake_which),
                mock.patch.object(module.os, "access", return_value=True),
                mock.patch.object(module, "_gradle_version", side_effect=fake_gradle_version),
            ):
                self.assertEqual(module.gradle_binary(), str(cached))

            with (
                mock.patch.object(module, "APP", app),
                mock.patch.object(module, "IS_WINDOWS", False),
                mock.patch.dict(os.environ, {"HOME": str(root / "empty-home"), "PATH": str(bad_bin)}, clear=True),
                mock.patch.object(module.shutil, "which", side_effect=fake_which),
                mock.patch.object(module.os, "access", return_value=True),
                mock.patch.object(module, "_gradle_version", side_effect=fake_gradle_version),
            ):
                self.assertIsNone(module.gradle_binary())

    def test_windows_mutation_reselects_managed_jdk25_after_android_build_wrapper_exits(self) -> None:
        module = load_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "apps/kassee-android"
            daemon = app / "gradle/gradle-daemon-jvm.properties"
            daemon.parent.mkdir(parents=True)
            daemon.write_text("toolchainVersion=25\n", encoding="utf-8")
            user = root / "user"
            java = user / ".kassigner/tools/jdk-25/bin/java.exe"
            java.parent.mkdir(parents=True)
            java.write_text("#!/bin/sh\necho 'openjdk version \"25.0.1\"' >&2\n", encoding="utf-8")
            java.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            environment = {"USERPROFILE": str(user), "PATH": ""}
            with (
                mock.patch.object(module, "APP", app),
                mock.patch.object(module, "IS_WINDOWS", True),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(module, "_java_major", return_value=25),
            ):
                self.assertTrue(module.configure_gradle_java())
                self.assertEqual(os.environ["JAVA_HOME"], str(java.parent.parent))
                self.assertEqual(os.environ["PATH"].split(os.pathsep)[0], str(java.parent))

    def test_missing_portable_cli_does_not_block_gradle_mutation_baseline(self) -> None:
        module = load_module()
        calls: list[list[str]] = []

        class Result:
            returncode = 0
            stdout = ""

        def fake_run(command, *, timeout=420):
            calls.append(list(command))
            return Result()

        gradle_command = ["/verified/gradle", ":app:testDebugUnitTest"]
        with (
            mock.patch.object(module, "portable_toolchain_available", return_value=False),
            mock.patch.object(module, "run", side_effect=fake_run),
        ):
            self.assertTrue(module.baseline(gradle_command))

        self.assertEqual(calls[0], [sys.executable, str(module.ARCH)])
        self.assertEqual(calls[1], gradle_command)
        self.assertFalse(any(str(module.PORTABLE) in item for call in calls for item in call))


    def test_mutant_timeout_is_counted_as_a_kill_after_green_baseline(self) -> None:
        module = load_module()
        mutants, files = module.discover()
        self.assertTrue(mutants)
        timeout = subprocess.TimeoutExpired(cmd=["gradle"], timeout=420)
        with (
            mock.patch.object(module, "discover", return_value=([mutants[0]], files)),
            mock.patch.object(module, "gradle_command", return_value=["/verified/gradle", ":app:testDebugUnitTest"]),
            mock.patch.object(module, "baseline", return_value=True),
            mock.patch.object(module, "mutant_survives", side_effect=timeout),
            mock.patch.object(sys, "argv", [str(MUTATION)]),
        ):
            self.assertEqual(module.main(), 0)

    def test_android_production_source_crap_gate_is_green(self) -> None:
        checker = ROOT / "qa/checks/android/kotlin_crap.py"
        result = subprocess.run(
            [sys.executable, str(checker)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS: Android source CRAP", result.stdout)

    def test_mutation_keeps_api37_and_pinned_gradle_cache_contracts(self) -> None:
        source = MUTATION.read_text(encoding="utf-8")
        gradle_source = (ROOT / "apps/kassee-android/app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn('Path("/mnt/Extra/android-dev/sdk")', source)
        self.assertIn('Path("/mnt/Extra/android-dev/gradle")', source)
        self.assertIn('APP / "local.properties"', source)
        self.assertIn('kassigner/distributions/gradle-{version}/bin/gradle', source)
        self.assertIn('":app:testDebugUnitTest"', source)
        self.assertNotIn('"-x", ":app:syncKasSeeWebUi"', source)
        self.assertNotIn('":app:purgeLegacyKasSignerRuntime"', source)
        self.assertIn("Gradle JUnit/Robolectric baseline remains authoritative", source)
        self.assertIn('KASSIGNER_ANDROID_JDK', source)
        self.assertIn('gradle-daemon-jvm.properties', source)
        self.assertIn('.kassigner/tools/jdk-{required}/bin/java.exe', source)
        self.assertIn('configure_gradle_java()', source)
        self.assertIn('it.name.startsWith("merge") && it.name.endsWith("Assets")', gradle_source)
        self.assertIn("dependsOn(syncKasSeeWebUi)", gradle_source)


if __name__ == "__main__":
    unittest.main()
