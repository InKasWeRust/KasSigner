#!/usr/bin/env python3
"""Run Android API-37 connected instrumentation tests when a device is available."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-android"
SKIP = 77


def sdk_root() -> Path | None:
    value = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    return Path(value) if value else None


def connected_device(adb: str) -> str | None:
    result = subprocess.run([adb, "devices"], text=True, capture_output=True, timeout=30)
    if result.returncode:
        return None
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            return fields[0]
    return None


def main() -> int:
    gradle = shutil.which(os.environ.get("GRADLE_BIN", "gradle"))
    sdk = sdk_root()
    adb = shutil.which("adb") or (str(sdk / "platform-tools/adb") if sdk and (sdk / "platform-tools/adb").is_file() else None)
    if not gradle or not sdk or not (sdk / "platforms/android-37/android.jar").is_file():
        print("SKIP: Android instrumentation requires Gradle plus Android SDK API 37.")
        return SKIP
    if not adb:
        print("SKIP: Android instrumentation requires adb and an attached device/emulator.")
        return SKIP
    serial = os.environ.get("ANDROID_SERIAL") or connected_device(adb)
    if not serial:
        print("SKIP: no authorized Android device/emulator is attached for connectedDebugAndroidTest.")
        return SKIP
    environment = os.environ.copy()
    environment["ANDROID_SERIAL"] = serial
    command = [gradle, "--project-dir", str(APP), "--no-daemon", ":app:connectedDebugAndroidTest"]
    result = subprocess.run(command, cwd=ROOT, env=environment)
    if result.returncode:
        return result.returncode
    print(f"PASS: Android connected instrumentation suite on {serial}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
