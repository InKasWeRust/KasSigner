#!/usr/bin/env python3
"""Compile and run the host-portable Android shell policy tests."""
from pathlib import Path
import shutil, subprocess, sys, tempfile
ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-android"
SKIP = 77
SOURCES = (APP / "app/src/main/java/org/kassigner/kassigner/domain/weather/WeatherModels.kt",)
TEST = APP / "portable-tests/KasSignerShellCoreTests.kt"

def main():
    kotlinc=shutil.which("kotlinc"); java=shutil.which("java")
    if not kotlinc or not java:
        print("SKIP: standalone Kotlin CLI smoke test requires kotlinc and java; Gradle JUnit remains authoritative.")
        return SKIP
    with tempfile.TemporaryDirectory(prefix="kassee-android-shell-") as tmp:
        jar=Path(tmp)/"tests.jar"
        result=subprocess.run([kotlinc,*(str(p) for p in SOURCES),str(TEST),"-include-runtime","-d",str(jar)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        if result.returncode: print(result.stdout,end=""); return result.returncode
        result=subprocess.run([java,"-jar",str(jar)],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(result.stdout,end=""); return result.returncode
if __name__ == "__main__": raise SystemExit(main())
