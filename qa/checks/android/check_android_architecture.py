#!/usr/bin/env python3
"""Fail-closed source/architecture contracts for the Android KasSee shell."""
from __future__ import annotations
from pathlib import Path
import shutil, subprocess, sys, xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-android"
SOURCE = APP / "app/src/main/java/org/kassigner/kassigner"
MAIN = SOURCE / "app/MainActivity.kt"
WEB_HOST = SOURCE / "app/KasSeeWebViewHost.kt"
MOBILE_BRIDGE = SOURCE / "app/KasSeeMobileBridge.kt"
CONTAINER = SOURCE / "app/AppContainer.kt"
BUILD = APP / "app/build.gradle.kts"
MANIFEST = APP / "app/src/main/AndroidManifest.xml"
MAX_KOTLIN_LINES = 450
MAX_DIRECT_KOTLIN_FILES = 8


def add(errors, message): errors.append(message)


def check_structure(errors):
    for name in ("app", "domain", "features", "infrastructure", "shared"):
        if not (SOURCE / name).is_dir(): add(errors, f"missing Android source responsibility root: {name}")
    for path in (SOURCE / "generated", SOURCE / "infrastructure/engine", SOURCE / "domain/runtime",
                 SOURCE / "domain/serialization", SOURCE / "domain/transaction", SOURCE / "domain/wallet",
                 SOURCE / "features/send", SOURCE / "features/receive", SOURCE / "features/scanner",
                 SOURCE / "features/wallet", SOURCE / "features/utxos", SOURCE / "features/activity"):
        if path.exists(): add(errors, f"retired native-wallet Android surface must not exist: {path.relative_to(ROOT)}")
    forbidden_files = (
        SOURCE / "app/AppSecurityScreen.kt", SOURCE / "features/root/RootScreen.kt",
        SOURCE / "features/settings/SettingsScreen.kt", SOURCE / "features/settings/DonateScreen.kt",
        APP / "app/src/main/assets/web/bridge.js", APP / "app/src/main/assets/web/bridge.html",
    )
    for path in forbidden_files:
        if path.exists(): add(errors, f"obsolete Android compatibility file must not exist: {path.relative_to(ROOT)}")
    if list(APP.rglob("*.rs")) or (APP / "Cargo.toml").exists():
        add(errors, "Android app must not embed a duplicate Rust runtime/workspace")
    for path in SOURCE.rglob("*.kt"):
        lines = len(path.read_text(encoding="utf-8").splitlines())
        if lines > MAX_KOTLIN_LINES: add(errors, f"Kotlin SRP line limit exceeded ({lines}>{MAX_KOTLIN_LINES}): {path.relative_to(ROOT)}")
    for directory in sorted({p.parent for p in SOURCE.rglob("*.kt")}):
        if len(list(directory.glob("*.kt"))) > MAX_DIRECT_KOTLIN_FILES:
            add(errors, f"crowded Android source folder: {directory.relative_to(ROOT)}")


def check_live_shell(errors):
    required = (
        MAIN, WEB_HOST, MOBILE_BRIDGE, CONTAINER, SOURCE / "features/root/MobileOverlayScreen.kt",
        SOURCE / "features/settings/SecuritySettingsScreen.kt",
        SOURCE / "features/settings/DecoyLaunchSettingsScreen.kt",
        SOURCE / "features/cover/WeatherCoverScreen.kt",
        SOURCE / "infrastructure/security/AppLockService.kt",
        SOURCE / "infrastructure/network/WeatherService.kt",
        SOURCE / "infrastructure/network/WeatherCoverFacade.kt",
        SOURCE / "infrastructure/persistence/WeatherCoverPreferences.kt",
    )
    for path in required:
        if not path.is_file(): add(errors, f"live Android shell responsibility missing: {path.relative_to(ROOT)}")
    main = MAIN.read_text(encoding="utf-8")
    host = WEB_HOST.read_text(encoding="utf-8")
    bridge = MOBILE_BRIDGE.read_text(encoding="utf-8")
    for token in ("KasSeeWebViewHost(", "MobileOverlayScreen("):
        if token not in main: add(errors, f"Android thin Activity contract missing: {token}")
    for token in (
        'KASSEE_URL = "https://$ASSET_HOST/assets/kassee/index.html"', "WebViewAssetLoader.Builder()",
        "settings.javaScriptEnabled = true", "settings.allowFileAccess = false", "settings.allowContentAccess = false",
        "WebSettings.MIXED_CONTENT_NEVER_ALLOW", "shouldOverrideUrlLoading", 'addJavascriptInterface(',
        '"KasSignerMobile"', "import('./js/mobile/native_adaptations.js')",
    ):
        if token not in host: add(errors, f"Android KasSeeWebViewHost contract missing: {token}")
    for token in ("@JavascriptInterface", "openMobileSettings", "resetWalletSurface"):
        if token not in bridge: add(errors, f"Android native JS bridge contract missing: {token}")
    container = CONTAINER.read_text(encoding="utf-8")
    for token in ("AppPreferences", "WeatherCoverPreferences", "WeatherCoverFacade", "AppLockService"):
        if token not in container: add(errors, f"Android native shell dependency missing: {token}")
    for token in ("KasSignerEngine", "WalletStore", "WalletSyncService", "QrEngineFacade", "PendingSigningStore"):
        if token in "\n".join(p.read_text(errors="ignore") for p in SOURCE.rglob("*.kt")):
            add(errors, f"retired Android native wallet dependency remains: {token}")


def check_platform(errors):
    build = BUILD.read_text(encoding="utf-8")
    for token in ("compileSdk = 37", "targetSdk = 37", 'versionName = "2.0.0"', "JavaVersion.VERSION_17", "isMinifyEnabled = true", "isShrinkResources = true"):
        if token not in build: add(errors, f"Android build contract missing: {token}")
    for token in ('into("kassee")', 'addGeneratedSourceDirectory(', 'syncKasSeeWebUi', 'target/kassee-web/site', 'build_kassee_runtime.py'):
        if token not in build: add(errors, f"Android complete KasSee UI asset contract missing: {token}")
    if 'commandLine("bash"' in build or '"bash", "-lc"' in build:
        add(errors, "Android Gradle runtime build must not require bash; use the canonical cross-platform runtime builder")
    if 'src/main/assets/web' in build:
        add(errors, "Android generated KasSee runtime must not be staged under authored src/main/assets")
    for token in ("androidx.camera:", "com.google.mlkit:barcode-scanning", "com.google.zxing:core"):
        if token in build: add(errors, f"retired native scanner dependency remains: {token}")
    manifest = MANIFEST.read_text(encoding="utf-8")
    for token in ('android:allowBackup="false"', 'android:usesCleartextTraffic="false"', "android.permission.INTERNET", "android.permission.CAMERA"):
        if token not in manifest: add(errors, f"Android manifest contract missing: {token}")
    try: ET.parse(MANIFEST)
    except Exception as exc: add(errors, f"AndroidManifest.xml is not well formed: {exc}")
    sync = (ROOT / "scripts/linux/build/android-runtime-sync.sh").read_text(encoding="utf-8")
    if "tools/build/web/build_kassee_runtime.py" not in sync:
        add(errors, "Android runtime sync must delegate to the canonical KasSee runtime builder")


def check_tests(errors):
    required = (
        APP / "app/src/test/java/org/kassigner/kassigner/domain/WeatherUnlockPolicyTest.kt",
        APP / "app/src/test/java/org/kassigner/kassigner/infrastructure/PersistenceRobolectricTest.kt",
        APP / "app/src/test/java/org/kassigner/kassigner/infrastructure/WeatherServiceRobolectricTest.kt",
        APP / "app/src/test/java/org/kassigner/kassigner/infrastructure/AppLockServiceRobolectricTest.kt",
        APP / "app/src/androidTest/java/org/kassigner/kassigner/integration/MainActivityRecreationInstrumentedTest.kt",
    )
    for path in required:
        if not path.is_file(): add(errors, f"Android live-shell regression test missing: {path.relative_to(ROOT)}")


def check_generated_runtime(errors):
    legacy = APP / "app/src/main/assets/web"
    if legacy.exists():
        add(errors, "legacy generated Android runtime must not exist under app/src/main/assets/web")
    generated = APP / "app/build/generated/kassee-web-ui/kassee"
    if generated.exists():
        for relative in ("index.html", "js/main.js", "js/mobile/native_adaptations.js", "pkg/kassee_web.js", "pkg/kassee_web_bg.wasm"):
            if not (generated / relative).is_file():
                add(errors, f"Android generated KasSee site is incomplete: missing {relative}")


def main():
    errors=[]
    check_structure(errors); check_live_shell(errors); check_platform(errors); check_tests(errors); check_generated_runtime(errors)
    if errors:
        for msg in errors: print(f"ERROR: {msg}")
        return 1
    print("PASS: Android direct-KasSee shell, mobile security/weather, hardening, and dead-native-wallet contracts.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
