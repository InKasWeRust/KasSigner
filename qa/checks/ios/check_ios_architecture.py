#!/usr/bin/env python3
"""Fail-closed source/architecture contracts for the iOS KasSee shell."""
from __future__ import annotations
from pathlib import Path
import re, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parents[3]
APP = ROOT / "apps/kassee-ios"
SOURCE = APP / "KasSigner"
PBX = APP / "KasSigner.xcodeproj/project.pbxproj"
ROOT_VIEW = SOURCE / "Features/Root/Components/RootView.swift"
WEB_VIEW = SOURCE / "Features/Root/Components/KasSeeWebView.swift"
LOOPBACK = SOURCE / "Features/Root/Components/KasSeeLoopbackServer.swift"
APP_ENTRY = SOURCE / "App/KasSignerApp.swift"
MAX_SWIFT_LINES = 600
MAX_DIRECT_SWIFT_FILES = 8


def add(errors, message): errors.append(message)


def check_structure(errors):
    for name in ("App", "Features", "Infrastructure"):
        if not (SOURCE / name).is_dir(): add(errors, f"missing iOS source responsibility root: KasSigner/{name}")
    for path in (SOURCE / "Domain", SOURCE / "Generated", SOURCE / "Infrastructure/Engine",
                 SOURCE / "Features/Receive", SOURCE / "Features/Scanner", SOURCE / "Features/Send", SOURCE / "Features/Wallet"):
        if path.exists(): add(errors, f"retired native-wallet iOS surface must not exist: {path.relative_to(ROOT)}")
    for path in (SOURCE / "Resources/Web/bridge.js", SOURCE / "Resources/Web/bridge.html", APP / "Package.swift", APP / "Tests/KasSignerCoreTests"):
        if path.exists(): add(errors, f"obsolete iOS compatibility/runtime file must not exist: {path.relative_to(ROOT)}")
    if list(APP.rglob("*.rs")): add(errors, "iOS app must not embed a duplicate Rust runtime")
    for path in SOURCE.rglob("*.swift"):
        lines=len(path.read_text(encoding="utf-8").splitlines())
        if lines > MAX_SWIFT_LINES: add(errors, f"Swift SRP line limit exceeded ({lines}>{MAX_SWIFT_LINES}): {path.relative_to(ROOT)}")
    for directory in sorted({p.parent for p in SOURCE.rglob("*.swift")}):
        if len(list(directory.glob("*.swift"))) > MAX_DIRECT_SWIFT_FILES: add(errors, f"crowded iOS source folder: {directory.relative_to(ROOT)}")


def check_live_shell(errors):
    required=(APP_ENTRY, ROOT_VIEW, WEB_VIEW, LOOPBACK, SOURCE / "Features/Settings/SecuritySettingsView.swift",
              SOURCE / "Features/Cover/Components/WeatherCoverView.swift", SOURCE / "Features/Cover/Components/WeatherCoverModel.swift",
              SOURCE / "Infrastructure/Persistence/AppPreferences.swift", SOURCE / "Infrastructure/Security/AppLockService.swift")
    for path in required:
        if not path.is_file(): add(errors, f"live iOS shell responsibility missing: {path.relative_to(ROOT)}")
    root=ROOT_VIEW.read_text(encoding="utf-8")
    web=WEB_VIEW.read_text(encoding="utf-8")
    loopback=LOOPBACK.read_text(encoding="utf-8")
    for token in ("KasSeeWebView(", "KasSeeLoopbackServer", "SecuritySettingsView", "loadFailure"):
        if token not in root: add(errors, f"iOS thin RootView contract missing: {token}")
    for token in (
        "WKWebView",
        "allowsContentJavaScript = true",
        "decidePolicyFor navigationAction",
        "renderHealthCheck",
        "reportLoadState",
        "import('./js/mobile/native_adaptations.js')",
    ):
        if token not in web: add(errors, f"iOS KasSeeWebView contract missing: {token}")
    for forbidden in ("mobileViewportBootstrap", "webView.pageZoom", "scrollView.minimumZoomScale", "scrollView.maximumZoomScale"):
        if forbidden in web: add(errors, f"iOS KasSeeWebView must rely on the canonical page viewport instead of native zoom mutation: {forbidden}")
    for token in (
        "NWListener",
        "127.0.0.1",
        "Cache-Control: no-store",
        "normalizedRequestPath",
        "httpResponseHeader",
        'joined(separator: "\\r\\n")',
        "contentContext: .finalMessage",
        "isComplete: true",
        "mimeType",
    ):
        if token not in loopback: add(errors, f"iOS loopback server contract missing: {token}")
    if '"",\n            "",' not in loopback:
        add(errors, "iOS loopback HTTP responses must terminate headers with CRLF CRLF")
    app=APP_ENTRY.read_text(encoding="utf-8")
    for token in ("AppPreferences()", "AppLockService()", "AppSecurityContainer", "WeatherCoverView"):
        if token not in app: add(errors, f"iOS native shell dependency missing: {token}")
    combined="\n".join(p.read_text(errors="ignore") for p in SOURCE.rglob("*.swift"))
    for token in ("WalletStore", "KasSignerEngine", "WalletSyncService", "KaspaLiveRPCService", "UTXOCoinControlStore", "PriceService", "CopyFeedbackCenter"):
        if token in combined: add(errors, f"retired iOS native wallet dependency remains: {token}")


def require_regex(errors, text, pattern, message):
    if re.search(pattern, text, flags=re.S) is None:
        add(errors, message)


def check_cover_behavior(errors):
    city=(SOURCE / "Features/Cover/Components/CitySearchView.swift").read_text(encoding="utf-8")
    decoy=(SOURCE / "Features/Cover/Components/DecoyLaunchSettingsView.swift").read_text(encoding="utf-8")
    cover=(SOURCE / "Features/Cover/Components/WeatherCoverView.swift").read_text(encoding="utf-8")
    settings=(SOURCE / "Features/Cover/Components/WeatherSettingsView.swift").read_text(encoding="utf-8")

    for token in (
        "query.count >= 2 && model.searchResults.isEmpty",
        "guard !Task.isCancelled, query == newValue else { return }",
    ):
        if token not in city: add(errors, f"iOS city-search behavior contract missing: {token}")

    for token in (
        "@AppStorage(WeatherCoverKey.enabled) private var enabled = false",
        "@State private var toggleValue = false",
        ".disabled(appLockService.isAuthenticating || !appLockService.isEnabled)",
        "guard oldValue != newValue, newValue != enabled else { return }",
        ".navigationBarBackButtonHidden(onHome != nil)",
    ):
        if token not in decoy: add(errors, f"iOS decoy-launch behavior contract missing: {token}")
    require_regex(errors, decoy, r"if !appLockService\.isEnabled\s*\{\s*enabled = false\s*\}",
                  "iOS decoy-launch must disable the weather cover on appear when App Lock is off")
    require_regex(errors, decoy, r"if !appLockEnabled\s*\{\s*enabled = false\s*toggleValue = false\s*\}",
                  "iOS decoy-launch must disable and visually reset the weather cover when App Lock turns off")

    for token in (
        "@State private var showingSettings = false",
        "@State private var isUnlockRequestInFlight = false",
        "Button { showingSettings = true }",
        "Text(index == 0 ? \"Today\"",
        "temperatureUnit == \"fahrenheit\"",
        "guard target == tappedTarget, !isUnlockRequestInFlight else { return }",
        "guard await waitForTapWindow(), tapSequenceID == sequenceID else { return }",
        "guard completedCount == requiredTapCount else { return }",
    ):
        if token not in cover: add(errors, f"iOS weather-cover behavior contract missing: {token}")
    require_regex(errors, cover, r"WeatherSettingsView\(model: model\)\s*\{\s*showingSettings = false\s*\}",
                  "iOS weather-cover settings sheet must close by resetting its presentation state")
    require_regex(errors, cover, r"isUnlockRequestInFlight = true\s*await requestUnlock\(\)\s*isUnlockRequestInFlight = false",
                  "iOS weather-cover unlock request must be guarded for the full async request")
    require_regex(errors, cover, r"try await Task\.sleep\(for: \.milliseconds\(500\)\)\s*return true\s*\} catch \{\s*return false",
                  "iOS weather-cover tap window must succeed only after the delay and fail when cancelled")

    for token in (
        "@AppStorage(WeatherCoverKey.enabled) private var decoyEnabled = false",
        "@State private var showingCitySearch = false",
        "@State private var showingResetConfirmation = false",
        "showingCitySearch = true",
        "showingResetConfirmation = true",
    ):
        if token not in settings: add(errors, f"iOS weather-settings behavior contract missing: {token}")
    require_regex(errors, settings, r"longitude = location\.longitude\s*showingCitySearch = false",
                  "iOS weather-settings city selection must dismiss the city-search sheet")
    require_regex(errors, settings, r"removeObject\(forKey: WeatherCoverKey\.longitude\)\s*decoyEnabled = false",
                  "iOS weather-settings reset must disable the weather cover after clearing location state")
    if settings.count('temperatureUnit == "fahrenheit"') != 2:
        add(errors, "iOS weather-settings must use the selected temperature unit for both refresh paths")


def check_project(errors):
    project=PBX.read_text(encoding="utf-8")
    disk=sorted(p.relative_to(APP).as_posix() for p in SOURCE.rglob("*.swift"))
    project_paths=sorted(set(re.findall(r"path = (KasSigner/[^;]+\.swift);", project)))
    if disk != project_paths:
        add(errors, f"Xcode Swift source list drifted (missing={sorted(set(disk)-set(project_paths))}, stale={sorted(set(project_paths)-set(disk))})")
    if "MARKETING_VERSION = 2.0.0;" not in project: add(errors, "KasSee iOS marketing version must remain pinned at 2.0.0")
    if "Sync shared KasSee runtime" not in project or "tools/build/web/build_kassee_runtime.py" not in project or "tools/build/ios/sync_runtime.py" not in project:
        add(errors, "Xcode target must consume the canonical KasSee runtime builder and synchronize generated iOS resources")
    if "../../target/kassee-runtime/ios/KasSeeUI" not in project:
        add(errors, "Xcode KasSeeUI resource must point to generated target/ build resources")
    if "KasSigner/Resources/KasSeeUI" in project:
        add(errors, "Xcode must not stage generated KasSeeUI under authored source resources")
    sync=(ROOT / "tools/build/ios/sync_runtime.py").read_text(encoding="utf-8")
    for token in ('target" / "kassee-web" / "site', 'target" / "kassee-runtime" / "ios" / "KasSeeUI', 'shutil.copytree', 'kassee_web_bg.wasm'):
        if token not in sync: add(errors, f"iOS KasSee runtime sync contract missing: {token}")


def check_tests(errors):
    for path in (APP / "Tests/KasSignerAppTests/KasSignerAppTests.swift", APP / "Tests/KasSignerUITests/KasSignerUITests.swift"):
        if not path.is_file(): add(errors, f"iOS live-shell test missing: {path.relative_to(ROOT)}")


def parse_sources(errors):
    swiftc=shutil.which("swiftc")
    if swiftc:
        files=[str(p) for p in sorted(SOURCE.rglob("*.swift"))]
        result=subprocess.run([swiftc,"-frontend","-parse",*files],text=True,capture_output=True)
        if result.returncode: add(errors,"Swift source parse failed: "+(result.stderr or result.stdout).strip())


def main():
    errors=[]
    check_structure(errors); check_live_shell(errors); check_cover_behavior(errors); check_project(errors); check_tests(errors); parse_sources(errors)
    if errors:
        for msg in errors: print(f"ERROR: {msg}")
        return 1
    print("PASS: iOS direct-KasSee shell, mobile security/weather, Xcode source, and dead-native-wallet contracts.")
    return 0

if __name__ == "__main__": raise SystemExit(main())
