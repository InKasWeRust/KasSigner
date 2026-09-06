[KasSigner](../../README.md) › [Documentation](../../docs/README.md) › [KasSee](../../docs/kassee/KASSEE.md) › iOS

# KasSee iOS

KasSee iOS is a native Swift security/platform shell around the same KasSee
wallet used by the browser application. It does not maintain a second native
wallet, transaction builder, QR/signing engine, resolver, or watch-only database.

## Qualification

KasSee iOS has been tested on **macOS Sonoma with Xcode 16.2**, including XCTest and the native iOS mutation gate. Distribution releases additionally require an Apple signing identity/provisioning profile and physical-device smoke evidence.

## Architecture

- `KasSigner/Features/Root/` hosts the synchronized KasSee UI in a loopback-only `WKWebView`.
- `KasSigner/Features/Settings/` and `KasSigner/Features/Cover/` provide native app-lock/security and weather privacy/decoy behavior.
- `KasSigner/Infrastructure/` owns only native shell persistence/security responsibilities.
- `target/kassee-runtime/ios/KasSeeUI/` is generated staging for the complete KasSee application. Xcode references that build-owned resource tree directly; generated KasSee runtime files are not written under `KasSigner/Resources/`.

## macOS / Xcode setup

For a new Mac, double-click `setup-macos.command` in this directory, or use the
repository-level `scripts/mac/setup-macos.command` wrapper. Terminal users can
run `scripts/mac/install.sh`. These all use the same iOS-only bootstrap: it
selects the installed full Xcode application, completes
Xcode first-launch setup, verifies `make` and Python 3, installs the
repository-pinned Rust/WASM prerequisites, and verifies the **iPhone 16 Pro**
simulator destination used by iOS QA. It does not install or configure Android
or ESP32 tooling.

The same setup can be run or checked from Terminal:

```text
./scripts/mac/install.sh
./scripts/mac/install.sh --check
./scripts/mac/setup-macos.command
./apps/kassee-ios/setup-macos.command
```

After setup, run these commands from the repository root:

```text
make ios
make ios-qa
./scripts/mac/run-ios.command
```

`make ios` builds the shared KasSee Web/WASM runtime and then performs the Xcode
Simulator build. On success it prints the generated application path under
`target/ios/DerivedData/Build/Products/Debug-iphonesimulator/KasSigner.app`.
`make ios-test` writes and prints `target/ios/KasSignerTests.xcresult`.
`make ios-qa` performs the Xcode tests followed by the iOS architecture, CRAP,
and full native-shell mutation gates.
`./scripts/mac/run-ios.command` boots the configured simulator, builds into
`target/ios-simulator/`, installs `KasSigner.app`, launches it, and leaves
Simulator open for interactive testing. Pass `--simulator "DEVICE NAME"` to
choose another installed simulator or `--no-build` to relaunch the last build.

## Runtime synchronization

The Xcode target's **Sync shared KasSee runtime** phase runs the canonical
`tools/build/web/build_kassee_runtime.py`, then the platform-neutral
`tools/build/ios/sync_runtime.py`. The generated runtime stays under `target/`;
Xcode does not write generated KasSee runtime files into authored iOS sources.


## Distribution signing

The repository does not pin a developer-specific Apple Team ID. Simulator builds do not require signing. For a device/App Store archive, supply the publishing team's Apple Developer Team ID without committing it:

```bash
KASSIGNER_IOS_DEVELOPMENT_TEAM=ABCDE12345 make ios-release
```

`make ios-release` creates `target/ios/KasSigner.xcarchive`. Distribution/export from that archive uses the publisher's local Xcode/App Store Connect credentials and provisioning. Signing identities, provisioning profiles, and team IDs are deployment credentials rather than source configuration.
