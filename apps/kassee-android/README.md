[KasSigner](../../README.md) › [Documentation](../../docs/README.md) › [KasSee](../../docs/kassee/KASSEE.md) › Android

# KasSee Android

KasSee Android is the Android 17 / API 37 shell for the centralized KasSee wallet. The app does **not** maintain a second native wallet, transaction builder, QR/signing engine, node resolver, or watch-only database. Wallet behavior and all existing KasSigner/KasSee features are supplied by the current `apps/kassee-web` application and shared Rust crates.

## Platform target

- Android 17 / API 37 (`compileSdk = 37`, `targetSdk = 37`)
- Android Gradle Plugin 9.3.1 with built-in Kotlin
- Kotlin/Compose compiler plugin 2.3.21
- Gradle 9.5.0 distribution metadata with SHA-256 verification
- `versionName = 2.0.0`
- Java 17 application bytecode
- Jetpack Compose native shell around the bundled KasSee WebView

## Architecture

The live native surface is deliberately small:

- `app/` — activity, dependency composition, theme, and hardened `WebView` host.
- `domain/weather/` — weather-cover data and hidden-unlock policy only.
- `features/cover/` — functional weather privacy/decoy cover.
- `features/settings/` — mobile-only security and decoy-launch settings.
- `features/root/MobileOverlayScreen.kt` — native overlay routing above KasSee.
- `infrastructure/security/` — biometric/device-credential application lock.
- `infrastructure/network/` — weather service/facade only.
- `infrastructure/persistence/` — appearance, weather-cover settings/cache only.
- `app/build/generated/kassigner-runtime/` — Gradle-owned KasSee runtime staging. The Android build combines the authored KasSee Web UI with generated WASM/package output there, then exposes it as generated `assets/kassee/` input without writing into `app/src/main/`.

The retired native wallet/send/receive/activity/UTXO/scanner stacks, wallet persistence, native resolver catalog, transaction bridge, and native QR dependencies are intentionally absent. KasSee is the sole wallet/transaction/QR runtime.

## KasSee runtime

A normal Gradle build compiles the current `apps/kassee-web` WASM module and creates a generated `assets/kassee/` tree containing the complete KasSee UI plus the generated `pkg/` runtime. `MainActivity` serves that tree through `WebViewAssetLoader` at the app-local HTTPS origin `https://appassets.androidplatform.net/assets/kassee/index.html`.

The WebView disables file/content access and mixed content, keeps debugging restricted to debug builds, confines in-app navigation to the app-assets host, and forwards external HTTP(S) navigation to the platform browser. The only JavaScript bridge is the narrow mobile-settings entry point; wallet and transaction semantics stay inside KasSee.

## Native-only additions retained

Android continues to provide the mobile functionality that is not part of the web wallet itself:

- biometric/device-credential application locking;
- recents/switcher privacy handling;
- configurable weather decoy/privacy cover and hidden-tap unlock behavior;
- mobile security/decoy settings;
- application appearance integration;
- Android camera permission and file-picker mediation requested by the hosted KasSee UI.

## Public build and quality commands

From the repository root:

```bash
make android
make android-test
make android-qa
make android-release
```

`make android` builds the API-37 Debug APK. `make android-test` runs the Debug unit tests. `make android-qa` runs the Android-focused architecture, Gradle unit tests, optional standalone Kotlin CLI smoke test, CRAP, instrumentation, and enumerated mutation gates. When the standalone `kotlinc` CLI is unavailable, that duplicate portable smoke test is reported as skipped rather than failing the command; the equivalent weather-unlock policy remains covered by the authoritative Gradle JUnit suite. `make android-release` builds the optimized Release APK; publisher signing remains external to the repository. The lower-level Android QA helpers live under `qa/checks/android/`, but they are implementation details rather than public Make targets.

## Android Studio workflow

From a fresh extracted repository, use the platform helper when you want the project opened in Android Studio after a verified Debug build:

```bash
# Linux
./scripts/linux/build/android-studio.sh
```

```powershell
# Windows PowerShell
.\scripts\windows\build\android-studio.ps1
```

The helper verifies Android API 37, the repository-pinned Android Studio/Gradle JVM requirement, Rust/rustup, and the pinned Gradle distribution; builds the complete Debug APK including KasSee; verifies the bundled KasSee assets; and opens the Android project in Android Studio. KasSee does not need to be built manually first.

## Android platform build

The repository intentionally does not commit generated Gradle/WASM outputs. The Gradle distribution metadata is pinned in `gradle/wrapper/gradle-wrapper.properties`, including the verified binary SHA-256; the source archive does not vendor a generated `gradle-wrapper.jar`. The public Make wrappers prepare and verify that pinned Gradle distribution in repository-local build state, so a globally installed Gradle is not required.

Set `ANDROID_SDK_ROOT` (or `ANDROID_HOME`) to an SDK containing `platforms/android-37`, and make the required Rust/rustup toolchains available. Then run `make android`, `make android-test`, `make android-qa`, or `make android-release` as appropriate. The Android application source/bytecode compatibility level remains Java 17, but the repository-owned Gradle Daemon JVM criteria require JDK 25 for every command-line Gradle build and test. The Linux and Windows build wrappers use an existing exact JDK 25 when available and otherwise download the managed JDK 25 into the user's KasSigner tool cache with SHA-256 verification before starting Gradle. The native installers (`./install.sh` / `.\install.ps1`) provision the same managed JDK proactively. This is a Gradle runtime requirement, not a change to the app's Java 17 bytecode target.

Successful Debug and Release builds print the exact APK path. The normal locations are:

```text
apps/kassee-android/app/build/outputs/apk/debug/
apps/kassee-android/app/build/outputs/apk/release/
```

Unit tests print the HTML report path when Gradle produces it.

## Android Studio local state

Android Studio creates machine-local `.idea/`, `.kotlin/`, `local.properties`, and sometimes `*.iml` files. They are intentionally absent from KasSigner source archives, ignored by Git, and excluded from repository inventory/source scanning. Release/source archives must omit them.

`gradle/gradle-daemon-jvm.properties` is repository-owned build configuration and remains checked in. Android application bytecode/source compatibility remains Java 17.


## Distribution signing

`make android-release` builds the optimized Android Release variant, but the repository intentionally does not contain a publisher keystore or a release `signingConfig`. For Play or direct distribution, create a signed Android App Bundle/APK with the publisher-controlled upload/release key (for example through Android Studio's **Generate Signed Bundle / APK** workflow). Keep keystores and passwords outside the repository; `*.jks` and `*.keystore` are ignored.

Google Play deployments should normally use Play App Signing with a separately protected upload key. Distribution signing material is release-operator state and is not part of KasSigner source archives.
