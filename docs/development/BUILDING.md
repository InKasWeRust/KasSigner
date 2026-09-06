[KasSigner](../../README.md) › [Documentation](../README.md) › Development › Building

<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- License: GPL-3.0-only -->

# Building and testing

GNU Make is the small, stable developer interface. Targets describe user intentions; detailed implementation/debug steps remain under `scripts/`, `tools/`, and `qa/`.

## Normal development

```bash
make help
make test
```

`make test` runs the fast host/browser contributor suite. It deliberately runs **no Android, iOS/Xcode, physical-device, or HIL tests**, and it does not run coverage/CRAP generation, mutation, fuzz campaigns, historical regression-policy suites, branch ratchets, architecture policing, firmware build/lint matrices, QEMU, or benchmarks.

Run the specialist assurance umbrella explicitly when needed:

```bash
make qa
```

`make qa` is intentionally expensive and authoritative for **all non-hardware tests**. It runs strict coverage/CRAP first, then immediately executes the pinned stable Core CI gate: formatting, workspace/all-target Clippy with warnings denied, strict `make test`, and `git diff --check`. The complete Core CI transcript is retained at `target/qa/core-ci/core-ci.log`. After that gate passes, full QA continues with strict architecture/security/regression work, browser/mobile/QEMU/software integration, real-node and funded/interactive testnet E2E before long unattended campaigns, benchmarks, fresh mutation certification, and fuzzing last. Platform-ineligible mobile stages report an explicit SKIP. Physical-device/HIL work remains explicit through `make test-hardware`, `make workflow-e2e`, and `make workflow-hil`. To continue a failed full run without replaying earlier green stages, use `make qa RESUME_FROM=<stable-step-id>`; the named step is rerun and the remaining canonical QA catalog follows.

## KasSee

```bash
make kassee
```

The canonical runnable site is staged under `target/kassee-web/site/`. For direct local development, the same build also mirrors the generated WASM bindings into `apps/kassee-web/web/pkg/`, so serving `apps/kassee-web/web/` works immediately after `make kassee`. The local `pkg/` mirror is generated/ignored and is not source-archive content.

## iOS

```bash
make ios
make ios-release
make ios-test
make ios-qa
```

`make ios` is a real Xcode Debug build and prints the resulting `target/ios/DerivedData/Build/Products/Debug-iphonesimulator/KasSigner.app` path. `make ios-release` creates and prints `target/ios/KasSigner.xcarchive`; `make ios-test` runs XCTest/XCUITest and writes `target/ios/KasSignerTests.xcresult`. These commands fail clearly outside macOS/Xcode. `make ios-qa` runs the real iOS tests plus the strict iOS architecture/CRAP/mutation gates. The repository does not pin an Apple Team ID; a device/App Store archive requires the publishing team's ID, for example `KASSIGNER_IOS_DEVELOPMENT_TEAM=ABCDE12345 make ios-release`.

On macOS, `./scripts/mac/install.sh` bootstraps the iOS-only prerequisites and `./scripts/mac/run-ios.command` builds, installs, and launches KasSigner in the configured iOS Simulator. The Finder-friendly `scripts/mac/setup-macos.command` and `apps/kassee-ios/setup-macos.command` wrappers use the same setup path.

## Android

```bash
make android
make android-release
make android-test
make android-qa
```

These are real Gradle/API-37 operations. `android` builds Debug, `android-release` builds the optimized Release variant, `android-test` runs Debug unit tests, and `android-qa` adds the strict Android architecture/CRAP/instrumentation/mutation gates plus an optional standalone Kotlin CLI smoke test. If `kotlinc` is not on `PATH`, that duplicate smoke test is skipped; the equivalent policy remains exercised by the Gradle JUnit suite. The Make wrappers prepare the pinned Gradle distribution in repository-local build state and successful Debug/Release builds print the exact APK path under `apps/kassee-android/app/build/outputs/apk/`. Distribution signing is intentionally publisher-controlled: the repository contains no release keystore/signing configuration, and `*.jks`/`*.keystore` are ignored.

## Firmware and devices

`BOARD` defaults to `m5stack`; supported public board values are `m5stack` and `waveshare`.

```bash
make firmware
make firmware BOARD=waveshare

make flash
make flash BOARD=waveshare
make flash PORT=/dev/ttyACM0
make flash BOARD=waveshare PORT=/dev/ttyACM0

# Flash an existing signed merged normal-release image only (no rebuild/provisioning)
make flash-release
make flash-release BOARD=waveshare PORT=/dev/ttyACM0 RELEASE_DIR=release

make firmware-mirror
make test-hardware BOARD=m5stack PORT=/dev/ttyACM0
make workflow-e2e BOARD=m5stack PORT=/dev/ttyACM0
make workflow-hil BOARD=m5stack PORT=/dev/ttyACM0
```

`firmware-mirror` preserves the original Waveshare mirror functionality. Firmware feature flags themselves remain documented in the firmware manifest/docs; there is no public `firmware-features` Make command.

QEMU remains explicit:

```bash
make firmware-qemu-setup
make firmware-qemu
make firmware-qemu-test
```


### Owner-authorized CoreS3 application

After generating an RSA-3072 owner key outside the repository, build the enrollment record and owner-signed application with:

```bash
make owner-firmware OWNER_KEY=/secure/offline/path/owner.pem
```

The generated `OWNERKEY.KAS` and `OWNERFW.BIN` are placed under `target/owner-firmware/`. Back up `owner.pem` before enrollment; it cannot be reconstructed from the enrollment record, device/eFuse state, or a signed image. Owner-key enrollment is an explicit CoreS3 provisioning action before the Settings-only Pop It! flow; `secure-provisioning` uses vendor + optional owner authority, while `secure-owner-only` requires the owner key as the sole authority; normal release firmware omits that UI/path entirely, while development firmware only simulates the irreversible path. See [Pop It! and owner-authorized firmware](../security/POP_IT_SECURE_BOOT.md).

## Release

```bash
make release
make release SIGNING_KEY=/path/to/key.bin RELEASE_DIR=release
```

`make release` builds the normal non-destructive production profile (`production` without `secure-provisioning`): Pop It!, owner-authority UI, and irreversible boot-control staging are not compiled into that firmware. `make flash-release` consumes only the existing signed merged `*-full.bin` plus its `SHA256SUMS`; it does not build, provision eFuses, invoke the special secure profile, or fall back to unsigned artifacts. The dedicated `make secure-provisioning` and `make secure-owner-only` targets build `m5stack,secure-provisioning` and `m5stack,secure-owner-only` respectively; neither target flashes hardware. Both bootloaders defer irreversible flash-encryption/Secure-Boot/anti-rollback changes until explicit Pop It consent. The owner-only variant requires only `OWNER_KEY` and does not require the vendor Schnorr release key.

A production release is always reproducible. The intended release workflow is `make test` → `make qa` → `make test-hardware` → `make workflow-e2e` → `make workflow-hil` → `make release` → `make release-readiness`. The reproducible-build implementation lives under `scripts/` and `tools/`; `make release` builds and manifest-verifies the release artifacts without replaying the preceding test stages. `make release-readiness` is the separate fail-closed gate for operator-supplied source/artifact-bound signed evidence.

## Generated output ownership

Temporary/generated output, including run-specific QA and hardening evidence, belongs under the repository-root `target/qa/` tree (or Gradle `build/generated` for Android); distributables belong under `release/`, and authored source/contracts stay in the repository.

For detailed device behavior, timeouts, UART/HIL evidence, and resume tranches, see [Build, Sign & Flash](BUILD_FLASH_GUIDE.md) and the hardware/HIL documentation rather than `make help`.
