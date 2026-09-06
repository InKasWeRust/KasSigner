<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner Build, Sign & Flash Guide

This guide covers KasSigner 2.0.0 build, signing, flashing, and production-security workflows. **M5Stack CoreS3 is hardware-tested.** Waveshare and Waveshare-AF remain source-supported but require their own hardware-in-loop qualification before production use. Production eFuse provisioning is irreversible; follow [EFUSE_RUNBOOK.md](../EFUSE_RUNBOOK.md).

## 1. Prepare the host

Linux and Windows have complete native development bootstraps:

```bash
# Linux
./install.sh
```

```powershell
# Windows PowerShell
.\install.ps1
```

Both install/check the pinned Rust and ESP toolchains plus the QA/build
prerequisites. macOS `./install.sh` is intentionally different: it preserves
the original interactive Waveshare firmware build/erase/flash workflow and is
not the full Linux/Windows QA bootstrap.

## 2. Development firmware

From the repository root, GNU Make is the supported native façade on Linux and
Windows:

```text
make firmware                  # M5Stack CoreS3 development build; no flash
make firmware BOARD=waveshare  # Waveshare development build; no flash
make flash BOARD=m5stack PORT=/dev/ttyACM0 # explicit development flash
make test                      # fast host/browser contributor suite; no mobile/HIL
make qa                        # authoritative all non-hardware QA, including mobile/QEMU/node/E2E
```

For direct Cargo use, the firmware workspace is `apps/signer-firmware/` and its
pinned ESP toolchain is selected by its toolchain configuration. Do not replace
the repository pins with a host-global compiler version.

## 3. Reproducible release images

The release path is Docker-based internally and intentionally separate from local
convenience builds, but the public interface remains Make:

```bash
make release
# signed release artifacts:
make release SIGNING_KEY=/path/to/dev_signing_key.bin
```

The implementation passes the signing-key file through the BuildKit secret path documented in [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md). Never bake a private signing key into an image, layer, or source archive. `make release` stops after artifact/manifest verification; production publication additionally requires `make release-readiness` with the external signed evidence described in [Release evidence](../../qa/release/README.md).

The reproducible pipeline builds app-only and full-flash artifacts for
Waveshare, Waveshare-AF, and M5Stack, and performs the repository's firmware-hash
convergence checks. Generated identity bytes remain in flash rodata, and passes 2 through 5
must have an identical executable code hash. Unsigned verification images are not production-signed
firmware.

## 4. Development flashing

Development builds and device writes are deliberately separate public operations. A build
command never opens a serial port:

```bash
make firmware
```

To build and flash an unprovisioned CoreS3 development image explicitly:

```bash
make flash BOARD=m5stack PORT=/dev/ttyACM0
```

The flash target performs the same five-pass firmware-hash convergence and final-image
verification as `make firmware`, uses the repository-owned CoreS3 partition profile,
and supplies espflash with the explicit CoreS3 connection profile `--chip esp32s3 --before
usb-reset`. It flashes the development ELF and immediately enters espflash's live UART
monitor so the complete ROM/bootloader/KasSigner startup log is visible. Press `CTRL+C` to
leave the monitor after the device reaches the expected screen.

M5Stack CoreS3 does **not** use espflash's generic application layout. Its repository-owned 16 MiB table is `apps/signer-firmware/partitions/m5stack-cores3.csv`. It contains two 2 MiB OTA application slots (`ota_0` at `0x10000`, `ota_1` at `0x210000`), a 2 MiB owner-firmware staging partition at `0x410000`, the one-sector `kassigner_bootctl` handoff at `0x610000`, and the QA/persistent-state sectors at the top of flash. Anti-rollback intentionally uses OTA slots rather than a factory application partition.

The development firmware exposes `Settings -> Developer -> Argon2 Bench` for a manual
Argon2/PSRAM benchmark. It runs only when selected; hardware-test profiles may exercise the
same benchmark automatically as part of explicit device QA.

`make test-hardware BOARD=m5stack PORT=...` intentionally flashes the developer-only
`hardware-tests` profile. `make workflow-e2e BOARD=m5stack PORT=...` intentionally flashes
the developer-only `workflow-runtime-auto` profile on M5Stack (`workflow-test-auto` on Waveshare). Neither is production firmware, and both leave
the test image on the device after completion; use `make flash BOARD=m5stack PORT=...` to
restore the normal development image. Their serial supervision is non-interactive and restores
the caller terminal even on timeout or Ctrl-C. The connected runners retry transient transport
failures only before flash completion; their device-test timeout starts after espflash reports the
write complete. A post-flash USB/monitor drop is recovered by monitor-only attachment with
`no-reset-no-sync`, never by reflashing a possibly destructive HIL image. If the automatic
CoreS3 reset cannot enter download mode, close other serial monitors, hold RESET for about
three seconds until the internal green LED turns on, release it, then rerun the command.

`make release` produces the normal non-destructive production artifacts; it does **not** produce the CoreS3 Secure-Boot-v2 provisioning image. The opt-in CoreS3 provisioning artifacts use the explicit public profiles: `make secure-provisioning SECURE_BOOT_KEY=... SIGNING_KEY=...` for dual authority, or `make secure-owner-only OWNER_KEY=...` for the restored sole-owner model. Both commands build/sign artifacts only; neither flashes hardware. Development flashing is not a production manufacturing recipe.

## 5. Secure Boot v2 / eFuse hardware

Hardware-enforced CoreS3 deployments require **both** KasSigner's software-level signed-image
identity checks and a correctly configured ESP32-S3 Secure Boot v2 chain. The normal
non-destructive production release uses the software-verification layer without provisioning eFuses. The
second-stage bootloader must itself be built with Secure Boot v2 application
enforcement enabled. Merely appending a signature to a normal development
bootloader is not equivalent.

Before irreversible provisioning:

1. Build the exact release source with pinned inputs.
2. Build the matching ESP-IDF second-stage bootloader with Secure Boot v2 enabled.
3. Secure-pad the application image to the ESP32-S3 64 KiB MMU boundary. The repository release tooling performs this step before RSA signing.
4. Sign the padded image with the controlled Secure Boot RSA key using the pinned ESP-IDF tooling.
5. Flash the bootloader, partition table, and application at the offsets produced by that build.
6. On a sacrificial board, prove that a one-byte-modified or unsigned application is rejected.
7. If owner authority is required, enroll its RSA-3072 public-key digest before Pop It! and run the owner-authority HIL matrix.
8. Only then follow [EFUSE_RUNBOOK.md](../EFUSE_RUNBOOK.md) for irreversible eFuse operations.

Source support is not production qualification. Waveshare-family targets require separate hardware-in-loop evidence before production use.


## 6. Owner-authorized CoreS3 application firmware

Owner authority is **optional in dual `secure-provisioning` and mandatory in `secure-owner-only`**, and any enrollment must occur **before Pop It!**. Generate and protect an RSA-3072 owner key outside the repository, then build the SD enrollment record and owner-signed application with:

```bash
make owner-firmware OWNER_KEY=/secure/offline/path/owner.pem
```

Outputs are written under `target/owner-firmware/`, including `OWNERKEY.KAS`, `OWNERFW.BIN`, and hashes. `OWNERKEY.KAS` contains only the public-key digest and integrity metadata. **Back up `owner.pem` before enrollment** and keep it offline; it cannot be recovered from `OWNERKEY.KAS`, the device/eFuse digest, or `OWNERFW.BIN`, and it is never copied to the signer.

On a dedicated CoreS3 provisioning firmware, enroll through **Settings → Advanced → Owner Firmware → Enroll Owner Key** before Pop It!. In `secure-owner-only` this is mandatory and becomes digest 0; in dual `secure-provisioning` it is optional and becomes digest 1. The normal `make release` firmware intentionally has no Owner Firmware or Pop It! menu. In dual mode, Pop It! is Settings-only and explicitly warns before the user chooses the vendor-only path without owner enrollment; owner-only mode has no such bypass and refuses Pop It until enrollment succeeds. After Secure Boot is enabled, owner-signed applications can be installed through **Install from SD**. Development firmware validates/simulates these flows without writing eFuses or arming production boot-control operations. See [Pop It! and owner-authorized firmware](../security/POP_IT_SECURE_BOOT.md) for the complete build, backup, enrollment, and modified-firmware installation procedure.

## 7. KasSee and mobile apps

```text
make kassee          # KasSee Web
make android         # real Android Debug build
make android-qa      # Android tests + strict platform QA
make ios             # real Xcode Debug build (macOS/Xcode required)
make ios-qa          # iOS tests + strict platform QA
```

Android and iOS are native shells around the same KasSee runtime; they do not
maintain independent wallet/signing implementations. Successful Android builds
print the exact APK path under `apps/kassee-android/app/build/outputs/apk/`.
`make ios` prints the Debug simulator `.app` path under `target/ios/DerivedData/`,
while `make ios-release` prints `target/ios/KasSigner.xcarchive`. The iOS Xcode
build phase builds KasSee with the native macOS shell and then runs the
platform-neutral `tools/build/ios/sync_runtime.py` asset synchronizer.

## 8. Before trusting a build

- Verify the expected board target and network.
- Keep recovery words offline and test recovery with small value first.
- Verify release hashes/reproducibility where available.
- Never bypass a boot known-answer test, firmware identity failure, QR/session warning, or transaction-review warning.
- For production/eFuse hardware, require the release evidence described in `qa/release/README.md`; skipped external/HIL controls are not passes.

## Troubleshooting

**`cargo` uses the wrong compiler:** re-run the host bootstrap and confirm the
repository-pinned rustup toolchains are installed. Do not globally override the
firmware toolchain.

**Device is not detected:** use a known data-capable USB cable, reconnect the
board without holding boot buttons, and check the OS-specific serial device.

**KasSee/iOS/Android assets are missing:** run `make kassee`, `make android`, or the
appropriate iOS build on macOS. Generated WASM/mobile staging output is intentionally
not treated as authored source.

**A production image fails verification:** stop. Rebuild from pinned inputs and
compare the signed/unsigned artifact class and hashes; do not disable the check.
