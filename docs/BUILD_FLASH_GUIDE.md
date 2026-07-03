<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner — Build, Sign & Flash Guide

> Step-by-step guide for building, signing, and flashing KasSigner firmware.
> Covers all three device configurations: dev Waveshare, eFuse Waveshare, and M5Stack.

## Prerequisites

- Docker Desktop installed and running
- `kassigner-toolchain:v2` Docker image present (`docker images | grep kassigner-toolchain`)
- `esptool` installed (`pip3 install esptool`)
- `espflash` installed (`cargo install espflash`)
- ESP Rust toolchain installed (for local builds only)
- RSA signing key at `<your_secure_boot_key>.pem` (eFuse devices only)
- Schnorr signing key at `<your_signing_key>.bin` (optional, for signature verification)

## 1. Docker Reproducible Build (Both Targets)

This produces binaries with converged self-verifying hashes. No signing keys needed. See [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md) for why reproducibility matters and how to verify a release.

```bash
cd /path/to/KasSigner

# Build (includes hash convergence — 3 passes per target)
docker build -t kassigner-build:latest . 2>&1 | tee docker_build.log

# Verify reproducibility (optional — run a second time with --no-cache)
docker build --no-cache -t kassigner-build:verify . 2>&1 | tee docker_verify.log

# Compare hashes — should be identical
docker run --rm kassigner-build:latest
docker run --rm kassigner-build:verify
```

### Extract binaries from Docker

```bash
# Waveshare
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-waveshare.bin kassigner-waveshare.bin
docker rm ks-extract
shasum -a 256 kassigner-waveshare.bin

# M5Stack
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-m5stack.bin kassigner-m5stack.bin
docker rm ks-extract
shasum -a 256 kassigner-m5stack.bin
```

## 2. Flash — Dev Waveshare (No eFuse, No Secure Boot)

The simplest path. Uses `espflash` directly.

```bash
cd bootloader
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features skip-tests
```

This compiles, flashes, and opens the serial monitor in one command.
The device boots with `[DEV] Development mode` and hash mismatch (expected — no convergence).

### With hash convergence (optional)

```bash
cd /path/to/KasSigner
ESP_HAL_CONFIG_PSRAM_MODE=octal ./tools/build_with_hash.sh
```

Or with Schnorr signature:

```bash
ESP_HAL_CONFIG_PSRAM_MODE=octal ./tools/build_with_hash.sh --key <your_signing_key>.bin
```

Then flash:

```bash
cd bootloader
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/kassigner-bootloader
```

## 3. Flash — eFuse Waveshare (Secure Boot V2)

**IMPORTANT:** eFuse devices reject `espflash flash`. You must use `esptool` for flashing
and `espflash monitor --no-stub` for serial monitoring.

### Option A: Docker binary + RSA signature (reproducible, no Schnorr)

```bash
# 1. Extract Docker binary (already hash-converged)
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-waveshare.bin kassigner-waveshare.bin
docker rm ks-extract

# 2. Verify hash matches Docker output
shasum -a 256 kassigner-waveshare.bin

# 3. Sign with RSA key for Secure Boot
python3 -m espsecure sign_data --version 2 \
  --keyfile <your_secure_boot_key>.pem \
  --output kassigner-waveshare-signed.bin \
  kassigner-waveshare.bin

# 4. Flash
python3 -m esptool --port /dev/cu.usbmodem21201 --baud 460800 \
  write_flash 0x10000 kassigner-waveshare-signed.bin

# 5. Monitor (must use --no-stub for eFuse devices)
espflash monitor --port /dev/cu.usbmodem21201 --no-stub
```

Boot log will show:
- `secure boot verification succeeded` ✅
- `Code segment hash: OK` ✅
- `Build not signed` (no Schnorr — expected for Docker builds)

### Option B: Local build + Schnorr + RSA (full signature stack)

`tools/build_with_hash.sh` runs the 3-pass hash convergence and Schnorr signing for you:

```bash
export ESP_HAL_CONFIG_PSRAM_MODE=octal
./tools/build_with_hash.sh --key <your_signing_key>.bin
```

Then generate the flashable image, sign it with your RSA Secure Boot key, flash, and monitor:

```bash
cd bootloader
espflash save-image --chip esp32s3 \
  target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
  kassigner-app.bin

# Sign with RSA key for Secure Boot
python3 -m espsecure sign_data --version 2 \
  --keyfile <your_secure_boot_key>.pem \
  --output kassigner-app-signed.bin \
  kassigner-app.bin

# Flash + monitor (eFuse devices require --no-stub)
python3 -m esptool --port /dev/cu.usbmodem21201 --baud 460800 \
  write_flash 0x10000 kassigner-app-signed.bin
espflash monitor --port /dev/cu.usbmodem21201 --no-stub
```

Boot log will show `secure boot verification succeeded`, `Code segment hash: OK`, and `Signature present` (Schnorr verified).

<details>
<summary>Manual 3-pass convergence (what build_with_hash.sh automates)</summary>

Build, save-image, and gen-hash in a loop until the hash is stable:

```bash
export ESP_HAL_CONFIG_PSRAM_MODE=octal
cd bootloader && cargo build --release --features skip-tests && cd ..
espflash save-image --chip esp32s3 \
  bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
  bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader.bin
cargo run --manifest-path tools/Cargo.toml --bin gen-hash -- \
  bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader.bin \
  <your_signing_key>.bin
# Repeat build -> save-image -> gen-hash until gen-hash reports the same hash twice (CONVERGED).
```
</details>

## 4. Flash — M5Stack CoreS3 / CoreS3 Lite

```bash
cd bootloader
cargo run --release --no-default-features --features m5stack,skip-tests
```

Or from Docker binary:

```bash
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-m5stack.bin kassigner-m5stack.bin
docker rm ks-extract

python3 -m esptool --port /dev/cu.usbmodem21201 write_flash 0x10000 kassigner-m5stack.bin
espflash monitor
```

## 5. Build KasSee Web (Companion Wallet)

KasSee ships with pre-built WASM in `kassee/web/pkg/` and works out of the box — open `kassee/web/index.html` in any modern browser. To rebuild from source, see **Building KasSee from source** in the README.

## Troubleshooting

### `espflash flash` fails on eFuse device
eFuse devices with Secure Boot reject `espflash flash`. Use `esptool` instead:
```bash
python3 -m esptool --port /dev/cu.usbmodem21201 write_flash 0x10000 <signed.bin>
```

### `espflash monitor` fails on eFuse device
Use `--no-stub` flag:
```bash
espflash monitor --port /dev/cu.usbmodem21201 --no-stub
```

### Device stuck in download mode (`boot:0x0`)
Unplug USB, wait 5 seconds, replug. Don't hold any buttons during power-on.

### SRAM self-test crashes on eFuse board
Build with `--features skip-tests`. The 4MB flash partition layout on some boards
causes stack pressure during the SRAM write test.

### Hash mismatch at boot
Run `build_with_hash.sh` or the manual 3-pass convergence. Plain `cargo build`
without hash convergence will always show hash mismatch.

### `cargo build` doesn't recompile after changing constants
```bash
touch bootloader/src/main.rs  # or any file in the changed module
cargo build --release
```

### Docker `cat` produces oversized binary
Use `docker cp` instead of `docker run cat`:
```bash
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-waveshare.bin .
docker rm ks-extract
```

## Security Layers Summary

| Layer | What | Verified by | Required for |
|-------|------|-------------|-------------|
| RSA-3072 Secure Boot | ROM verifies bootloader + app signature | ESP32-S3 silicon | eFuse devices only |
| SHA-256 Hash | Firmware embeds its own hash, verifies at boot | KasSigner app code | All devices |
| Schnorr Signature | Developer signs the firmware hash | KasSigner app code | Optional (dev key) |
| Docker Reproducibility | Anyone can rebuild and verify identical binary | Binary hash comparison | Public verification |

## Key Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Reproducible build with hash convergence |
| `tools/build_with_hash.sh` | Local build with hash convergence + optional Schnorr signing |
| `tools/gen_hash.rs` | Computes code segment hash, optionally signs, writes `firmware_hash.rs` |
| `bootloader/src/firmware_hash.rs` | Auto-generated — embedded hash + signature (DO NOT EDIT) |
| `<your_secure_boot_key>.pem` | RSA-3072 key for Secure Boot (KEEP OFFLINE, NEVER COMMIT) |
| `<your_signing_key>.bin` | 32-byte Schnorr key for firmware signature (KEEP OFFLINE, NEVER COMMIT) |
