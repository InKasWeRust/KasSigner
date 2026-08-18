<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner: Build, Sign & Flash Guide

> Step-by-step guide for building, signing, and flashing KasSigner firmware.
> Covers dev and eFuse Waveshare, and dev and eFuse M5Stack CoreS3 Lite.

## Prerequisites

- Docker Desktop installed and running
- `kassigner-toolchain:v3` Docker image present (`docker images | grep kassigner-toolchain`)
- `esptool` installed (`pip3 install esptool`)
- `espflash` installed (`cargo install espflash`)
- ESP Rust toolchain installed (for local builds only)
- RSA signing key at `<your_secure_boot_key>.pem` (eFuse devices only)
- Schnorr signing key at `<your_signing_key>.bin` (optional, for signature verification)

## 1. Docker Reproducible Build

Every input to this build is pinned, so the same source produces the same
bytes on any machine. See [REPRODUCIBLE_BUILD.md](REPRODUCIBLE_BUILD.md) for
what is pinned and how a third party verifies a release.

### Build the toolchain image first

The firmware compiles inside a frozen toolchain image, which does not exist
until you build it. Skipping this step fails immediately with
"kassigner-toolchain:v3 not found".

```bash
cd /path/to/KasSigner
docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v3 .
```

Roughly 8 minutes, once. `--platform linux/amd64` is required, including on an
ARM Mac: it is what makes output identical regardless of host architecture. If
you have an old `kassigner-toolchain:v2`, it predates the pinning and will not
reproduce these hashes. Build v3 and use that.

### Build the firmware

Without a key, three unsigned targets. Signed targets skip:

```bash
docker build --platform linux/amd64 -t kassigner-build .
docker run --rm kassigner-build
```

With the key, all six, unsigned first then signed:

```bash
docker build --platform linux/amd64 \
  --secret id=signkey,src=/path/to/dev_signing_key.bin \
  -t kassigner-build .
docker run --rm kassigner-build
```

Twelve images in total: Waveshare, Waveshare AF and M5Stack, each as signed
and unsigned, each as app-only and full-flash. The run prints the
code-segment hash per configuration and the SHA-256 of every file.

**Prune before a release build.** `docker builder prune -af` first. Docker
caches `RUN` layers by command text, and mounting a secret does NOT invalidate
them, so a signed build after an unsigned one can silently reuse the layers
where the signed targets skipped. Verified 2026-08-03: with a full prune, one
run produced all twelve, and the six unsigned hashes matched an earlier
independent build exactly.

**Determinism verified 2026-08-03**: a full rebuild after `docker builder
prune -af` produced byte-identical hashes for every target.

### Signed vs unsigned

Passing `--secret id=signkey,src=/path/to/dev_signing_key.bin` writes a real
Schnorr signature into `bootloader/src/firmware_hash.rs`.

**In a dev build the signature never reaches the binary.**
`FIRMWARE_SIGNATURE` is a Rust `const`, and consts have no storage: they exist
only where they are used. Its only use is inside `verify_signature()`, which a
dev build never reaches, so the compiler drops the function and the 64 bytes
with it. Measured: signed and unsigned dev builds are byte-identical, and the
signature bytes appear in none of the images.

**A `production` build embeds it, and that changes the code segment.**
Measured on Waveshare: 552396 bytes signed against 552388 unsigned, and
different code-segment hashes (`fe280831...` signed, `c87efe56...` unsigned).
So a verifier compares their unsigned build against the published UNSIGNED
hashes. Comparing unsigned against signed will never match and means nothing.

Every released image is therefore a production build. Development builds are
for developers, via `cargo run`, and no hashes are published for them.

### Convergence

The firmware embeds a hash of its own code segment, so writing the hash
changes the thing being hashed. The build iterates five times and asserts the
last two passes agree.

Measured: signed settles at pass 2, unsigned at pass 3. Three passes was the
previous assumption and had never been checked. A configuration needing four
would have shipped a binary whose embedded hash did not match its own code,
which in a production build halts at boot. The assertion turns that into a
failed build.

### Extract binaries from Docker

```bash
docker create --name ks-out kassigner-build
for f in kassigner-waveshare kassigner-waveshare-af kassigner-m5stack; do
  docker cp ks-out:/build/$f.bin .
  docker cp ks-out:/build/$f-full.bin .
done
docker rm ks-out
shasum -a 256 kassigner-*.bin
```

Replace `$f` with `$f-unsigned` for the verification set.

**Do not flash an unsigned image.** It runs in production mode with no valid
signature, fails verification, and halts at boot. Unsigned images exist to be
hashed.

## 1a. USB state: dev builds vs production builds

This catches people out, so it is worth stating exactly. Measured on hardware
2026-08-03, not inferred from the code.

### Dev builds: USB stays open

`post_boot_lockdown()` clears two pad-configuration bits and nothing else. The
USB Serial/JTAG peripheral keeps running, the serial monitor works, and
`cargo run` reflashes normally. This is the normal working mode.

### Production builds: USB closes a second or two into boot

Under `--features production` the same function gates the USB Serial/JTAG
clock (`SYSTEM_PERIP_CLK_EN1_REG` bit 10, `SYSTEM_USB_DEVICE_CLK_EN`) and
holds the peripheral in reset. Register and bit confirmed against ESP32-S3 TRM
v1.2, and confirmed working on BOTH boards: `esptool chip_id` fails with "No
serial data received" on a running production device.

What you actually see on macOS: **the `/dev/cu.usbmodem*` node stays present**,
but espflash fails at `Connecting...`. The device node is stale; there is no
live endpoint behind it. Do not take the node's presence as evidence USB is
alive.

Note the timing. The gate closes AFTER firmware verification, not at reset, so
there is a window of a second or two at the start of every boot where USB is
live. This matters twice:

- It is why repeatedly replugging the board while espflash retries sometimes
  succeeds. You are racing the lockdown, and you can win.
- It means "USB is dead in production" is stronger than what the hardware
  does. A host that retries can hit the same window.

There is also no serial output at all from a production build: `production`
implies `silent`. A dead port and a silent log together look like a failed
flash. They are not.

### Reflashing a production device

Enter download mode, which stops the application from running at all, so
nothing gates anything. **The same procedure works on both boards**, and it
starts from a powered-off device:

1. Unplug USB (the device must be off)
2. Press and hold the BOOT button (both boards have one)
3. Plug USB in while still holding
4. Release the button

Verified on Waveshare 2026-08-03 and on a Secure Boot provisioned M5Stack CoreS3 Lite running production firmware 2026-08-18.

Holding the button and tapping RESET with the cable already connected does NOT
work. The board has to be powered off first: GPIO0 is sampled as the chip
comes out of reset, and a running device never gets there.

You will know you are in download mode because the screen stays blank and the
boot log reads `boot:0x0 (DOWNLOAD(USB/UART0))`, then `waiting for download`.
After flashing, press CTRL+R in the monitor or tap RESET to leave download
mode and run the firmware.

`espflash`'s automatic reset does not help here. On the ESP32-S3 those control
lines are carried by the USB Serial/JTAG peripheral itself, so once it is
gated there is nothing left to receive the request.

To confirm a device is genuinely gated rather than merely quiet:

```bash
python3 -m esptool --port /dev/cu.usbmodemXXXXX chip_id
```

On a running production device this fails with "No serial data received" even
though the port node is still listed. After the download-mode sequence it
connects and reports the MAC. Verified on both boards.

### Reading the firmware hash on the device

The boot screen shows the hash embedded at build time, not one computed at
boot.

**On a production build that number is trustworthy**, because verification is
enforced: if the embedded hash did not match the running code the device would
halt instead of showing you anything. Reaching the UI is itself the proof, and
the screen confirms in teal.

**On a dev build it is just a printed constant.** Verification runs but does
not enforce. The log says `[DEV] WARNING: Hash mismatch ... continuing` and
the screen marks the build in orange. Do not verify against a dev build.

### Warning: do not burn `DIS_DOWNLOAD_MODE`

That eFuse permanently removes download mode. Combined with a production
build, which gates USB a second or two into boot, a device would have no
recovery path at all.

**Secure Boot does not close download mode**, so provisioning a board does not
cost you the ability to update it. Verified on a provisioned board
2026-08-03: with `SECURE_BOOT_EN`, `DIS_PAD_JTAG` and `DIS_USB_JTAG` burned,
every download-mode fuse read `False` and the board flashed normally. Flashing
stays open because it must; what Secure Boot enforces is that only firmware
signed with the burned key digest will run.

`ENABLE_SECURITY_DOWNLOAD` narrows download mode to flash writes only and
still permits signed updates, but it has not been tested on this hardware.
See `EFUSE_RUNBOOK.md` before burning it.

## 2. Flash: Dev Waveshare (No eFuse, No Secure Boot)

The simplest path. Uses `espflash` directly.

```bash
cd bootloader
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features ov5640-af
```

Drop `ov5640-af` if the plain OV5640 or OV2640 module is fitted. This compiles, flashes, and opens the serial monitor in one command. The boot self-tests and crypto known-answer tests run and print `All crypto KATs passed`; do not add `skip-tests` to a flash you intend to use.
The device boots with `[DEV] Development mode` and hash mismatch (expected. No convergence).

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

## 3. Flash: eFuse Waveshare (Secure Boot V2)

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
- `Build not signed` (no Schnorr. Expected for Docker builds)

### Option B: Local build + Schnorr + RSA (full signature stack)

`tools/build_with_hash.sh` runs the hash convergence (up to five passes, stops when two agree) and Schnorr signing for you:

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

## 4. Flash: Dev M5Stack CoreS3 Lite (No eFuse, No Secure Boot)

```bash
cd bootloader
cargo run --release --no-default-features --features m5stack
```

Or from Docker binary:

```bash
docker create --name ks-extract kassigner-build:latest
docker cp ks-extract:/build/kassigner-m5stack.bin kassigner-m5stack.bin
docker rm ks-extract

python3 -m esptool --port /dev/cu.usbmodem21201 write_flash 0x10000 kassigner-m5stack.bin
espflash monitor
```

## 5. Flash: eFuse M5Stack CoreS3 Lite (Secure Boot V2)

Same chip-level procedure as the Waveshare in section 3, different artifacts.
Read the Board Profiles section of [EFUSE_RUNBOOK.md](EFUSE_RUNBOOK.md) first.
The CoreS3 Lite has working RST and BOOT buttons and enters download mode the
same way as the Waveshare; with a battery connected, unplugging USB does not
power the chip down, so power it off before the BOOT-button sequence.

Secure Boot V2 signs each image separately, so the merged `-full.bin` cannot be
signed as a unit. Extract the second-stage bootloader at its exact length:

```bash
python3 tools/extract_bootloader.py kassigner-m5stack-full.bin
# prints chip ID, segments, length, SHA-256, and the signed size
# -> kassigner-m5stack-bootloader.bin

python3 -m espsecure sign_data --version 2 \
  --keyfile <your_secure_boot_key>.pem \
  --output kassigner-m5stack-bootloader-signed.bin \
  kassigner-m5stack-bootloader.bin

python3 -m espsecure sign_data --version 2 \
  --keyfile <your_secure_boot_key>.pem \
  --output kassigner-m5stack-signed.bin \
  kassigner-m5stack.bin

python3 -m esptool --port /dev/cu.usbmodem21201 --baud 460800 write_flash \
  0x0     kassigner-m5stack-bootloader-signed.bin \
  0x10000 kassigner-m5stack-signed.bin

espflash monitor --port /dev/cu.usbmodem21201 --no-stub
```

Confirm the boot before burning any eFuse. The signed images boot on an
unprovisioned board, which is what makes the whole flashing path testable while
it is still reversible.

Verified on both boards. On a provisioned board the ROM adds two lines ahead of
the bootloader banner:

```
Valid secure boot key blocks: 0
secure boot verification succeeded
```

Note that `espsecure sign_data` uses RSA-PSS, so signing the same input twice
produces different bytes. Hash the inputs, not the `*-signed.bin` outputs.

An eFuse device is still reflashed with plain `esptool write_flash`; Secure Boot
does not close download mode. If the first connect fails with "No serial data
received", that is the production build gating USB a second into boot. Retry, or
enter download mode: unplug USB, hold BOOT, plug USB, release.

## 6. Build KasSee Web (Companion Wallet)

KasSee ships with pre-built WASM in `kassee/web/pkg/` and works out of the box. Open `kassee/web/index.html` in any modern browser. To rebuild from source, see **Building KasSee from source** in the README.


---

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

### Boot self-tests halt
If the device halts during Phase 1 or the crypto known-answer tests, that is a
defect: report it with the serial log. Do not build with `skip-tests` to get past
it; a shipped image cannot be built that way.

### Hash mismatch at boot
Run `build_with_hash.sh` (or the Docker build). Plain `cargo build` without
hash convergence will always show a hash mismatch.

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
| Schnorr Signature | Developer signs the firmware hash | KasSigner app code | Required in `production` builds; optional in dev |
| Docker Reproducibility | Anyone can rebuild and verify identical binary | Binary hash comparison | Public verification |

## Key Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Reproducible build with hash convergence |
| `tools/build_with_hash.sh` | Local build with hash convergence + optional Schnorr signing |
| `tools/gen_hash.rs` | Computes code segment hash, optionally signs, writes `firmware_hash.rs` |
| `bootloader/src/firmware_hash.rs` | Auto-generated. Embedded hash + signature (DO NOT EDIT) |
| `<your_secure_boot_key>.pem` | RSA-3072 key for Secure Boot (KEEP OFFLINE, NEVER COMMIT) |
| `<your_signing_key>.bin` | 32-byte Schnorr key for firmware signature (KEEP OFFLINE, NEVER COMMIT) |
