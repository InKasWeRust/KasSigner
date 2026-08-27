<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner: eFuse Secure Boot Runbook

**WARNING: eFuse operations are IRREVERSIBLE. A mistake here can permanently brick the board. Read this entire document before touching any commands.**

## Overview

The ESP32-S3 has two independent security layers that use eFuses:

1. **Secure Boot v2**: ROM bootloader verifies the second-stage bootloader signature (RSA-3072 or ECDSA). Second-stage bootloader verifies the app signature.
2. **Flash Encryption**: all flash contents are encrypted with an AES-128/256 XTS key. Prevents reading firmware from flash.

KasSigner also has a **software-level** Schnorr signature check (the `features/verify.rs` + `firmware_hash.rs` system). This is independent of and complementary to the hardware secure boot.

## Architecture

```
┌─────────────────────────────────────────────────┐
│  ROM Bootloader (in silicon, immutable)          │
│  Reads SECURE_BOOT_EN eFuse                      │
│  Verifies 2nd-stage bootloader with RSA-3072     │
│  Key digest stored in eFuse BLOCK_KEY0           │
└───────────────────┬─────────────────────────────┘
                    │ signature OK
                    ▼
┌─────────────────────────────────────────────────┐
│  2nd-stage bootloader (esp-bootloader-esp-idf)   │
│  Verifies app partition signature                │
│  RSA-3072 signature appended to binary           │
└───────────────────┬─────────────────────────────┘
                    │ signature OK
                    ▼
┌─────────────────────────────────────────────────┐
│  KasSigner App                                   │
│  Software Schnorr verify (firmware_hash.rs)       │
│  This is our OWN additional layer                │
└─────────────────────────────────────────────────┘
```

## Board Profiles

Every eFuse in this runbook is chip-level and identical on both boards. Both are
ESP32-S3 with 16 MB flash and **no USB-to-UART bridge**: the USB-C connector goes
straight to the chip's native USB, D- on GPIO19 and D+ on GPIO20 on both. Both
have working RST and BOOT buttons, and the download-mode sequence is the same on
each: unplug USB, hold BOOT, plug USB in, release.

| | Waveshare ESP32-S3-Touch-LCD-2 | M5Stack CoreS3 Lite |
|---|---|---|
| PSRAM | octal (`ESP_HAL_CONFIG_PSRAM_MODE=octal`) | quad (no env var) |
| Build | `--features production` | `--no-default-features --features m5stack,production` |
| Artifacts | `kassigner-waveshare*.bin` | `kassigner-m5stack*.bin` |

Nothing else about provisioning differs. Every command in Steps 0 through 9 is
byte-identical between the two; only the image filenames change.

### Identify the board before every burn

Both boards enumerate as `/dev/cu.usbmodem*` and look alike to the tooling. An
eFuse burned into the wrong unit cannot be undone. Read the MAC first, every
time:

```bash
python3 -m esptool --port <PORT> chip_id
```

Record the MAC of each unit as you provision it, and keep that record outside
the repository.

### Note on stale screens

The display panel holds the last frame written to it. Every `espefuse` invocation drives
the chip into download mode, where the app never runs, so the panel keeps
displaying whatever it was showing. A UI frozen mid-boot after a burn is almost
always a stale frame, not a broken device. Confirm with the boot line rather than
the screen: `boot:0x2b (SPI_FAST_FLASH_BOOT)` is running normally,
`boot:0x0 (DOWNLOAD(USB/UART0))` is parked in download mode.

## Pre-flight Checklist

Before ANY eFuse operation:

- [ ] Board boots and runs KasSigner correctly
- [ ] `python3 -m espefuse summary` shows all security eFuses at default (0)
- [ ] Signing key generated and backed up to 3+ offline locations
- [ ] Flash encryption key generated (if using flash encryption)
- [ ] Signed bootloader + signed app both verified on a TEST board first
- [ ] You understand: **there is no undo**

## Step 0: Read Current eFuse State

```bash
# Check what's already burned (should all be zero/default on a fresh board)
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 summary

# Key fields to verify are at defaults:
#   SECURE_BOOT_EN = False
#   SPI_BOOT_CRYPT_CNT = 0
#   All KEY_PURPOSE_0..5 = 0 (User purposes)
#   All SECURE_BOOT_KEY_REVOKE0..2 = False
```

**STOP if any security eFuse is already set.** That board has been touched before.

## Step 1: Generate RSA-3072 Signing Key

This is the key that the ROM bootloader will use to verify firmware. It is DIFFERENT from KasSigner's Schnorr signing key (which is our software-level check).

```bash
# Generate RSA-3072 private key for Secure Boot v2
python3 -m espsecure generate_signing_key --version 2 --scheme rsa3072 \
    secure_boot_v2_key.pem

# BACK THIS UP IMMEDIATELY:
#   - USB drive in a safe
#   - Second USB drive in a different location
#   - Paper printout in sealed envelope
#
# If you lose this key, you can NEVER update firmware on this board.
```

**Optional but recommended:** Generate a second key for redundancy.

```bash
python3 -m espsecure generate_signing_key --version 2 --scheme rsa3072 \
    secure_boot_v2_key_backup.pem
```

## Step 2: Generate Public Key Digest

```bash
# Primary key
python3 -m espsecure digest_sbv2_public_key \
    --keyfile secure_boot_v2_key.pem \
    --output digest0.bin

# Backup key (if using)
python3 -m espsecure digest_sbv2_public_key \
    --keyfile secure_boot_v2_key_backup.pem \
    --output digest1.bin
```

## Step 3: Burn Key Digest to eFuse

**THIS IS IRREVERSIBLE. Triple-check the file paths.**

```bash
# Burn primary key digest to BLOCK_KEY0
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY0 digest0.bin SECURE_BOOT_DIGEST0

# If using backup key, burn to BLOCK_KEY1
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY1 digest1.bin SECURE_BOOT_DIGEST1
```

You will be prompted to type `BURN` to confirm.

## Step 4: Revoke Unused Key Slots

Any unused SECURE_BOOT_DIGEST slot MUST be revoked. If you used only digest0:

```bash
# Revoke unused slots (if only using 1 key)
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_KEY_REVOKE1

python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_KEY_REVOKE2

# If using 2 keys (digest0 + digest1), only revoke slot 2:
# python3 -m espefuse --port ... burn_efuse SECURE_BOOT_KEY_REVOKE2
```

## Step 5: Build and Sign Firmware

Two images sit in the ROM chain and both must carry an RSA-3072 signature: the
second-stage bootloader at `0x0` and the app at `0x10000`. Signing is per image,
so the merged `-full.bin` cannot be signed as a unit, and the bootloader has to
come out of it at its exact length first. `tools/extract_bootloader.py` walks the
ESP image header and segment table to find where the bootloader ends, because the
trailing `0xFF` padding up to `0x8000` would otherwise be signed with it and push
the signature sector over the partition table.

The examples below use the M5Stack artifact names. Substitute `waveshare` or
`waveshare-af` for the other boards.

```bash
# Docker produces both, per board:
#   kassigner-m5stack.bin        app only, for 0x10000
#   kassigner-m5stack-full.bin   bootloader + partition table + app

# Pull the second-stage bootloader out at its exact length. This prints its
# SHA-256 and confirms the signed size stays clear of 0x8000; it refuses to
# write the file if it does not.
python3 tools/extract_bootloader.py kassigner-m5stack-full.bin

# Sign the bootloader
python3 -m espsecure sign_data --version 2 --keyfile secure_boot_v2_key.pem \
    --output kassigner-m5stack-bootloader-signed.bin \
    kassigner-m5stack-bootloader.bin

# Sign the app
python3 -m espsecure sign_data --version 2 --keyfile secure_boot_v2_key.pem \
    --output kassigner-m5stack-signed.bin \
    kassigner-m5stack.bin

# If using a backup key, append a second signature to each
python3 -m espsecure sign_data --version 2 --keyfile secure_boot_v2_key_backup.pem \
    --append_signatures \
    --output kassigner-m5stack-signed.bin kassigner-m5stack-signed.bin
```

## Step 6: Flash Signed Firmware BEFORE Enabling Secure Boot

**CRITICAL ORDER: Flash first, THEN enable secure boot.** If you enable secure boot before flashing signed firmware, the board will refuse to boot and is bricked.

On a board that has never held a KasSigner image, write the merged image once so
the partition table at `0x8000` is in place:

```bash
python3 -m esptool --port /dev/cu.usbmodem* --baud 460800 \
    write_flash 0x0 kassigner-m5stack-full.bin
```

Then overwrite the two signed images over the top:

```bash
python3 -m esptool --port /dev/cu.usbmodem* --baud 460800 write_flash \
    0x0     kassigner-m5stack-bootloader-signed.bin \
    0x10000 kassigner-m5stack-signed.bin
```

**This is the gate.** Secure boot is not enabled yet, so a signed image that the
chain would reject still boots here, and anything that goes wrong is still
recoverable. Confirm on the monitor that the device reaches the UI and that
`Code segment hash: OK` appears, then power-cycle and confirm it a second time.
The signature block adds 4 KiB in front of nothing the running firmware reads, so
a board that boots signed-but-unenforced will boot the same way enforced.

```bash
espflash monitor --port /dev/cu.usbmodem* --no-stub
```

Do not continue to Step 7 from a board you have not just watched boot.

## Step 7: Enable Secure Boot

**POINT OF NO RETURN. After this, only signed firmware will boot.**

```bash
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_EN
```

## Step 8: Lock Down Security eFuses (Production)

For production boards, additional eFuses should be burned to prevent attacks:

```bash
# Disable JTAG (prevents debug probe access)
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse DIS_PAD_JTAG
    
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse DIS_USB_JTAG

# Disable direct boot (force secure boot path)
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse DIS_DIRECT_BOOT

# Enable secure download mode (restricts what UART download can do)
# NOT RECOMMENDED, and untested on this hardware. Read the note below in full
# before you consider it. Skipping this line costs you nothing on KasSigner.
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse ENABLE_SECURITY_DOWNLOAD
```

**On `ENABLE_SECURITY_DOWNLOAD`, and why it is the weakest item in this step.**
It restricts UART download mode to flash writes: no reading flash back, no
memory access, no stub upload. Signed firmware can still be flashed, which is
the update path this device needs.

What it defends is flash readout by someone holding the board. On KasSigner
that surface is close to empty: the firmware is public, there is no persistent
key storage, keys live in RAM and die at power-off, and only the public key
digest is in eFuse. The private signing key never touches the device. What is
actually worth stealing sits on the SD card, and no eFuse protects that.

It has also **not been verified on this hardware**. Every other fuse in this
step has. If you burn it, expect to need `--no-stub` for flashing as well as
for monitoring, and confirm the update path on a sacrificial board first.

**The recommendation is: do not burn it.** eFuses are one-way. This one buys a
defence against a readout of a flash whose contents are already published,
while risking the ability to update the device at all, on a fuse nobody here
has tested end to end. That trade is not worth making on a board holding your
keys. It stays documented rather than removed so that anyone who has already
burned it knows what to expect, and so the reasoning is on the record if it is
ever tested properly; until someone has confirmed a full flash-and-update cycle
on a sacrificial board, treat this line as an experiment and not as part of the
runbook.

**DO NOT burn `DIS_USB_SERIAL_JTAG`.** It is deliberately left unburned. Note the two fuse names differ by one word and do very different things:

| eFuse | ESP32-S3 TRM Table 5-1 | Effect |
|---|---|---|
| `DIS_USB_JTAG` | "whether the function of usb_serial_jtag that switch usb to jtag is disabled" | Closes the JTAG debug path. **Serial console still works.** Burned above. |
| `DIS_USB_SERIAL_JTAG` | "whether usb_serial_jtag function is disabled" | Disables the **whole** peripheral. No console, no flashing over USB, permanently. |

`DIS_USB_JTAG` above is what closes USB JTAG. Burning `DIS_USB_SERIAL_JTAG` as well would additionally remove the only interface for signed firmware updates and for reading boot diagnostics, and it cannot be undone.

This matches `KasSigner_Security_Architecture.pdf` section 3 (eFuse Hardening), which lists the production configuration as `DIS_PAD_JTAG = True`, `DIS_USB_JTAG = True`, `DIS_USB_SERIAL_JTAG = False` ("USB Serial preserved", by design), and KasSigner-Specific Note 3 below, which recommends preserving UART download with `ENABLE_SECURITY_DOWNLOAD`. Earlier revisions of this runbook burned it here, contradicting both.

**Step 8 is required, not optional.** `DIS_PAD_JTAG` and `DIS_USB_JTAG` are what remove debug access to a device holding key material. A board with Secure Boot burned but JTAG left open is not hardened.

**DO NOT burn `DIS_DOWNLOAD_MODE` unless you are absolutely sure.** This permanently prevents any firmware updates via UART, even signed ones. Only do this for final production units where OTA is the only update path, and KasSigner has no OTA since it is air-gapped.

The reason it is safe to leave open is worth stating: **Secure Boot does not close download mode, and it does not need to.** Verified on a provisioned board, 2026-08-03: with `SECURE_BOOT_EN`, `DIS_PAD_JTAG` and `DIS_USB_JTAG` all burned, every download-mode fuse read `False` and the board flashed normally. Flashing stays open because it must; what Secure Boot enforces is that only firmware signed with the burned key digest will *run*. An attacker can write whatever they like and the ROM refuses to execute it.

That is also what anchors the software verification in `features/verify.rs`. The hash, the signature and the public key all live inside the image being checked, so on their own they cannot stop someone who replaced the image and removed the check. The ROM check happens first and cannot be removed.

**Note the interaction with production firmware.** A `production` build gates the USB Serial/JTAG peripheral a second or two into boot, so download mode is the only way back into a running device. Burning `DIS_DOWNLOAD_MODE` on a board running production firmware leaves no recovery path at all. See `BUILD_FLASH_GUIDE.md`.

## Optional: Flash Encryption

Flash encryption prevents reading firmware from the flash chip. This must be done BEFORE enabling secure boot if combining both features (the eFuse write-protection ordering matters).

```bash
# Generate flash encryption key
python3 -m espsecure generate_flash_encryption_key flash_encrypt_key.bin

# Burn flash encryption key
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY2 flash_encrypt_key.bin XTS_AES_128_KEY

# Enable flash encryption (permanently)
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse SPI_BOOT_CRYPT_CNT 0x7

# Disable manual encryption in download mode
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 \
    burn_efuse DIS_DOWNLOAD_MANUAL_ENCRYPT
```

**Order matters if combining Secure Boot + Flash Encryption:**
1. Burn flash encryption key FIRST (needs read-protection)
2. Read-protect the flash encryption key block
3. Burn secure boot key digest
4. Write-protect RD_DIS (locks read-protection settings)
5. Enable secure boot
6. Enable flash encryption

## Decision Matrix: What to Enable

| Threat | Secure Boot | Flash Encryption | Both |
|--------|-------------|-----------------|------|
| Malicious firmware flash | Protected | Not protected | Protected |
| Firmware readout/cloning | Not protected | Protected | Protected |
| JTAG debug attack | Needs DIS_PAD_JTAG + DIS_USB_JTAG (Step 8) | Needs DIS_PAD_JTAG + DIS_USB_JTAG | Needs DIS_PAD_JTAG + DIS_USB_JTAG |
| Boot-time tampering | Protected | Not protected | Protected |

**Recommendation for KasSigner:** Start with Secure Boot only. Flash encryption adds complexity (encrypted flashing workflow) and the primary threat model is firmware tampering, not firmware cloning.

## Recovery: What If Something Goes Wrong

**There is no recovery from a bricked eFuse configuration.** That's why this document exists.

If secure boot is enabled and the signing key is lost:
- The board is permanently bricked
- It cannot be reflashed
- It cannot be recovered
- Buy a new board

If flash encryption is enabled and the encryption key is lost:
- New firmware cannot be encrypted for this board
- The board is permanently bricked

## Verification After Burn

```bash
# Confirm secure boot is active
python3 -m espefuse --port /dev/cu.usbmodem* --chip esp32s3 summary | grep -E "SECURE_BOOT|KEY_PURPOSE|KEY_REVOKE"

# Expected output (with 1 key):
#   SECURE_BOOT_EN = True
#   KEY_PURPOSE_0 = SECURE_BOOT_DIGEST0
#   SECURE_BOOT_KEY_REVOKE1 = True
#   SECURE_BOOT_KEY_REVOKE2 = True
```

## Verify the Key Before Burning It

The public key digest is deterministic from the pem, so a board already
provisioned with that key is an oracle for whether you hold the right one.
Regenerate the digest and compare it against the burned block on a working
device:

```bash
python3 -m espsecure digest_sbv2_public_key \
    --keyfile secure_boot_v2_key.pem --output digest0.bin
xxd digest0.bin

# on an already-provisioned board
python3 -m espefuse --port <PORT> --chip esp32s3 summary | grep -A4 BLOCK_KEY0
```

A byte-for-byte match proves the pem is the one that board enforces, and that
one signed release will run on both. A mismatch means the wrong pem, and is the
cheapest possible place to find that out.

## Signed Images Are Not Reproducible

Secure Boot V2 signs with RSA-PSS, which uses a random salt. Signing the same
input twice produces different bytes and a different SHA-256 both times. This is
correct behaviour, not a build problem.

Track hashes of the **inputs**, never of the signed outputs. The reproducible
artifacts are `kassigner-<board>.bin` and `kassigner-<board>-full.bin`;
`*-signed.bin` files are not reproducible and publishing their hashes would be
meaningless.

## Target Configuration

The same configuration applies to both boards. Every eFuse below is chip-level;
nothing here differs between Waveshare and M5Stack CoreS3 Lite.

| eFuse | Target | Why |
|---|---|---|
| `SECURE_BOOT_EN` | True | ROM verifies bootloader and app on every boot |
| `KEY_PURPOSE_0` | `SECURE_BOOT_DIGEST0`, `R/-` | the one live digest slot, write-protected |
| `KEY_PURPOSE_1..5` | `USER` | unassigned |
| `SECURE_BOOT_KEY_REVOKE0` | False | the slot holding your key |
| `SECURE_BOOT_KEY_REVOKE1` | True | unused slot, closed |
| `SECURE_BOOT_KEY_REVOKE2` | True | unused slot, closed |
| `DIS_PAD_JTAG` | True | closes the physical JTAG pins |
| `DIS_USB_JTAG` | True | closes the USB-to-JTAG switch path |
| `DIS_USB_SERIAL_JTAG` | False | **by design.** Preserves console and flashing |
| `DIS_DOWNLOAD_MODE` | False | preserves the signed-update path |
| `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` | False | preserves the signed-update path |
| `DIS_USB_OTG_DOWNLOAD_MODE` | False | preserves the signed-update path |
| `SPI_BOOT_CRYPT_CNT` | Disable | flash encryption not used, see Decision Matrix |
| `ENABLE_SECURITY_DOWNLOAD` | False | not verified on this hardware, see Step 8 |

One digest slot with the other two revoked is the recommended configuration. A
second slot holding the same key buys nothing: it does not survive a key
compromise, since both digests are the same key, and it leaves a live slot that
the revokes would otherwise have closed.

**Key rotation is not available under this configuration.** `KEY_PURPOSE_0` is
write-protected by the burn and the remaining slots are revoked, so a
provisioned board enforces one key for its lifetime. If the signing key is ever
compromised or lost, provisioned units are retired, not re-keyed. That is the
deliberate trade for a device holding key material: no path exists for an
attacker to install their own trust root either.

### Revoking unused slots is not optional

Secure Boot V2 accepts a signature matching any of three digest slots. With an
unused slot left unrevoked, someone who can write eFuses installs their own
public key digest in a free key block, points it at that slot, signs firmware
with their private key, and the ROM accepts it as legitimate. Your digest stays
intact in slot 0 and is completely bypassed.

Burning `SECURE_BOOT_KEY_REVOKE1` and `SECURE_BOOT_KEY_REVOKE2` is what makes
slot 0 the only door. A board with `SECURE_BOOT_EN` burned and a slot left open
is not provisioned.

## Confirmed on Hardware

Full Secure Boot V2 provisioning run end to end on both Waveshare
ESP32-S3-Touch-LCD-2 and M5Stack CoreS3 Lite. The observations below are chip-level
and applied identically to both.

Signed images boot on an unprovisioned board, which is what makes the whole path
testable while still reversible. Under enforcement the ROM prints
`Valid secure boot key blocks: 0` and `secure boot verification succeeded` before
the second-stage bootloader banner; neither line appears with `SECURE_BOOT_EN`
unburned, so their absence before the burn is expected rather than a fault.

Burning `DIS_PAD_JTAG` and `DIS_USB_JTAG` left the USB Serial console and the
download path intact. After all burns, `esptool chip_id` connects, loads the
stub, and reports the MAC. Signed firmware updates still work.

The second-stage bootloader extracted from a merged image measured roughly 21 KB
across four segments, signing to 28672 bytes and leaving headroom below the
partition table at `0x8000`. `extract_bootloader.py` reports the exact figures
and refuses to write the file if the signed size would reach `0x8000`.

## eFuse Budget

The ESP32-S3 has 6 key blocks (BLOCK_KEY0 through BLOCK_KEY5). Plan allocation:

| Block | Purpose | Key Type |
|-------|---------|----------|
| BLOCK_KEY0 | Secure Boot primary key digest | SECURE_BOOT_DIGEST0 |
| BLOCK_KEY1 | Secure Boot backup key digest | SECURE_BOOT_DIGEST1 |
| BLOCK_KEY2 | Flash encryption key (if used) | XTS_AES_128_KEY |
| BLOCK_KEY3 | Available | - |
| BLOCK_KEY4 | Available | - |
| BLOCK_KEY5 | Available | - |

## KasSigner-Specific Notes

1. **Two signing systems coexist.** Hardware secure boot (RSA-3072, verified by ROM) and software Schnorr verify (verified by our code in `features/verify.rs`). Both must pass for the app to run on a `production` build.

2. **The `esp-bootloader-esp-idf` crate** provides a pre-built second-stage bootloader. For secure boot, this bootloader binary must also be signed.

3. **No OTA.** KasSigner is air-gapped, so firmware updates require physical USB access. If `DIS_DOWNLOAD_MODE` is burned, the board cannot be updated at all. Leave UART download enabled. `ENABLE_SECURITY_DOWNLOAD` narrows it further and still allows signed firmware flashing, but see the note in Step 8 before burning it.

4. **Test on a sacrificial board first.** Keep a spare of whichever board you are provisioning, and burn that one first. Never experiment on the primary development board.

5. **Artifact names differ per board.** `kassigner-m5stack.bin` and `kassigner-m5stack-full.bin` for CoreS3 Lite, `kassigner-waveshare*` and `kassigner-waveshare-af*` for the others. The RSA key and every eFuse command are board-independent; only the images change.
