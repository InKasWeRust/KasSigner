<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# KasSigner — eFuse Secure Boot Runbook

**WARNING: eFuse operations are IRREVERSIBLE. A mistake here can permanently brick the board. Read this entire document before touching any commands.**

## Overview

The ESP32-S3 has two independent security layers that use eFuses:

1. **Secure Boot v2** — ROM bootloader verifies the second-stage bootloader signature (RSA-3072 or ECDSA). Second-stage bootloader verifies the app signature.
2. **Flash Encryption** — all flash contents are encrypted with an AES-128/256 XTS key. Prevents reading firmware from flash.

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

## Pre-flight Checklist

Before ANY eFuse operation:

- [ ] Board boots and runs KasSigner correctly
- [ ] `espefuse.py summary` shows all security eFuses at default (0)
- [ ] Signing key generated and backed up to 3+ offline locations
- [ ] Flash encryption key generated (if using flash encryption)
- [ ] Signed bootloader + signed app both verified on a TEST board first
- [ ] You understand: **there is no undo**

## Step 0: Read Current eFuse State

```bash
# Check what's already burned (should all be zero/default on a fresh board)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 summary

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
espsecure.py generate_signing_key --version 2 --scheme rsa3072 \
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
espsecure.py generate_signing_key --version 2 --scheme rsa3072 \
    secure_boot_v2_key_backup.pem
```

## Step 2: Generate Public Key Digest

```bash
# Primary key
espsecure.py digest_sbv2_public_key \
    --keyfile secure_boot_v2_key.pem \
    --output digest0.bin

# Backup key (if using)
espsecure.py digest_sbv2_public_key \
    --keyfile secure_boot_v2_key_backup.pem \
    --output digest1.bin
```

## Step 3: Burn Key Digest to eFuse

**THIS IS IRREVERSIBLE. Triple-check the file paths.**

```bash
# Burn primary key digest to BLOCK_KEY0
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY0 digest0.bin SECURE_BOOT_DIGEST0

# If using backup key, burn to BLOCK_KEY1
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY1 digest1.bin SECURE_BOOT_DIGEST1
```

You will be prompted to type `BURN` to confirm.

## Step 4: Revoke Unused Key Slots

Any unused SECURE_BOOT_DIGEST slot MUST be revoked. If you used only digest0:

```bash
# Revoke unused slots (if only using 1 key)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_KEY_REVOKE1

espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_KEY_REVOKE2

# If using 2 keys (digest0 + digest1), only revoke slot 2:
# espefuse.py --port ... burn_efuse SECURE_BOOT_KEY_REVOKE2
```

## Step 5: Build and Sign Firmware

The second-stage bootloader and app must be signed with the RSA-3072 key. Since KasSigner uses `esp-bootloader-esp-idf` (not full ESP-IDF), the signing process needs to be done manually:

```bash
# Sign the bootloader binary
espsecure.py sign_data --version 2 --keyfile secure_boot_v2_key.pem \
    --output bootloader-signed.bin bootloader.bin

# Sign the app binary  
espsecure.py sign_data --version 2 --keyfile secure_boot_v2_key.pem \
    --output kassigner-signed.bin kassigner-bootloader.bin

# If using backup key, append second signature:
espsecure.py sign_data --version 2 --keyfile secure_boot_v2_key_backup.pem \
    --append_signatures \
    --output kassigner-signed.bin kassigner-signed.bin
```

## Step 6: Flash Signed Firmware BEFORE Enabling Secure Boot

**CRITICAL ORDER: Flash first, THEN enable secure boot.** If you enable secure boot before flashing signed firmware, the board will refuse to boot and is bricked.

```bash
# Flash the signed bootloader and app
espflash flash --chip esp32s3 kassigner-signed.bin

# Verify it boots correctly
# Monitor serial output to confirm boot succeeds
```

## Step 7: Enable Secure Boot

**POINT OF NO RETURN. After this, only signed firmware will boot.**

```bash
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse SECURE_BOOT_EN
```

## Step 8: Lock Down Security eFuses (Production)

For production boards, additional eFuses should be burned to prevent attacks:

```bash
# Disable JTAG (prevents debug probe access)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse DIS_PAD_JTAG
    
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse DIS_USB_JTAG

# Disable USB Serial/JTAG  
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse DIS_USB_SERIAL_JTAG

# Disable direct boot (force secure boot path)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse DIS_DIRECT_BOOT

# Enable secure download mode (restricts what UART download can do)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse ENABLE_SECURITY_DOWNLOAD
```

**DO NOT burn `DIS_DOWNLOAD_MODE` unless you are absolutely sure.** This permanently prevents any firmware updates via UART, even signed ones. Only do this for final production units where OTA is the only update path (and KasSigner has no OTA since it's air-gapped).

## Optional: Flash Encryption

Flash encryption prevents reading firmware from the flash chip. This must be done BEFORE enabling secure boot if combining both features (the eFuse write-protection ordering matters).

```bash
# Generate flash encryption key
espsecure.py generate_flash_encryption_key flash_encrypt_key.bin

# Burn flash encryption key
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_key BLOCK_KEY2 flash_encrypt_key.bin XTS_AES_128_KEY

# Enable flash encryption (permanently)
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
    burn_efuse SPI_BOOT_CRYPT_CNT 0x7

# Disable manual encryption in download mode
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 \
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
| JTAG debug attack | Needs DIS_JTAG eFuse separately | Needs DIS_JTAG eFuse | Needs DIS_JTAG eFuse |
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
espefuse.py --port /dev/tty.usbmodem* --chip esp32s3 summary | grep -E "SECURE_BOOT|KEY_PURPOSE|KEY_REVOKE"

# Expected output (with 1 key):
#   SECURE_BOOT_EN = True
#   KEY_PURPOSE_0 = SECURE_BOOT_DIGEST0
#   SECURE_BOOT_KEY_REVOKE1 = True
#   SECURE_BOOT_KEY_REVOKE2 = True
```

## eFuse Budget

The ESP32-S3 has 6 key blocks (BLOCK_KEY0 through BLOCK_KEY5). Plan allocation:

| Block | Purpose | Key Type |
|-------|---------|----------|
| BLOCK_KEY0 | Secure Boot primary key digest | SECURE_BOOT_DIGEST0 |
| BLOCK_KEY1 | Secure Boot backup key digest | SECURE_BOOT_DIGEST1 |
| BLOCK_KEY2 | Flash encryption key (if used) | XTS_AES_128_KEY |
| BLOCK_KEY3 | Available | — |
| BLOCK_KEY4 | Available | — |
| BLOCK_KEY5 | Available | — |

## KasSigner-Specific Notes

1. **Two signing systems coexist.** Hardware secure boot (RSA-3072, verified by ROM) and software Schnorr verify (verified by our code in `features/verify.rs`). Both must pass for the app to run.

2. **The `esp-bootloader-esp-idf` crate** provides a pre-built second-stage bootloader. For secure boot, this bootloader binary must also be signed. Check if the crate supports this or if we need to extract and sign it manually.

3. **No OTA.** KasSigner is air-gapped, so firmware updates require physical UART access. If `DIS_DOWNLOAD_MODE` is burned, the board cannot be updated at all. Consider leaving UART download enabled with `ENABLE_SECURITY_DOWNLOAD` (secure download mode) which still allows signed firmware flashing.

4. **Test on a sacrificial board first.** Buy a spare Waveshare board specifically for eFuse testing. Never experiment on the primary development board.
