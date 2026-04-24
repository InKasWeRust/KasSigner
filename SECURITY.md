<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# Security Policy

KasSigner is an air-gapped offline signing device that handles cryptographic keys and transaction signing. It is NOT a hardware wallet — it has no secure element and no persistent key storage. All keys exist in RAM only and are destroyed on power-off. Security is the project's highest priority.

## Supported Versions

| Platform | Supported |
|----------|-----------|
| Waveshare ESP32-S3-Touch-LCD-2 | Yes |
| M5Stack CoreS3 / CoreS3 Lite | Yes |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly:

1. **Email:** Send details to **kassigner@proton.me** with subject line `[SECURITY]`
2. **Include:** description of the vulnerability, steps to reproduce, potential impact, and suggested fix (if any)
3. **Response timeline:** acknowledgment within 48 hours, initial assessment within 7 days, fix or mitigation plan within 30 days

## Security Model

Security is not a single feature. It is a series of independent walls. An attacker must defeat all of them — not just one.

### Layer 1 — Air-gap

No network stack. WiFi and Bluetooth radios are never initialized. Radio clocks are gated at boot. USB OTG disabled. JTAG disabled post-boot. Data moves only through QR codes (camera and display) and SD card.

### Layer 2 — Volatile keys

All key material lives in SRAM only. Mnemonic, master key, derived keys, signing nonces — all volatile. Power off and SRAM decays in milliseconds. The panic handler wipes RAM even on a crash. Nothing is stored in flash. Nothing is persisted anywhere.

### Layer 3 — Hardware Secure Boot

On eFuse devices, the ESP32-S3 ROM — immutable silicon — verifies an RSA-3072 firmware signature against a key digest burned permanently into eFuse before any code runs. Only firmware signed with the matching private key can execute. This is a silicon-level guarantee.

See [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) for the eFuse procedure.

### Layer 4 — Software firmware verification

Independent of Secure Boot. The firmware computes its own SHA-256 hash at every boot and verifies a Schnorr signature against the developer's public key embedded at build time. A tampered binary fails verification and halts boot. Hash convergence (three-pass Docker build) ensures the embedded hash is self-consistent.

### Layer 5 — Rust memory safety

100% Rust, `no_std`. The ownership and borrow checker eliminates buffer overflows, use-after-free, null pointer dereference, uninitialized reads, double-free, and data races — at compile time. The entire signing path (parser, sighash, Schnorr, BIP32, address encoding) contains zero `unsafe` code. Malicious input triggers a panic and RAM wipe — never arbitrary code execution.

### Layer 6 — Encrypted backup

SD card backups are protected by AES-256-GCM encryption with PBKDF2 key derivation. The BIP39 passphrase (25th word) creates a completely separate wallet derivation — even if an attacker recovers the 24 mnemonic words, they access only a decoy wallet. The real wallet lives behind a passphrase that exists only in the user's memory.

### Layer 7 — Steganographic hiding

The encrypted seed hides inside an ordinary JPEG photograph on the SD card, stored in EXIF metadata fields. The photo looks ordinary. Among thousands of files, nobody knows which one matters. There is no safe to crack, no metal plate to find.

The EXIF ImageDescription field — which looks like a normal photo caption ("Sunset at Playa Blanca, Aug 2024") — is used as the encryption password. Even with the correct file, an attacker needs the exact caption text, and then the 25th word on top of that.

See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the complete steganographic backup design.

### Reproducible builds

Anyone can verify that a binary was built from the published source code. The repository contains a Dockerfile that freezes every component of the build — exact Ubuntu version, exact Rust compiler, every dependency pinned in `Cargo.lock`. Run `docker build` on any machine and compare the SHA-256 hash to the one published in the release.

See [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) for details.

## KasSee Security Boundary

KasSee is the browser-based watch-only companion wallet. It runs in an untrusted environment — the user's browser, OS, and network. It is **not a security boundary**.

A phishing clone could show one address and put another in the QR. Browser malware could rewrite the transaction in memory. The WebAssembly binary is compiled from the same open Rust source and can be verified with a reproducible build — a phishing site would need to serve a different binary, and the hash would not match. That raises the bar. But it does not replace the final check: **verify on the KasSigner screen**. The device shows what is actually in the transaction data. Not what the browser claims.

By default KasSee connects to a public Kaspa node. The node operator can see which addresses belong to the same wallet, the total balance, and the user's IP address. For privacy, run your own node and point KasSee at it via Settings.

## What KasSigner Does NOT Protect Against

- **Lab-grade physical attacks** — an attacker with a JTAG probe, electron microscope, or voltage glitching equipment may extract secrets from the ESP32-S3 while it is powered on. This is inherent to consumer microcontrollers.
- **Compromised build environment** — if the Rust toolchain or dependencies are backdoored, the binary may contain exfiltration paths. Always build from source and verify with reproducible Docker builds.
- **Social engineering** — if you reveal your seed, EXIF password, or 25th word to an attacker, the device cannot protect you.
- **Compromised companion device** — if the device running KasSee is compromised, transaction details could be manipulated before QR encoding. Always verify amounts and addresses on the KasSigner screen before signing.

## Known Limitations

Internal security review has identified areas for improvement. All findings are documented with severity ratings and resolution status in [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf). Fixes are tracked and applied in subsequent releases.

## Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Seed generation | BIP39 mnemonic | BIP-0039 |
| Key derivation | BIP32 HD keys | BIP-0032 |
| Child mnemonics | BIP85 | BIP-0085 |
| Key stretching | PBKDF2-HMAC-SHA512 (2048 rounds) | RFC 8018 |
| Transaction signing | Schnorr (secp256k1) | Kaspa spec |
| Transaction hashing | Keyed Blake2b-256 | Kaspa consensus |
| Seed encryption (SD) | AES-256-GCM | NIST SP 800-38D |
| Seed encryption (stego) | AES-256-GCM + PBKDF2 | NIST SP 800-38D / RFC 8018 |
| Hashing | SHA-256, HMAC-SHA512, BLAKE2b | FIPS 180-4, RFC 2104, RFC 7693 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare, XOR masking | Side-channel mitigation |

## Memory Safety

- All wallet and crypto code is pure Rust (`no_std`)
- Hardware drivers use `unsafe` only for MMIO register access (ESP32-S3 peripherals)
- Stack-allocated buffers with compile-time size bounds — no heap allocation in crypto paths
- Integer overflow checks enabled even in release builds (`overflow-checks = true`)

## Code Audit Status

This project has undergone internal security review. The findings are documented in [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf) with severity ratings and resolution status.

The project has **not** been reviewed by an independent professional security firm. A formal third-party audit is a goal for a future release. Community review is welcome and encouraged.

Priority review targets:

1. `wallet/` — BIP39, BIP32, Schnorr signing, PSKB/KSPT parsing
2. `crypto/` — constant-time operations, zeroization, secret containers
3. `features/stego.rs` — encryption and EXIF embedding
4. `hw/sd_backup.rs` — AES-256-GCM backup codec

## Responsible Disclosure

1. Reporter contacts us privately via **kassigner@proton.me** with subject `[SECURITY]`
2. We confirm and assess the vulnerability
3. We develop and test a fix
4. We release the fix and credit the reporter (unless anonymity is requested)
5. Full details are published after users have had time to update

## eFuse / Secure Boot Notes

The ESP32-S3 supports hardware secure boot via eFuse. This is a **one-time, irreversible** operation:

- Once secure boot is enabled and the signing key is burned, it cannot be changed or disabled
- A lost signing key means the board can never be reflashed
- Flash encryption can be combined with secure boot for defense-in-depth

KasSigner's `tools/gen_keypair` generates the Schnorr keypair used for software-level firmware verification (Layer 4). Hardware-level eFuse secure boot (Layer 3) is a separate, additional layer that uses the ESP32-S3's built-in RSA verification during the ROM bootloader stage.

See [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) for the complete eFuse procedure.

## Bug Bounty

There is currently no formal bug bounty program. We publicly credit security researchers who responsibly disclose vulnerabilities.
