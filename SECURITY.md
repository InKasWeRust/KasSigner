<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Security Policy

KasSigner is an air-gapped offline signing device that handles cryptographic keys and transaction signing. It is NOT a hardware wallet. It has no secure element and no persistent key storage. All keys exist in RAM only and are destroyed on power-off. Security is the project's highest priority.

## Supported Versions

Only the latest release receives security updates. The current release is **1.0.5**.

Supported hardware:

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

Security is not a single feature. It is a series of independent walls. An attacker must defeat all of them. Not just one.

### Layer 1: Air-gap

No network stack. WiFi and Bluetooth radios are never initialized. At boot the modem clocks are gated and the wireless power domain is switched off. USB OTG disabled. JTAG closed by eFuse. Data moves only through QR codes (camera and display) and SD card.

### Layer 2: Volatile keys

All key material lives in SRAM only. Mnemonic, master key, derived keys, signing nonces. All volatile. Power off and SRAM decays in milliseconds. The panic handler wipes RAM even on a crash. Nothing is stored in flash. Nothing is persisted anywhere.

### Layer 3: Hardware Secure Boot

On eFuse devices, the ESP32-S3 ROM. Immutable silicon. Verifies an RSA-3072 firmware signature against a key digest burned permanently into eFuse before any code runs. Only firmware signed with the matching private key can execute. This is a silicon-level guarantee.

See [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) for the eFuse procedure.

### Layer 4: Software firmware verification

Independent of Secure Boot. The firmware computes its own SHA-256 hash at every boot and verifies a Schnorr signature against the developer's public key embedded at build time. In a `production` build a tampered binary fails verification and halts boot; development builds report the result and continue. Hash convergence (three-pass Docker build) ensures the embedded hash is self-consistent.

Note the limit of this layer on its own: the hash, the signature and the public key all live inside the image being checked, so it detects accidental corruption and casual tampering, not an attacker who replaced the firmware and removed the check. Layer 3 is what anchors it.

### Layer 5: Rust memory safety

100% Rust, `no_std`. The ownership and borrow checker eliminates buffer overflows, use-after-free, null pointer dereference, uninitialized reads, double-free, and data races. At compile time. `unsafe` appears in the signing path in exactly one role: `write_volatile` to wipe secrets, in the zeroization routines of `bip32.rs`, `bip39.rs` and `pskt.rs`. Volatile writes are unsafe by definition in Rust, and they are used precisely because a safe write can be optimised away. `schnorr.rs` and `sighash.rs` contain none. `transaction.rs` additionally uses `mem::zeroed`, `alloc_zeroed` and `Box::from_raw` to build a large transaction on the heap without overflowing the stack. Malicious input triggers a panic and RAM wipe. Never arbitrary code execution.

### Layer 6: Encrypted backup

SD card backups are protected by AES-256-GCM encryption with PBKDF2 key derivation. The BIP39 passphrase (25th word) creates a completely separate wallet derivation. Even if an attacker recovers the 24 mnemonic words, they access only a decoy wallet. The real wallet lives behind a passphrase that exists only in the user's memory.

### Layer 7: Steganographic hiding

The encrypted seed hides inside an ordinary JPEG photograph on the SD card. The photo looks ordinary. Among thousands of files, nobody knows which one matters. There is no safe to crack, no metal plate to find.

Two carriers are available, chosen at export. **Descriptor** puts the payload in the photo's EXIF metadata: it survives re-saving the image and is destroyed if anything strips metadata. **Picture** puts it in the image's own compressed data: it ignores metadata stripping and is destroyed by re-compression. They fail on opposite operations, so running the export twice writes both; on import the device tries both carriers and reports which one carried the backup.

The EXIF ImageDescription field, which looks like a normal photo caption ("Sunset at Playa Blanca, Aug 2024"), is used as the encryption password. Even with the correct file, an attacker must know that the caption is the password, and then needs the 25th word on top of that.

See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the complete steganographic backup design.

### Reproducible builds

Anyone can verify that a binary was built from the published source code. The repository contains a Dockerfile that freezes every component of the build. Exact Ubuntu version, exact Rust compiler, every dependency pinned in `Cargo.lock`. Run `docker build` on any machine and compare the SHA-256 hash to the one published in the release.

See [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) for details.

## KasSee Security Boundary

KasSee is the browser-based watch-only companion wallet. It runs in an untrusted environment. The user's browser, OS, and network. It is **not a security boundary**.

A phishing clone could show one address and put another in the QR. Browser malware could rewrite the transaction in memory. The WebAssembly binary is compiled from the same open Rust source and can be verified with a reproducible build. A phishing site would need to serve a different binary, and the hash would not match. That raises the bar. But it does not replace the final check: **verify on the KasSigner screen**. The device shows what is actually in the transaction data. Not what the browser claims. This extends to covenants. A covenant locks funds to a script, so the covenant parameters shown on the device (recipient, cap, timelock, heir) are the trust anchor, not what KasSee displays.

By default KasSee connects to a public Kaspa node. The node operator can see which addresses belong to the same wallet, the total balance, and the user's IP address. For privacy, run your own node and point KasSee at it via Settings.

Stealth payments add address-level privacy: a payer derives a one-time address from your stealth keys, so on-chain payments don't link to your public address. Scanning for incoming stealth payments uses a view key, separate from the spend key that authorizes spends.

## What KasSigner Does NOT Protect Against

- **Lab-grade physical attacks**: an attacker with a JTAG probe, electron microscope, or voltage glitching equipment may extract secrets from the ESP32-S3 while it is powered on. This is inherent to consumer microcontrollers.
- **Compromised build environment**: if the Rust toolchain or dependencies are backdoored, the binary may contain exfiltration paths. Always build from source and verify with reproducible Docker builds.
- **Social engineering**: if you reveal your seed, EXIF password, or 25th word to an attacker, the device cannot protect you.
- **Compromised companion device**: if the device running KasSee is compromised, transaction details could be manipulated before QR encoding. Always verify amounts and addresses on the KasSigner screen before signing.

## Known Limitations

A full security audit of v1.0.5 produced 40 findings across all severities. Most are closed; the remainder are recorded with the reasoning for deferring them. See [CHANGELOG.md](CHANGELOG.md) for what this release fixed and what is still open, and [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf) for the design review.

## Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Seed generation | BIP39 mnemonic | BIP-0039 |
| Key derivation | BIP32 HD keys | BIP-0032 |
| Child mnemonics | BIP85 | BIP-0085 |
| Seed derivation | PBKDF2-HMAC-SHA512 (2048 rounds) | BIP-0039 / RFC 8018 |
| Backup password stretching | PBKDF2-HMAC-SHA256 (100,000 rounds, per-file salt) | RFC 8018 |
| Transaction signing | Schnorr (secp256k1), BIP-340 tagged challenge | BIP-0340 / Kaspa spec |
| Transaction hashing | Keyed Blake2b-256 | Kaspa consensus |
| Backup encryption (SD and stego) | AES-256-GCM, per-file salt and nonce | NIST SP 800-38D |
| Payload encryption (ECIES) | ECDH + BLAKE2B-256 + AES-256-GCM | SEC 1 / RFC 7693 / NIST SP 800-38D |
| Shared-secret derivation | ECDH (secp256k1) | SEC 1 |
| Hashing | SHA-256, HMAC-SHA512, BLAKE2b | FIPS 180-4, RFC 2104, RFC 7693 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare, XOR masking, constant-time BIP32 scalar comparison and reduction | Side-channel mitigation |

## Memory Safety

- All wallet and crypto code is pure Rust (`no_std`)
- `unsafe` is confined to three roles: MMIO register access in hardware drivers, `write_volatile` in zeroization routines (a safe write can be optimised away), and heap construction of the transaction struct
- Stack-allocated buffers with compile-time size bounds throughout the crypto primitives; the heap is used for large structures (transaction, camera and stego buffers) that would otherwise overflow the stack
- Integer overflow checks enabled even in release builds (`overflow-checks = true`)

## Code Audit Status

This project has been through a full security audit producing 40 findings, most of which are closed in v1.0.5. Findings and their status are summarised in [CHANGELOG.md](CHANGELOG.md); the design review is in [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf).

The project has **not** been reviewed by an independent professional security firm. A formal third-party audit is a goal for a future release. Community review is welcome and encouraged.

Priority review targets:

1. `wallet/`: BIP39, BIP32, Schnorr signing, PSKB/KSPT parsing
2. `crypto/`: constant-time operations, zeroization, secret containers
3. `features/stego.rs`: encryption and EXIF embedding
4. `features/stego_dct.rs` and `features/stego_perm.rs`: JPEG coefficient carrier and its keyed traversal
5. `hw/sd_backup.rs`: AES-256-GCM backup codec
6. `wallet/ecies.rs`: ECDH + AES-256-GCM encrypt-to-pubkey
7. `wallet/pskt.rs`: covenant redeem-script signing and covenant binding (KSPT v3)
8. KasSee `kspt_*` covenant builders and `stealth.rs`: covenant scripts and ECDH stealth addresses

## Responsible Disclosure

1. Reporter contacts us privately (see **Reporting a Vulnerability** above)
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
