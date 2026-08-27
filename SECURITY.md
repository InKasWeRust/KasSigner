<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Security Policy

KasSigner is an air-gapped offline signing device that handles cryptographic keys and transaction signing. It is NOT a hardware wallet. It has no secure element and no persistent key storage. All keys exist in RAM only and are destroyed on power-off. Security is the project's highest priority.

## Supported Versions

Only the latest release receives security updates. The current release is **1.0.7**.

Supported hardware:

| Platform | Supported |
|----------|-----------|
| Waveshare ESP32-S3-Touch-LCD-2 | Yes |
| M5Stack CoreS3 Lite | Yes |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly:

1. **Email:** Send details to **kassigner@proton.me** with subject line `[SECURITY]`
2. **Include:** description of the vulnerability, steps to reproduce, potential impact, and suggested fix (if any)
3. **Response timeline:** acknowledgment within 48 hours, initial assessment within 7 days, fix or mitigation plan within 30 days
4. **Fix and credit:** we confirm and assess the report, develop and test a fix, release it and credit the reporter unless anonymity is requested

## Security Model

Security is not a single feature. It is a series of independent walls. An attacker must defeat all of them. Not just one.

### Layer 1: Air-gap

No network stack. WiFi and Bluetooth radios are never initialized. At boot the modem clocks are gated and the wireless power domain is switched off. USB OTG disabled. JTAG closed by eFuse. Data moves only through QR codes (camera and display) and SD card.

### Layer 2: Volatile keys

All key material lives in SRAM only. Mnemonic, master key, derived keys, signing nonces. All volatile. Power off and SRAM decays in milliseconds. The panic handler wipes RAM even on a crash. Nothing is stored in flash. Nothing is persisted anywhere.

### Layer 3: Hardware Secure Boot

On a provisioned unit the ESP32-S3 ROM, immutable silicon, verifies an RSA-3072 firmware signature against a key digest burned permanently into eFuse before any code runs. Only firmware signed with the matching private key can execute. This is a silicon-level guarantee.

The eFuse operation is **one-time and irreversible**: once Secure Boot is enabled and the key digest is burned it cannot be changed or disabled, and a lost signing key means the board can never be reflashed.

See [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) for the eFuse procedure.

### Layer 4: Software firmware verification

Independent of Secure Boot. The firmware computes its own SHA-256 hash at every boot and verifies a Schnorr signature against the developer's public key embedded at build time. In a `production` build a tampered binary fails verification and halts boot; development builds report the result and continue. Hash convergence (the Docker build iterates up to five passes and asserts the last two agree) ensures the embedded hash is self-consistent.

Note the limit of this layer on its own: the hash, the signature and the public key all live inside the image being checked, so it detects accidental corruption and casual tampering, not an attacker who replaced the firmware and removed the check.

Secure Boot is the root of trust; this layer is defense in depth under it, and the developer public key it carries is never what stops a hostile image from executing. Verify what you flash with [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md); trust what runs to the eFuse digest.

### Layer 5: Rust memory safety

100% Rust, `no_std`. The compiler rules out buffer overflows, use-after-free, null dereferences, uninitialized reads, double frees and data races before the code runs. Malicious input triggers a panic and a RAM wipe, never code execution. Integer overflow checks stay enabled in release builds.

`unsafe` is confined to four roles, and the signing and hashing code itself contains none:

- MMIO register access in the hardware drivers
- `write_volatile` in the zeroization routines, because a safe write can be optimised away
- building the large transaction struct on the heap, so it does not overflow the stack
- the two seams where the firmware hands the hardware-free `core/` crate a logger and an entropy source as function pointers (`core/src/log.rs`, `core/src/entropy.rs`); each carries a SAFETY comment and has a single writer

### Layer 6: Encrypted backup

SD card backups are protected by AES-256-GCM with a key stretched from the backup password by PBKDF2 (see Cryptographic Primitives for the round count and why). Salt and nonce are per file. Nothing on the card is usable without the password.

### Layer 7: Steganographic hiding

The encrypted seed hides inside an ordinary JPEG photograph. The device writes it to the SD card, and from there the photo can live anywhere a photo lives, indistinguishable from every other one. Two carriers are available, EXIF metadata and the image's own compressed data, which fail on opposite operations, and the photo's caption doubles as the encryption password. See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the full design.

### Layer 8: BIP39 passphrase

The optional 25th word derives a completely separate wallet. An attacker who recovers the 24 words, from a card, a backup or a photo, reaches only the decoy wallet; the real one needs the passphrase as well, and the passphrase is never stored on the device or in any backup it writes.

## Build and Boot Integrity

### Reproducible builds

Anyone can verify that a binary was built from the published source code. The repository contains a Dockerfile that freezes every component of the build. Exact Ubuntu version, exact Rust compiler, every dependency pinned in `Cargo.lock`. Run `docker build` on any machine and compare the SHA-256 hash to the one published in the release.

See [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) for details.

The published unsigned hash stands for the complete firmware. The unsigned image is built from the same source as the signed one; the only inputs that differ are the embedded signature, the signed flag and the hash. Verification always compares unsigned against unsigned (a byte-diff of signed against unsigned is not confined to the signature region, since those constants shift the compiler's output). Before 1.0.7 the unsigned image was not the firmware at all: the compiler could prove an unsigned `production` build never reached the wallet and deleted most of it, so rebuilding it verified a stub rather than the firmware anyone runs.

### Boot-time known-answer tests

On every power-on, before anything else is usable, the firmware checks its cryptographic primitives against published answers and refuses to boot if any of them disagree (`app/boot_test.rs`, `run_crypto_kats`). Crypto has no natural failure signal: a wrong derivation still gives a valid-looking key and a wrong sighash still signs cleanly, so this is the check that catches a broken build before it can touch funds. It cannot be compiled out of a shipped image (`main.rs` makes that a build error). The set: five BIP39 vectors, four storage-encryption vectors, a BIP32 vector, two Schnorr vectors, a 45' multisig address produced by an independent implementation, 30 transaction sighash vectors taken from the rusty-kaspa 2.0.1 consensus tests covering all six sighash types and both transaction versions, and a health-checked draw from the hardware RNG. Measured at boot: 30/30 sighash in 326 ms on M5Stack CoreS3 Lite and 149 ms on Waveshare, full KAT set 2054 ms and 2080 ms respectively. Every entropy source, what it feeds, what was measured against SP 800-90B and what is only health-checked at runtime, is recorded in [docs/ENTROPY.md](docs/ENTROPY.md).

### Testing the crypto yourself

Everything above runs on a host as well as on the device. The key derivation,
the transaction parsers, sighash, Schnorr and the storage encryption are a
separate crate, `core/`, with no peripheral access and no `esp-hal`, so a
reviewer needs no ESP hardware and no Xtensa toolchain: `cd core && cargo test`
on stock stable Rust runs the same boot-time known-answer tests listed above,
the FAT32 layer against an in-memory card image, and a mutation loop over
every parser. [core/README.md](core/README.md) explains what is in the crate,
what deliberately is not, and how to run the coverage-guided fuzzer. A
reproducer submitted as a failing test in that crate is the most useful form
a report can take.

## KasSee Security Boundary

KasSee is the browser-based watch-only companion and the project's test bench: new device features, covenant designs and ideas are tried there first. It is not the product. KasSigner speaks PSKB and QR and works with any watch-only wallet that does the same.

KasSee runs in the user's browser, OS and network and is **not a security boundary**. A phishing clone can show one address and put another in the QR; malware can rewrite a transaction in memory. The WASM is built from the same open source and is reproducible, which raises the bar, but the final check is always: **verify on the KasSigner screen**. The device shows what is in the transaction data, not what the browser claims.

For covenants the device does not decode semantics. It shows the destination and amount of every output, and first checks that the redeem script the host supplied hashes to the P2SH commitment being spent, so a substituted script cannot vouch for itself. The trust anchor is the covenant address you verified out of band at creation, matched against what the device displays.

For 45' multisig, the descriptor is a second secret: a seed alone cannot find or spend the funds, so back up seed and descriptor. When a transaction claims an output as change, the device tries to reproduce it from a descriptor that already reproduces one of the inputs; if it cannot, the claim is shown as unverified, and if the descriptor contradicts it, the device refuses to sign. A 44' and a 45' kpub are byte-identical in form, so the multisig key export is a separately labelled action from the watch-only one. The full scheme is written up in [KIP: Multisig Wallet Conventions for Kaspa](https://github.com/kaspanet/kips/pull/39/commits/ec5db96).

Stealth payments, where a payer derives a one-time address from your published stealth keys, started life here. Scanning uses a view key separate from the spend key.

By default KasSee connects to a public Kaspa node, whose operator can see which addresses belong together, the balance and your IP. For privacy, run your own node and point KasSee at it in Settings.

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
| Hashing | SHA-256, HMAC-SHA512, BLAKE2b, RIPEMD-160 (kpub fingerprint) | FIPS 180-4, RFC 2104, RFC 7693, ISO/IEC 10118-3 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare, XOR masking, constant-time BIP32 scalar comparison and reduction | Side-channel mitigation |

The backup KDF is PBKDF2-HMAC-SHA256 at 100,000 rounds by decision, not by default. Raising the count six-fold buys under three bits against an attacker on rented GPUs while costing the user seconds on a handheld; what protects a backup is the per-file salt and the strength of the password and passphrase. The container reserves a KDF id so a memory-hard replacement can ship without breaking old backups.

## Reviews and Known Limitations

KasSigner has been through several security reviews since v1.0.5. Every finding was checked against the source; see [CHANGELOG.md](CHANGELOG.md) for the fixes that shipped. Several claims from the reviews were refuted from the code.

The project has not been reviewed by an independent professional security firm; a formal third-party audit is a goal for a future release. Community review is welcome, and `core/src/wallet/`, `core/src/crypto/`, `bootloader/src/hw/sd_backup.rs` and `bootloader/src/features/stego*.rs` are where it counts most.

### What KasSigner does not protect against

- **Lab-grade physical attacks**: an attacker with decapping equipment, an electron microscope or voltage glitching gear may extract secrets from the ESP32-S3 while it is powered on. This is inherent to consumer microcontrollers.
- **Compromised build environment**: if the Rust toolchain or dependencies are backdoored, the binary may contain exfiltration paths. Always build from source and verify with reproducible Docker builds.
- **Social engineering**: if you reveal your seed, EXIF password, or 25th word to an attacker, the device cannot protect you.
- **Compromised companion device**: if the device running KasSee is compromised, transaction details could be manipulated before QR encoding. Always verify amounts and addresses on the KasSigner screen before signing.

