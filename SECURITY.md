# Security Policy

KasSigner is an air-gapped hardware wallet that handles cryptographic keys and transaction signing. Security is the project's highest priority.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x (Waveshare) | Yes |
| 1.0.x (M5Stack) | Yes |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability, please report it responsibly:

1. **Email:** Send details to **kassigner-security@proton.me**
2. **Include:** description of the vulnerability, steps to reproduce, potential impact, and suggested fix (if any)
3. **Response timeline:** acknowledgment within 48 hours, initial assessment within 7 days, fix or mitigation plan within 30 days

## Security Model

### Three-layer steganographic protection

KasSigner's backup system uses three independent layers. An attacker must defeat all three to access funds:

**Layer 1 — Steganography (what to look for).** The encrypted seed is hidden in JPEG EXIF metadata. The image looks ordinary — a vacation photo, a pet, anything. Among thousands of files, nobody knows which one matters. There is no safe to crack, no metal plate to find.

**Layer 2 — Encryption (how to decrypt).** The seed is encrypted with AES-256-CBC. The key is derived via PBKDF2 from the EXIF ImageDescription field — which looks like a normal photo caption ("Sunset at Playa Blanca, Aug 2024"). Even with the correct file, an attacker needs this exact text.

**Layer 3 — BIP39 passphrase (the 25th word).** Even if an attacker decrypts the 24-word mnemonic, the real wallet is derived with a passphrase that exists only in the owner's memory. The mnemonic alone leads to a decoy wallet. The real funds live on a derivation path that requires knowledge only the user possesses.

### What KasSigner protects against

- **Network-based attacks** — the device is fully air-gapped. WiFi and Bluetooth radios are never initialized. All communication is via QR codes and SD card.
- **Key extraction from device** — private keys are XOR-masked in RAM, never stored in flash, and zeroized after each signing operation.
- **Supply chain attacks** — firmware integrity is verified at every boot via SHA-256 hash + Schnorr signature against a build-time embedded public key.
- **Side-channel timing** — cryptographic comparisons use constant-time operations. Key material is XOR-masked to prevent pattern analysis.
- **Casual physical access** — without the SD card backup file, the EXIF passphrase, AND the BIP39 25th word, accessing funds is infeasible.

### What KasSigner does NOT protect against

- **Lab-grade physical attacks** — an attacker with a JTAG probe, electron microscope, or voltage glitching equipment may extract secrets from the ESP32-S3. This is inherent to consumer microcontrollers.
- **Compromised build environment** — if the Rust toolchain or dependencies are backdoored, the binary may contain exfiltration paths. Always build from source and verify dependencies.
- **Social engineering** — if you reveal your seed, EXIF passphrase, or 25th word to an attacker, the device cannot protect you.
- **Clipboard/screen capture on companion device** — the watch-only wallet on your phone/PC handles the unsigned PSKT. If that device is compromised, transaction details could be manipulated before QR encoding. Always verify amounts and addresses on the KasSigner screen before signing.

### Cryptographic primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Seed generation | BIP39 mnemonic | BIP-0039 |
| Key derivation | BIP32 HD keys | BIP-0032 |
| Child mnemonics | BIP85 | BIP-0085 |
| Key stretching | PBKDF2-HMAC-SHA512 (2048 rounds) | RFC 8018 |
| Transaction signing | Schnorr (secp256k1) | Kaspa spec |
| Seed encryption (SD) | AES-256-GCM | NIST SP 800-38D |
| Seed encryption (stego) | AES-256-CBC + PBKDF2 | NIST / RFC 8018 |
| Hashing | SHA-256, HMAC-SHA512, BLAKE2b | FIPS 180-4, RFC 2104, RFC 7693 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare, XOR masking | Side-channel mitigation |

### Memory safety

- All wallet and crypto code is pure Rust (`no_std`, no `unsafe` in wallet modules)
- Hardware drivers use `unsafe` only for MMIO register access (ESP32-S3 peripherals)
- Stack-allocated buffers with compile-time size bounds — no heap allocation in crypto paths
- Integer overflow checks enabled even in release builds (`overflow-checks = true`)

### Code audit status

This project has not yet undergone a formal third-party security audit. Community review is welcome and encouraged. Priority review targets:

1. `wallet/` — BIP39, BIP32, Schnorr signing, PSKT parsing
2. `crypto/` — constant-time operations, zeroization, secret containers
3. `features/stego.rs` — encryption and EXIF embedding
4. `hw/sd_backup.rs` — AES-256-GCM backup codec

## Responsible Disclosure

1. Reporter contacts us privately via email
2. We confirm and assess the vulnerability
3. We develop and test a fix
4. We release the fix and credit the reporter (unless anonymity is requested)
5. Full details are published after users have had time to update

## eFuse / Secure Boot Notes

The ESP32-S3 supports hardware secure boot via eFuse. This is a **one-time, irreversible** operation:

- Once secure boot is enabled and the signing key is burned, it cannot be changed or disabled
- A lost signing key means the board can never be reflashed
- Flash encryption can be combined with secure boot for defense-in-depth

KasSigner's `tools/gen_keypair` generates the Schnorr keypair used for software-level firmware verification. Hardware-level eFuse secure boot is a separate, additional layer that uses the ESP32-S3's built-in RSA/ECDSA verification during the ROM bootloader stage.

## Bug Bounty

There is currently no formal bug bounty program. We publicly credit security researchers who responsibly disclose vulnerabilities.
