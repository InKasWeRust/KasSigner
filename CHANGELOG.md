# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-03-30

### Critical Fixes
- **Sighash**: All sub-hashes and final digest now use keyed Blake2b-256 with `TransactionSigningHash` domain key (was unkeyed)
- **Output hash**: Added `script_len` (u64 LE) prefix before script bytes in `hash_output`
- **Schnorr challenge**: Switched from plain `SHA256(R||P||msg)` to BIP-340 tagged hash `SHA256(tag||tag||R||P||msg)`
- **Change address signing**: `find_address_index_for_pubkey` now searches both receive (m/.../0/x) and change (m/.../1/x) chains; returns `(index, is_change)` tuple; all 3 callers updated

### Added
- **KasSee** — watch-only companion wallet integrated into monorepo (`kassee/`)
  - Import kpub, derive addresses, track UTXOs, build unsigned KSPT
  - Fee estimation via node RPC (`get_fee_estimate`)
  - Storage mass awareness (KIP-9/Crescendo): warns < 0.2 KAS, errors < 0.1 KAS
  - Address reuse detection with warning pause
  - Change address auto-rotation
  - Balanced QR frame splitting (equal size across frames)
  - `addresses --change` flag for change address listing
- **SD backup delete** with hold-to-confirm (matches seed delete UX: CANCEL left, DELETE right, HOLD 4s)
- **SD file list** fingerprint matching ("Seed #1", "Seed #2" labels)
- **SD progress bars** on seed restore decrypt and xprv import
- **Pre-signing size check**: rejects transactions exceeding 1024-byte buffer with "Too many inputs! N inputs — max 5. Compound first."
- **KSSN hex dump** as single line (was multi-line, required manual cleanup)
- **Hex buffer overflow** handled gracefully with warning (no panic)

### Fixed
- "Wrong passphrase" → "Wrong password" on SD import failure
- Remaining Spanish comments translated to English (5 instances)
- Email inconsistency in CONTRIBUTING.md (now `kassigner-security@proton.me`)
- Crate renamed from `kassigner-companion` to `kassee`

### Verified on Mainnet
- TX `2faa58b2...` — 1-input, 1-output (first air-gapped broadcast)
- TX `450e2e2d...` — 1-input, 1-output (fee logic)
- TX `35013c16...` — 1-input, 1-output (storage mass)
- TX `277517da...` — 3-input, 1-output (multi-UTXO across receive + change chains)

## [1.0.0] — 2026-03-28

### Added
- Air-gapped Kaspa offline signing device — 100% Rust, no_std, no network stack
- BIP39 seed generation (12/24 words) from hardware TRNG + camera + ADC entropy
- BIP39 passphrase (25th word) support with hidden wallet derivation
- BIP32 HD key derivation (Kaspa path m/44'/111111'/0')
- BIP85 child mnemonic derivation (deterministic child wallets)
- Schnorr signing (secp256k1) for Kaspa transactions
- PSKT (Partially Signed Kaspa Transaction) scanning, review, and signing
- Message signing with address keys (type or load from SD)
- M-of-N multisig address generation, co-signing, and wallet descriptor export
- Change address detection in TX review (flags OWN and CHANGE outputs)
- Multi-seed management in RAM (up to 16 slots, never persisted to flash)
- Dice roll seed generation (verifiable entropy, 99 rolls)
- Steganographic backup — encrypted seeds hidden in JPEG EXIF on SD card
- AES-256-GCM encrypted SD card backup with PBKDF2 key derivation
- CompactSeedQR import/export (SeedSigner compatible)
- Standard SeedQR and Plain Words QR export
- QR code scanning via camera with multi-frame confirmation
- KRC-20 token transaction detection during TX review
- kpub export for watch-only wallets
- xprv encrypted export to SD card
- ESP32-S3 Secure Boot V2 (RSA-3072 ROM verification)
- Software-level Schnorr firmware signature verification at every boot
- Radio lockdown (WiFi, Bluetooth, USB OTG disabled at boot)
- JTAG disabled post-boot
- Panic handler with SRAM zeroization
- SD card format with hold-to-confirm safety (4-second red button)
- Reproducible builds via Docker
- Live display mirror — stream screen to Mac/PC via serial for presentations
- Cross-platform build environment checker (tools/setup_check.rs)

### Hardware Support
- **Waveshare ESP32-S3-Touch-LCD-2** (primary)
  - ST7789T3 320x240 display (SPI)
  - CST816D capacitive touch with hardware gestures (I2C)
  - OV5640 5MP camera with autofocus (DVP)
  - SDHOST SD card controller (native 1-bit mode, PLL clock)
  - Battery ADC monitoring (GPIO5)
  - Secure Boot V2 ready (eFuse)

- **M5Stack CoreS3 / CoreS3 Lite** (secondary)
  - ILI9342C 320x240 display (SPI)
  - FT6336U capacitive touch (I2C)
  - GC0308 QVGA camera (DVP, Y-only grayscale)
  - Bitbang SPI SD card
  - AW88298 I2S speaker with volume control
  - AXP2101 PMU + AW9523B IO expander
  - Battery gauge via PMU

### Code Quality
- 80 source files, ~42,900 lines of Rust
- Zero compiler warnings on both platforms (clippy clean)
- 1,549 lines of dead code removed during pre-release audit
- All comments in English
- Zero TODO/FIXME comments remaining
- Targeted per-module `#[allow]` directives (no blanket crate-level suppression)
- GPL v3.0 license header on every source file
- Module description headers on all source files
