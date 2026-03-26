# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2025-03-26

### Added
- Air-gapped Kaspa hardware wallet — 100% Rust, no_std, no network stack
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
- 76 source files, ~41,700 lines of Rust
- Zero compiler warnings on both platforms
- 1,549 lines of dead code removed during pre-release audit
- All comments in English
- Zero TODO/FIXME comments remaining
- Targeted per-module `#[allow]` directives (no blanket crate-level suppression)
- GPL v3.0 license header on every source file
- Module description headers on all 76 files
