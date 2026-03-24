# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2025-03-24

### Added
- Air-gapped Kaspa hardware wallet for Waveshare ESP32-S3-Touch-LCD-2
- BIP39 seed generation (12/24 words) from hardware TRNG + camera + ADC entropy
- BIP32 HD key derivation (Kaspa path m/44'/111111'/0')
- BIP39 passphrase (25th word) support
- BIP85 child mnemonic derivation
- Schnorr signing (secp256k1) for Kaspa transactions
- PSKT (Partially Signed Kaspa Transaction) scanning, review, and signing
- Message signing with address keys
- M-of-N multisig address generation and co-signing
- Multi-seed management (RAM only, never persisted)
- Steganographic backup — encrypted seeds hidden in JPEG EXIF on SD card
- AES-256-GCM encrypted SD card backup
- CompactSeedQR import/export (SeedSigner compatible)
- QR code scanning via OV5640 camera with voting confirmation
- KRC-20 token transaction detection
- kpub/xprv export for watch-only wallets
- ESP32-S3 Secure Boot V2 (RSA-3072 ROM verification)
- Software-level Schnorr firmware signature verification
- Radio lockdown (WiFi, Bluetooth, USB OTG disabled at boot)
- JTAG disabled post-boot
- Panic handler with SRAM zeroization
- Reproducible builds via Docker

### Hardware Support
- Waveshare ESP32-S3-Touch-LCD-2
  - ST7789T3 320x240 display (SPI)
  - CST816D capacitive touch (I2C)
  - OV5640 5MP camera with autofocus (DVP)
  - SDHOST SD card controller (native 1-bit mode)
  - Battery ADC monitoring (GPIO5)
