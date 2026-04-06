<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-03-31

### Milestone: First Air-Gapped Multisig on Kaspa Mainnet
- **P2SH multisig** — fund and spend from M-of-N Pay-to-Script-Hash multisig addresses
- **Co-signing flow** — device A signs partial → QR → device B adds signature → fully signed
- **Two co-signing modes** — direct device-to-device QR, or via KasSee relay
- TX `8a6652fb...` — first P2SH multisig funding on Kaspa mainnet (air-gapped)
- TX `d1ffdb9f...` — first P2SH multisig spend (2-of-2, direct device-to-device)
- TX `2b53e35a...` — second P2SH funding (reversed kpub order, sorted keys verified)
- TX `2b718bd5...` — second P2SH multisig spend (2-of-2, via KasSee relay)

### Added — Device Firmware
- **P2SH script detection** (`OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL`) in transaction analysis
- **Redeem script** field on transaction inputs for P2SH round-trip
- **v2 KSPT serializer/parser** carries redeem scripts between signers
- **KSPT v1 flags 0x02** — optional redeem script per input for P2SH spending
- **ShowQR sig status overlay** — "PARTIAL 1/2" (orange) or "FULLY SIGNED 2/2" (teal)
- **Multi-frame v2 KSPT detection** in camera — previously only single-frame v2 was recognized
- **QR frame padding** — last frame padded to minimum 20 bytes for reliable scanning
- **"No seed loaded"** warning replaces generic "TX Cancelled" when signing without a seed
- **BIP85 auto-load** — derived child seed loads into slot immediately after derivation
- **BIP85 success sound** — plays "tururi" (success) instead of "bip" (task_done)
- **Home button** on SD format warning screen (was dead zone)
- **Click sound** on back/home during format warning
- **SD backup delete** with hold-to-confirm (matches seed delete UX: CANCEL left, DELETE right, HOLD 4s)
- **SD file list** fingerprint matching ("Seed #1", "Seed #2" labels)
- **SD progress bars** on seed restore decrypt and xprv import
- **Pre-signing size check**: rejects transactions exceeding 1024-byte buffer with "Too many inputs! N inputs — max 5. Compound first."
- **KSSN hex dump** as single line (was multi-line, required manual cleanup)
- **Hex buffer overflow** handled gracefully with warning (no panic)

### Fixed — Device Firmware
- **Sighash**: All sub-hashes and final digest now use keyed Blake2b-256 with `TransactionSigningHash` domain key (was unkeyed)
- **Output hash**: Added `script_len` (u64 LE) prefix before script bytes in `hash_output`
- **Schnorr challenge**: Switched from plain `SHA256(R||P||msg)` to BIP-340 tagged hash `SHA256(tag||tag||R||P||msg)`
- **Change address signing**: `find_address_index_for_pubkey` now searches both receive (m/.../0/x) and change (m/.../1/x) chains; returns `(index, is_change)` tuple; all 3 callers updated
- **No JPEG on SD loop** — stego export now returns to menu instead of looping
- **Import from SD "Saving"** — all read operations now show "Loading" screen
- **Multisig slot label overlap** — "Slot N" moved above delete button
- **MAX_SCRIPT_SIZE** — bumped from 64 to 170 bytes (supports up to 5-of-5 multisig)
- **QR frame payload** — reduced from 103 to 53 bytes for reliable device-to-device scanning
- "Wrong passphrase" → "Wrong password" on SD import failure
- Remaining Spanish comments translated to English

### Added — KasSee Web
- **KasSee Web** — browser-based watch-only companion wallet (Pure Rust → WASM)
  - Import kpub via QR scan or paste
  - Derive receive and change addresses
  - Track UTXOs and balance via Kaspa node (public or custom)
  - Build unsigned KSPT transactions
  - Fee estimation via GetFeeEstimate RPC with low / normal / priority levels
  - Send Max (sweep all UTXOs)
  - Broadcast signed transactions from KasSigner
  - UTXO explorer with manual selection
  - Address list with tap-to-verify and long-press-to-copy
  - Address verification with QR + derivation path
  - Animated QR frame indicator for multi-frame scanning
  - P2SH multisig address creation and multisig spend transactions
  - Custom node connection via Settings (WebSocket)
  - WebSocket retry logic on connection drops
  - Storage mass awareness (KIP-9/Crescendo): warns < 0.2 KAS
  - Camera QR scanner (kpub, signed TX, descriptors)
  - PWA installable on mobile
  - Sorted pubkeys — deterministic P2SH addresses regardless of kpub input order
  - v2 KSPT broadcast — parses multisig signatures, builds P2SH sig_script
  - GPL v3 license headers on all source files
  - Zero clippy warnings

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
- KSPT (KasSigner Packed Transaction) scanning, review, and signing
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
- **Waveshare ESP32-S3-Touch-LCD-2**
  - ST7789T3 320x240 display (SPI)
  - CST816D capacitive touch with hardware gestures (I2C)
  - OV5640 5MP camera with autofocus (DVP)
  - SDHOST SD card controller (native 1-bit mode, PLL clock)
  - Battery ADC monitoring (GPIO5)
  - Secure Boot V2 ready (eFuse)

- **M5Stack CoreS3 / CoreS3 Lite**
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
