<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.3] — 2026-04-16

### Fixed — Multisig SD workflow
- **Red trash button on multisig SD file list was unresponsive.** The `SdKpubFileList` touch handler (used by Multisig Address, Multisig Descriptor, and kpub import file pickers) routed every tap on a file row — including the red trash icon area — to "load this file". Mirrored the existing `SdFileList` pattern: right ~40px of each card (`x > 236`) now triggers a delete intent. Added a new `sd_delete_return: AppState` field on `AppData` so `SdDeleteConfirm` can bounce back to the correct list after confirm or cancel (falls back to filename-extension sniffing for the legacy seed-backup/KSPT callers, so those continue to work unchanged).
- **M5Stack: multi-frame QR scan progress dots invisible.** The dots render at `y=226..240`; the M5 camera viewfinder was sized `vf_h=192` starting at `vf_y=44`, extending to `y=236` — directly over the dots. Shrunk M5 `vf_h` from 192 to 180 (matching Waveshare) so the dot strip is preserved. Viewfinder still occupies the full chrome-adjusted region; no visible size change on the already-centered 240-wide preview.

### Fixed — Multisig SD workflow
- **Passphrase entry keyboards full-screen flashed on every keypress** — root cause: three handlers (`SdRestorePassphrase`, `SdXprvExportPassphrase`, `SdXprvImportPassphrase`) were missing the `1 =>` match arm that calls `draw_keyboard_screen` for valid character entry. Typed chars fell through to `_ => {}` → trailing `needs_redraw = true;` → full-screen redraw (header + keyboard layout + input strip). Fixed by adding the arm, adding partial redraws on backspace/space, and scoping `needs_redraw = true` to page change / OK / back only.
- **Keyboard per-keypress flash reduced** across all keyboard input screens via opaque-glyph rendering. Added `draw_prop_text_opaque()` in `ui/prop_fonts.rs` — glyphs render with opaque background via one `fill_contiguous` SPI burst per glyph (BG + FG pixels in a single transaction). No pre-clear of the text strip needed; unchanged glyphs transition same-to-same (invisible). Keyboards using this path (SD filename keyboards, password, stego description/hint, seed-word import) also feel more responsive.
  - Added `draw_lato_22_opaque()` wrappers in both `hw/display_ws.rs` and `hw/display_m5.rs`.
  - `draw_keyboard_screen` and `draw_import_keyboard` in `ui/screens.rs` rewritten to use opaque paint + narrow tail clear only. Same visual fidelity (fonts, colors, layout, cursor all preserved).
- **Password keyboard `needs_redraw` cleanup** (SdKsptEncryptPass): removed trailing unconditional `needs_redraw = true;` that was overriding the partial-redraw pattern. Matches the pattern used in address/descriptor filename keyboards.
- **Multisig address/descriptor filename keyboard blink fix**. The trailing `needs_redraw = true;` at the end of the `SdMsAddrFilename` and `SdMsDescFilename` handlers unconditionally overwrote the `needs_redraw = false` set by char-entry and backspace arms, forcing a full redraw (→ visible BG flash) on every keypress instead of the partial input-strip redraw. Moved `needs_redraw = true` to only fire on page change, OK, and back-press. Miss-tap no longer triggers a wasteful redraw either.
- **Multisig address loaded from SD** no longer routes through the signed-TX pipeline. Dedicated `MultisigShowAddressQR` dual-path renders the loaded address with the correct "MULTISIG QR" title; tap returns to main menu (no bogus "SIGNED TX" popup, no wrong TX/KSP filename, no multi-frame mode choice for single-frame data).
- **Multisig descriptor loaded from SD** now parses the `multi(M,hex1,hex2,...)` text and populates `ms_creating` (view-only, `.active=false`), then routes to the existing `MultisigDescriptor` screen — same participant-summary view as the live flow. Back button in that state branches on `ms_creating.active` so the SD-loaded flow returns to main menu.
- **CRITICAL: buffer overflow panic** on loading a 2-of-2+ descriptor from SD. Root cause: the descriptor bytes (up to 400) were being copied into `kpub_data` (120 bytes), causing `range end index 204 out of range for slice of length 120` and forcing a reboot. Fixed by parsing directly from the read buffer — no intermediate copy into the undersized `kpub_data`. Same defensive clamp added to the address load path.
- **Descriptor save flow** now follows the same keyboard+encrypt+overwrite pattern as KSPT and multisig address saves. New `SdMsDescFilename` and `SdMsDescEncryptAsk` states. Auto-generated filename uses `MD` prefix (e.g., `MD000001.TXT`). Descriptor text is staged into `signed_qr_buf` (1024 bytes) instead of `kpub_data` to handle large N-of-M configurations. Encrypt path reuses `SdKsptEncryptPass` with `sd_txt_origin=2`. No more hardcoded `MSDESC.TXT` overwrite.
- **Loading label** on SD file tap is now contextual: "Reading kpub...", "Reading address...", "Reading descriptor..." based on `txt_import_type` (no more misleading "Reading kpub..." for descriptors).
- **Descriptor load error bailout**: parse failure or invalid file size now returns to main menu after the error screen (prevents re-tapping the same bad file on the list).
- New helper: `parse_descriptor()` in `handlers/sd.rs` — validates prefix/suffix, single-digit M, exactly 64 hex chars per pubkey, comma separators, max keys per `MAX_MULTISIG_KEYS`.

### Changed
- Bootloader `Cargo.toml` version bumped to 1.0.3
- `fw_update::CURRENT_VERSION` bumped to 10003
- `kassee/Cargo.toml` version bumped to 1.0.3

## [1.0.2] — 2026-04-13

### Added — Device Firmware
- **cam_dma camera pipeline** — new DMA-based 480×480 YUV422 capture for Waveshare, replacing DvpCamera. Direct SYSTIMER register reads for QR decode performance timing.
- **OV2640 runtime auto-detect** — Waveshare now probes sensor ID at boot; OV2640 wide-angle supported alongside OV5640 (`camera_ov2640.rs`, `cam_dma.rs`)
- **kpub multi-frame QR export** — choose 2/3/4 frames, auto-cycle or manual navigation, save to SD, import from SD. New states: `ExportKpubFrameCount`, `ExportKpubModeChoice`, `ExportKpubPopup`, `KpubScannedPopup`, `SdKpubFileList`, `SdKpubFilename`
- **Signed QR frame size choice** — `ShowQrFrameChoice` lets user pick single vs multi-frame signed KSPT export
- **Multisig address SD save** — `MultisigSaveAddrAsk` state with optional encryption
- **SD overwrite confirmation** — generic `sd_overwrite_next`/`sd_overwrite_back` state machine prompts before overwriting existing files
- **SD file helpers** — extracted `sd_file_exists()`, `build_filename_83()`, `write_file_to_sd()`, `generate_trng_nonce()` as reusable functions
- **Multi-frame QR buffers expanded** — `MF_BUF` 2KB→5KB, `MF_RECEIVED`/`MF_FRAG_SIZE` 8→20 slots for larger KSPT payloads
- **Account-level PSKT signing fallback** — when address-level key doesn't match, tries account xonly pubkey (`acct.public_key_x_only()`)

### Fixed — Device Firmware
- **CST816D touch sensitivity** — threshold 0x28→0x50, low-power scan 0x10→0x20, auto-sleep disabled. Fixes ghost touches on Waveshare.

### Code Quality
- **Clippy cleanup** — zero warnings on `clippy::all` for both bootloader and KasSee WASM
- Inlined 38 format args, removed 9 unnecessary casts, added digit separators
- Eliminated 3× `Vec::clone()` in UTXO selection (sort in place, consume by value)
- QR SVG generation: `write!()` instead of `&format!()` — zero allocation per module
- `ws_rpc_call`: `.take()` instead of `.clone()` on WebSocket result
- `funded_addresses`: counts unique script_public_keys by reference
- Removed 7 redundant `#[allow(dead_code)]` directives
- 36 well-documented pedantic-tier `#[allow]` directives in `main.rs` for embedded patterns
- Removed dead code: `key_rect()` in pin_ui, `_word_idx` in sdcard_ws
- Removed orphaned zero-width text steganography code from `features/stego.rs` (unused constants, templates, `decode_stego_text()`, `contains_stego()`) — JPEG EXIF stego uses base64, not ZW characters

### KasSee Web
- **Donate card** — rebuilt with fully inline styles, no CSS conflicts with app screens
- **Broadcast → Donate flow** — after successful TX, user sees donate card before dashboard
- **UTXO selection fix** — sort in place + consume by value; sweep now takes top 5 UTXOs by size
- Fixed `manifest.json`, `lib.rs`, `Cargo.toml` version strings to 1.0.2
- Orphan file cleanup: removed stale WASM copies and leftover CSS
- GPL-3.0 header added to `constellation/index.html`
- Three-way sync verified (GitHub, gh-pages, source repo)

### QR Decoder
- **rqrr no_std fork** — replaced custom per-platform decoders (`decoder_ws.rs`, `decoder_m5.rs`) with `rqrr_nostd`, a no_std zero-dependency fork of rqrr 0.10.1
- Supports V1–V40, all ECC levels, full Reed-Solomon error correction
- Single-pass accept — rqrr's RS verification replaces the old 5-pass voting (Waveshare) and 3-consecutive match (M5Stack) heuristics
- Unified `rqrr_decode()` in `camera_loop.rs` for both platforms
- Deleted `bootloader/src/qr/decoder_ws.rs` and `bootloader/src/qr/decoder_m5.rs`

### Infrastructure
- Bootloader `Cargo.toml` version bumped to 1.0.2
- Docker build tags updated to v1.0.2
- **Version cleanup** — removed hardcoded version strings from filenames, titles, and docs; splash screen now reads version dynamically from `CURRENT_VERSION`

### Hardware
- **OV2640 wide-angle camera** — full driver + DMA pipeline for Waveshare 24-pin connector
- Evaluated camera modules (OV2640, OV5640, OV3660, GC2145) for Waveshare ESP32-S3 24-pin connector


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
  - OV5640 5MP camera (DVP)
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
