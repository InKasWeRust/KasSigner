<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.5]: 2026-08-03

A **security and hardening** release. A full external audit produced 40 findings;
this release closes most of them. It also adds a second way to hide a
seed backup inside a photograph, and fixes three defects that made the existing
one identifiable.

Two of the findings date from the start of the project and are described in the
Security section below.

### Added
- **Picture carrier for seed backups**: a second way to hide an encrypted seed in
  a JPEG, this time in the image's own compressed data rather than in its metadata.
  Choose at export:
  - **Descriptor** (the existing carrier) survives re-saving the photo, and is
    destroyed if anything strips metadata, which messaging apps and most social
    platforms do routinely.
  - **Picture** (new) ignores metadata stripping entirely, and is destroyed if the
    photo is re-compressed.
- **EXIF template for photos with no metadata**: screenshots and messaging-app
  downloads have no EXIF at all. Rather than leaving a two-tag block that no camera
  would produce, the device now synthesises a plausible software-export profile.
  It deliberately claims no camera make or model, because a fabricated camera
  identity can be contradicted by the photo's own compression parameters.
- **Camera and QR scanning reworked**: many rounds of work on the capture and
  decode path, alongside a hardware change on the Waveshare board. The visible
  result is a smoother viewfinder: capture, display and decoding used to share a
  single CPU core, so the preview froze for the length of every decode attempt.
  The ESP32-S3's second core was sitting idle, and decoding now runs there, so
  the image keeps moving while a scan is in progress.
- **Structural entropy health tests**: the hardware RNG is now checked for
  *structure*, not only for being stuck. A free-running counter, a stuck half-word
  and a stuck register are all refused. Boot logs report `stuck n/32 mono false`.

### Fixed
- **Steganography artifacts were identifiable three ways**: an audit hid one
  backup among 200 photographs and found it every time, with no false positives:
  a fixed text string at the head of every artifact, an EXIF tag count no camera
  produces, and a segment order no encoder writes. All three are closed and the
  same test now finds nothing. The photo's own camera metadata. Make, model, date,
  thumbnail. Is preserved intact rather than discarded.
- **Re-exporting onto the same photo left the previous encrypted seed in the file.**

### Security
- **The hardware random number generator had never been read.** It was addressed at
  the wrong location for this chip and returned zeros on every device since the
  project started. Found by measurement, not by inspection.

  **Seeds generated on earlier versions are not weak, and no action is needed.**
  Seed generation mixes eight full camera frames, with per-pixel health checks, into
  the entropy pool; the camera carried it while the RNG contributed nothing. The
  defect removed a source that was meant to be one of several, rather than the only
  one. It is rated Critical because a redundant source silently returning zeros for
  the life of a project is exactly the failure that must never go undetected, not
  because keys were compromised.
- **Releases 1.0.0 through 1.0.4 carry signatures that cannot be verified.** The
  signing tool computed the challenge incorrectly, so no BIP-340 verifier accepts
  them. **This affects only the check that a downloaded firmware file is authentic.**
  It never touched transaction signing, key derivation or funds. Those use a
  separate, correct code path, and every release signed transactions normally.
  Both sides are now anchored to a published test vector, checked at every boot.
- **Radio lockdown was not doing what it claimed.** It wrote to the wrong register,
  so the WiFi/Bluetooth power domain stayed energised from reset, and on M5Stack
  neither lockdown phase ran at all. **Nothing was transmitted:** the firmware
  contains no network stack, no drivers and no radio initialisation, so there is
  nothing on the device capable of using those radios. The defect left a powered
  peripheral where the design called for an unpowered one. Defence in depth that
  was not actually in place. Rather than an open radio.
- **Verification codes widened from 4 bytes to 8.** The firmware attestation and
  the transaction payload code are compared by a human against another screen.
  32 bits can be brute-forced by the very attacker they exist to catch; 64 cannot.
- **Constant-time key derivation**: BIP32 child-key comparison and reduction no
  longer branch on secret values.
- **Anti-glitch counter now detects order, not just count**: the previous version
  could be satisfied by skipping one stage and gaining another elsewhere.
- **Entropy failures refuse to sign** rather than silently falling back to a
  deterministic nonce.
- **Secrets wiped on drop** for mnemonics and extended public keys.
- **KasSee no longer publishes wallet state on `window`**: the derived addresses,
  UTXO set and pending transaction are no longer reachable by page scripts.

### Known limitations
- Backup password stretching is still PBKDF2. A memory-hard replacement is
  designed but deferred, so a weak backup password can be attacked offline.
  Use a strong one, and a strong passphrase.
- Multi-frame QR transfers still carry no session identifier. Every consumer
  rejects a mixed assembly, so the effect is a failed scan rather than a wrong
  result.

## [1.0.4]: 2026-07-02

The **Covenants++ (cov++)** release. KasSee builds covenant transactions; KasSigner
reviews and signs them air-gapped; KasSee broadcasts. The same
unsigned-build → sign-offline → broadcast flow, now for programmable covenants on
**Kaspa Toccata** (script introspection, `OP_CAT`, `OP_ZK_PRECOMPILE`). Exercised on
the TN10 test network.

### Added
- **Covenant suite (KasSee)**: build, fund, and spend a family of on-chain covenants:
  - **Piggy Bank**: save toward a goal or deadline; break it open to withdraw.
  - **Time-Locked Savings**: lock funds until a date; no early access, not even by you.
  - **Dead Man's Switch**: heir inherits after inactivity; a heartbeat resets the timer.
  - **Allowance**: a beneficiary withdraws up to a cap, with a cooldown between withdrawals.
  - **Spending Limit**: a per-withdrawal cap with cooldown, across the whole balance.
  - **Merkle Whitelist**: spend only to an approved set, proven with a Merkle proof (`OP_CAT`).
  - **Direct Channel**: payment channel with arbiter dispute resolution.
  - **Oracle**: release on an oracle attestation.
  - **PayJoin**: anonymous payment covenant.
  - **Commit-Reveal**: MEV-resistant inscriptions.
  - **Private Swap**: atomic swap via adaptor signatures: no preimage, no on-chain link.
  - **KIP-20 Vaults**: tagged and split covenant-id-aware vaults.
  - **Crowdfunding**: ZK-gated goal-and-deadline pledge covenant.
- **ZK Price Oracle (KasSee)**: live KAS/USD sourced from Pyth + Wormhole and proven on-chain with a zero-knowledge proof; ambient read plus pay-to-refresh.
- **Stealth payments (KasSee)**: dual-key stealth addresses (ECDH with view tags) so anyone can pay you without linking payments to your public address; send, scan, and an optional stealth indexer for recovery.
- **Covenant-aware PSKB signing (KasSigner)**: the KSPT format gains v3 (u16 redeem length for larger covenant scripts) and a covenant-binding flag (`0x04`): outputs carry a `covenant_id` and auth-input index, parsed and preserved through the sign round-trip. The signer recognizes the P2SH covenant redeem scripts and signs the matching input.
- **On-device covenant review (KasSigner)**: covenant details are shown on the review screen before signing.
- **ECIES (KasSigner, `wallet/ecies.rs`)**: encrypt-to-pubkey / decrypt-with-key via ECDH + BLAKE2B-256 + AES-256-GCM (33-byte ephemeral pubkey, 12-byte nonce, AEAD tag), for stealth / recovery payloads.

### Changed
- **KasSee WASM refactor**: split `lib.rs` (7291 → ~1,190 lines) and `kspt.rs` into per-feature modules (adaptor / stealth / oracle-mb / vault / covenant / zk, plus the `kspt_*` covenant-builder modules). All `wasm-bindgen` export names and behaviour unchanged.
- **KasSee tooling**: crate/module documentation, `rustfmt.toml`, a CI workflow, and SPDX / repository Cargo metadata; kassee crate version aligned to 1.0.4.

## [1.0.3]: 2026-04-16

### Added
- **Menu & Export restructure**: Tools reorganized into Seed Tools / Import-Export / Single Signature / Multisig; Export into Seed Backup / Watch-Only / Signing Keys / Steganography, with a distinct icon per item.
- **Sign TX screen** gains "EXP. KPUB" and "SCAN PSKB" buttons (PSKB replaces KSPT in the step guide).
- **Sign-message SD save** prompts for a filename (auto-incremented `SG…TXT`) instead of overwriting a fixed file.
- **SeedQR numeric mode** for standard compliance (12-word → V2 25×25, 24-word → V3 29×29).
- **Expanded entropy sources**: SYSTIMER, eFuse MAC + unique ID, idle timing; camera sensor noise remains primary.
- **HD multisig address browser** (v1.1.0 foundations): navigate the shared cosigner address series on `MultisigShowAddress`; index is RAM-only.
- **UX polish**: SIGNER/FRAMES badges on multi-frame QR, unified multi-QR layout, single-sig skips the density picker, unlimited change-chain address browsing (on-demand derivation).

### Fixed
- **CRITICAL: Waveshare seed generation was deterministic**: every entropy source returned zeros (TRNG at the wrong register, camera reading stale PSRAM, SYSTIMER unlatched); the pool was SHA-256 of zeros on every generation. Fixed by reading the DMA write buffer, latching SYSTIMER, and mixing eFuse chip-unique data. (TRNG stays dead without WiFi. A hardware limitation.)
- **CRITICAL: all change addresses rendered as `kaspa:qqqqq…`**: the change chain was never derived; all three derive paths now populate `change_pubkey_cache`.
- **Multisig P2SH mismatch across devices**: own-key select now uses the account-level x-only pubkey (matching `import_kpub()`), so both devices build byte-identical scripts and the same P2SH address.
- **Multisig SD workflow**: descriptor buffer-overflow panic fixed (parse from the read buffer, no undersized copy); descriptor/address loads no longer route through the signed-TX pipeline; keyboard full-screen flashing removed (partial redraws); the trash button on file lists now deletes; M5 QR progress dots no longer hidden by the viewfinder.
- **Navigation & UX**: dead-space blink eliminated across menus and dialogs (redraw only on state change); context-aware back buttons; delete-active-seed auto-activates the next slot; instant sign-message feedback.

### Changed
- Zero clippy warnings (auto + manual fixes; targeted `#[allow]`s for embedded patterns).
- Labels: "Phone" → "Wallet" on kpub export; outputs are 1-indexed in the QR view.

## [1.0.2]: 2026-04-13

### Added: Device Firmware
- **cam_dma camera pipeline**: new DMA-based 480×480 YUV422 capture for Waveshare, replacing DvpCamera. Direct SYSTIMER register reads for QR decode performance timing.
- **OV2640 runtime auto-detect**: Waveshare now probes sensor ID at boot; OV2640 wide-angle supported alongside OV5640 (`camera_ov2640.rs`, `cam_dma.rs`)
- **kpub multi-frame QR export**: choose 2/3/4 frames, auto-cycle or manual navigation, save to SD, import from SD. New states: `ExportKpubFrameCount`, `ExportKpubModeChoice`, `ExportKpubPopup`, `KpubScannedPopup`, `SdKpubFileList`, `SdKpubFilename`
- **Signed QR frame size choice**: `ShowQrFrameChoice` lets user pick single vs multi-frame signed KSPT export
- **Multisig address SD save**: `MultisigSaveAddrAsk` state with optional encryption
- **SD overwrite confirmation**: generic `sd_overwrite_next`/`sd_overwrite_back` state machine prompts before overwriting existing files
- **SD file helpers**: extracted `sd_file_exists()`, `build_filename_83()`, `write_file_to_sd()`, `generate_trng_nonce()` as reusable functions
- **Multi-frame QR buffers expanded**: `MF_BUF` 2KB→5KB, `MF_RECEIVED`/`MF_FRAG_SIZE` 8→20 slots for larger KSPT payloads
- **Account-level PSKT signing fallback**: when address-level key doesn't match, tries account xonly pubkey (`acct.public_key_x_only()`)

### Fixed: Device Firmware
- **CST816D touch sensitivity**: threshold 0x28→0x50, low-power scan 0x10→0x20, auto-sleep disabled. Fixes ghost touches on Waveshare.

### Code Quality
- **Clippy cleanup**: zero warnings on `clippy::all` for both bootloader and KasSee WASM
- Inlined 38 format args, removed 9 unnecessary casts, added digit separators
- Eliminated 3× `Vec::clone()` in UTXO selection (sort in place, consume by value)
- QR SVG generation: `write!()` instead of `&format!()`: zero allocation per module
- `ws_rpc_call`: `.take()` instead of `.clone()` on WebSocket result
- `funded_addresses`: counts unique script_public_keys by reference
- Removed 7 redundant `#[allow(dead_code)]` directives
- 36 well-documented pedantic-tier `#[allow]` directives in `main.rs` for embedded patterns
- Removed dead code: `key_rect()` in pin_ui, `_word_idx` in sdcard_ws
- Removed orphaned zero-width text steganography code from `features/stego.rs` (unused constants, templates, `decode_stego_text()`, `contains_stego()`): JPEG EXIF stego uses base64, not ZW characters

### KasSee Web
- **Donate card**: rebuilt with fully inline styles, no CSS conflicts with app screens
- **Broadcast → Donate flow**: after successful TX, user sees donate card before dashboard
- **UTXO selection fix**: sort in place + consume by value; sweep now takes top 5 UTXOs by size
- Fixed `manifest.json`, `lib.rs`, `Cargo.toml` version strings to 1.0.2
- Orphan file cleanup: removed stale WASM copies and leftover CSS
- GPL-3.0 header added to `constellation/index.html`
- Three-way sync verified (GitHub, gh-pages, source repo)

### QR Decoder
- **rqrr no_std fork**: replaced custom per-platform decoders (`decoder_ws.rs`, `decoder_m5.rs`) with `rqrr_nostd`, a no_std zero-dependency fork of rqrr 0.10.1
- Supports V1–V40, all ECC levels, full Reed-Solomon error correction
- Single-pass accept. Rqrr's RS verification replaces the old 5-pass voting (Waveshare) and 3-consecutive match (M5Stack) heuristics
- Unified `rqrr_decode()` in `camera_loop.rs` for both platforms
- Deleted `bootloader/src/qr/decoder_ws.rs` and `bootloader/src/qr/decoder_m5.rs`

### Infrastructure
- Bootloader `Cargo.toml` version bumped to 1.0.2
- Docker build tags updated to v1.0.2
- **Version cleanup**: removed hardcoded version strings from filenames, titles, and docs; splash screen now reads version dynamically from `CURRENT_VERSION`

### Hardware
- **OV2640 wide-angle camera**: full driver + DMA pipeline for Waveshare 24-pin connector
- Evaluated camera modules (OV2640, OV5640, OV3660, GC2145) for Waveshare ESP32-S3 24-pin connector


## [1.0.1]: 2026-03-31

### Milestone: First Air-Gapped Multisig on Kaspa Mainnet
- **P2SH multisig**: fund and spend from M-of-N Pay-to-Script-Hash multisig addresses
- **Co-signing flow**: device A signs partial → QR → device B adds signature → fully signed
- **Two co-signing modes**: direct device-to-device QR, or via KasSee relay
- TX `8a6652fb...`: first P2SH multisig funding on Kaspa mainnet (air-gapped)
- TX `d1ffdb9f...`: first P2SH multisig spend (2-of-2, direct device-to-device)
- TX `2b53e35a...`: second P2SH funding (reversed kpub order, sorted keys verified)
- TX `2b718bd5...`: second P2SH multisig spend (2-of-2, via KasSee relay)

### Added: Device Firmware
- **P2SH script detection** (`OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL`) in transaction analysis
- **Redeem script** field on transaction inputs for P2SH round-trip
- **v2 KSPT serializer/parser** carries redeem scripts between signers
- **KSPT v1 flags 0x02**: optional redeem script per input for P2SH spending
- **ShowQR sig status overlay**: "PARTIAL 1/2" (orange) or "FULLY SIGNED 2/2" (teal)
- **Multi-frame v2 KSPT detection** in camera. Previously only single-frame v2 was recognized
- **QR frame padding**: last frame padded to minimum 20 bytes for reliable scanning
- **"No seed loaded"** warning replaces generic "TX Cancelled" when signing without a seed
- **BIP85 auto-load**: derived child seed loads into slot immediately after derivation
- **BIP85 success sound**: plays "tururi" (success) instead of "bip" (task_done)
- **Home button** on SD format warning screen (was dead zone)
- **Click sound** on back/home during format warning
- **SD backup delete** with hold-to-confirm (matches seed delete UX: CANCEL left, DELETE right, HOLD 4s)
- **SD file list** fingerprint matching ("Seed #1", "Seed #2" labels)
- **SD progress bars** on seed restore decrypt and xprv import
- **Pre-signing size check**: rejects transactions exceeding 1024-byte buffer with "Too many inputs! N inputs. Max 5. Compound first."
- **KSSN hex dump** as single line (was multi-line, required manual cleanup)
- **Hex buffer overflow** handled gracefully with warning (no panic)

### Fixed: Device Firmware
- **Sighash**: All sub-hashes and final digest now use keyed Blake2b-256 with `TransactionSigningHash` domain key (was unkeyed)
- **Output hash**: Added `script_len` (u64 LE) prefix before script bytes in `hash_output`
- **Schnorr challenge**: Switched from plain `SHA256(R||P||msg)` to BIP-340 tagged hash `SHA256(tag||tag||R||P||msg)`
- **Change address signing**: `find_address_index_for_pubkey` now searches both receive (m/.../0/x) and change (m/.../1/x) chains; returns `(index, is_change)` tuple; all 3 callers updated
- **No JPEG on SD loop**: stego export now returns to menu instead of looping
- **Import from SD "Saving"**: all read operations now show "Loading" screen
- **Multisig slot label overlap**: "Slot N" moved above delete button
- **MAX_SCRIPT_SIZE**: bumped from 64 to 170 bytes (supports up to 5-of-5 multisig)
- **QR frame payload**: reduced from 103 to 53 bytes for reliable device-to-device scanning
- "Wrong passphrase" → "Wrong password" on SD import failure
- Remaining Spanish comments translated to English

### Added: KasSee Web
- **KasSee Web**: browser-based watch-only companion wallet (Pure Rust → WASM)
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
  - Sorted pubkeys. Deterministic P2SH addresses regardless of kpub input order
  - v2 KSPT broadcast. Parses multisig signatures, builds P2SH sig_script
  - GPL v3 license headers on all source files
  - Zero clippy warnings

### Verified on Mainnet
- TX `2faa58b2...`: 1-input, 1-output (first air-gapped broadcast)
- TX `450e2e2d...`: 1-input, 1-output (fee logic)
- TX `35013c16...`: 1-input, 1-output (storage mass)
- TX `277517da...`: 3-input, 1-output (multi-UTXO across receive + change chains)

## [1.0.0]: 2026-03-28

### Added
- Air-gapped Kaspa offline signing device: 100% Rust, no_std, no network stack
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
- Steganographic backup. Encrypted seeds hidden in JPEG EXIF on SD card
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
- Live display mirror. Stream screen to Mac/PC via serial for presentations
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
