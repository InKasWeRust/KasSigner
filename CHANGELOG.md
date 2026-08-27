<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Changelog

All notable changes to KasSigner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.7]: 2026-08-27

An **auditability** release. The security-critical half of the firmware moves
into a separate crate that builds and tests on any host, so a reviewer needs no
hardware and no Xtensa toolchain to run the same known-answer tests the device
runs at boot. The parsers were then held against the rusty-kaspa 2.0.1
reference implementation and its own fixtures, which surfaced and closed a
real signing gap, and a defect in the release pipeline that had made the
published unsigned hashes meaningless was found and fixed.

### Added
- **`core/`, the `kassigner-core` crate**: key derivation, mnemonics, the
  transaction parsers and serializers, sighash, Schnorr, storage encryption
  and the FAT32 layer, as a `no_std` crate with no peripheral access.
  `cd core && cargo test` on stock stable Rust, 57 tests. The firmware
  consumes it as a path dependency and re-exports the old paths, so no call
  site changed. The two things it needs from hardware arrive through
  registration points that fail closed: no logger registered means nothing
  prints, and no entropy source registered means **no signature is produced**.
- **Fuzzing**: nine parser fuzz targets with one total function per parser,
  run three ways: a deterministic mutation smoke loop under plain
  `cargo test`, a cargo-fuzz project over the same bodies for coverage-guided
  runs, and CI on every push (`.github/workflows/core.yml`).
- **Reference vectors from rusty-kaspa 2.0.1**: the boot sighash set grows
  from 27 to 30 vectors, adding proof that the signing input's own sequence is
  committed under SINGLE and two negatives that pin what is *not* committed.
  Both mainnet address rows of their table reproduce exactly; Bitcoin-versioned
  `xprv`/`xpub` from the BIP32 test vectors are refused by all six import
  entry points. The 45' multisig KAT was already a cross-implementation
  vector, reproducing the Go implementation's address, and now says so.
- **Multisig hint vectors on the host**: the V8 (KSPT v4) and V9 (PSKB) audit
  vectors decoded from their QR frames and embedded as tests, with a
  cross-format agreement test asserting every signed-over field and every
  derivation hint identical between the two encodings.
- **Lock time on the review screens**: a timelocked transaction shows
  "Locked until DAA n" or "Locked until YYYY-MM-DD HH:MM UTC" in orange on
  TX REVIEW, and a LOCKED marker on CONFIRM SEND. Zero lock time draws
  nothing, so existing screens are pixel-identical. The device discloses; it
  does not refuse.
- **The release build tests itself**: the Docker build now runs the core host
  tests before building any image, so a failing vector stops the release
  instead of shipping.

### Changed
- **One FAT32 layer**: the two per-board copies collapse into `core/fat32.rs`
  over a `BlockDevice` trait; the stricter guard from each copy survives, so
  the Waveshare mount now refuses an unsigned MBR as the M5 always did.
  Host-tested against an in-memory card image, including a corrupt circular
  chain terminating instead of hanging.
- **Batched FAT writes**: allocating a chain patches each touched FAT sector
  once per copy instead of once per cluster (a 7-cluster file costs 2 FAT
  sector writes, not 26), in an order a power loss cannot corrupt. Deletion
  is batched the same way and marks the directory entry before freeing the
  chain, so interruption leaks clusters instead of leaving a live entry over
  reusable ones.
- **Waveshare SD reselect**: back-to-back SD sessions reuse the held card via
  CMD13+CMD7 (measured 0 ms) instead of a full re-init.
- **Camera lifecycle in one place**: the camera-state sets are defined once,
  the touch debounce lives on `AppData`, and every one of the 28 camera exit
  paths arms it at the exit: 25 through `leave_camera`, and three where
  `start_review` sets the next state itself and the exit arms the guard
  directly, each with a comment saying so. The Waveshare scan-exit
  freeze was the path the old per-board cleanup missed.
- **PSKB compatibility with the reference implementation**: an unset input
  `sequence` (absent or null) now signs as `u64::MAX`, matching what the
  rusty-kaspa signer hashes; `minTime` is parsed and the transaction lock
  time is the largest across the inputs; creator-role zero counts over
  populated arrays are accepted as unset. rusty-kaspa's own committed PSKB
  fixture now parses. An explicit sequence value is always signed as given.
- **KasSee aligned with the same rules**: unset sequence is MAX and the lock
  time rides `minTime`, so both sides of the QR agree byte for byte. Also:
  the dead single-PSKT path removed, an "already accepted" broadcast reply
  treated as the success it is, and the signed-PSKB paste and copy-hex
  controls made reachable.

### Fixed
- **Published unsigned hashes now stand for the real firmware.** The unsigned
  release images were stubs: `FIRMWARE_SIGNED` is a `const bool`, and with
  `false` the compiler could prove boot never reached the wallet and deleted
  it, leaving 244-271 kB images with no wordlist and no UI against 904-912 kB
  signed. A verifier rebuilding unsigned reproduced the stub, so the
  comparison proved nothing about the firmware anyone runs. The constant is
  now read through `core::ptr::read_volatile` (a guarantee where
  `core::hint::black_box`, used briefly during 1.0.7 development, is only
  a hint): still truthful, unsigned production still halts at boot, and
  both images carry the complete firmware. The release build asserts the
  property: every unsigned app image must be full-sized and within 64 KiB
  of its signed pair, so a future compiler that defeats the barrier fails
  the build. Verification compares unsigned against unsigned.
- **The device could not sign a timelocked transaction.** PSKB `minTime` was
  skipped, so the device signed lock time 0 while the sender's extractor
  built the requested value, and the network rejected the mismatched
  signature. Fail closed, no funds at risk, but the capability did not exist.
  Now parsed, signed and shown on screen.
- **An absent PSKB sequence signed as 0**, producing signatures reference
  wallets reject. Now `u64::MAX`, per the rules above.
- **A test in `ecies.rs` had never compiled**; the `cfg(test)` code was
  unbuildable before the crate split made it buildable, and the assertion is
  fixed.

### Removed
- **`Install.sh`.** It downloaded the latest release over curl and flashed it
  with no checksum, no signature and no tag pin, on devices that at that
  point have no Secure Boot burned. That contradicted everything the
  reproducible-build design stands for. Build from source or flash a release
  binary whose hash you verified.
- **The single-PSKT envelope**, dead on both ends: nothing anywhere emits it
  and rusty-kaspa's own branch for it is `unimplemented!`.
- **Every GPIO edge-counting camera probe.** They aliased: a working camera
  read as a dead clock and vice versa. The real proof of a live camera is a
  full DMA frame and a decode, and the code now says so where the probes
  were.
- **The dead M5 SPI2 debug stub**, a 1 MHz path that was never wired in. The
  schematic shows the M5 socket is 1-bit SPI on the shared display bus, so
  the imagined fast path does not exist on this hardware.

### Security
- **Signing fails closed without entropy**: with no hardware source
  registered, `schnorr_sign` returns an error and produces no signature,
  pinned by a host test, rather than ever signing with a predictable nonce.
- **The signing keypair is written `0600`** by `gen-keypair` instead of the
  platform default.
- The build scripts pass the build configuration through verbatim and print
  which signing key, if any, they found; the embedded hash is read from the
  generated file rather than parsed out of logs.

### Known limitations
- A byte-diff of a signed image against an unsigned one is not confined to
  the signature region: the differing constants shift the compiler's output
  broadly. This is why verification compares unsigned against unsigned; a
  build where the code segments are byte-identical is on the roadmap.
- The lock-time screens disclose; they do not gate. A signer who ignores the
  orange text signs the lock time as given.

## [1.0.6]: 2026-08-18

A **multisig and hardening** release. Multisig moves to the Kaspa 45' scheme,
proven end to end on mainnet between two devices. Several security reviews of
v1.0.5 were answered: every finding was checked against the source and either
fixed, disputed with evidence, or declined with the reasoning recorded. What
shipped is below.

### Added
- **45' multisig**: cosigners derive at `m/45'/111111'/0'/<cosigner>/<chain>/<index>`,
  keys sorted so every implementation computes the same address, chain 1 for
  change. Create on device from scanned cosigner kpubs, co-sign between devices
  by QR, spend from several addresses in one transaction. The scheme is written
  up in [KIP: Multisig Wallet Conventions for Kaspa](https://github.com/kaspanet/kips/pull/39).
  Existing 44' wallets still load and spend; new wallets are 45' only.
- **Multisig change verification**: when a transaction claims an output as
  change, the device tries to reproduce it from a loaded descriptor that already
  reproduces one of the inputs. Verified is teal, unverifiable is orange with a
  `?`, and a claim the descriptor contradicts is marked FORGED and refused.
- **Descriptor backup**: the multisig descriptor is shown as a QR and can be
  saved to SD, plain or encrypted. A seed alone cannot find or spend multisig
  funds; back up seed and descriptor.
- **Multisig kpub export**: a separate, labelled `kpub Multisig QR` exports the
  45' key. The 44' export stays as the watch-only key. The two are
  byte-indistinguishable in form, so the label is the only distinction.
- **KSPT v4**: derivation hints ride the transaction so a device signs a
  multisig input without scanning its address table. Chosen by content: a
  single-sig transaction is byte-identical to before, and older firmware refuses
  the new version cleanly rather than reporting a corrupt scan.
- **Consensus sighash tests at every boot**: 27 vectors taken from the
  rusty-kaspa 2.0.1 consensus tests, all six sighash types and both transaction
  versions, run before the menu on every power-on and halt the device on
  divergence. See Fixed below for why this matters.
- **Secure Boot state on the verification screen**: five read-only eFuse bits
  shown so a user can see whether the unit is provisioned. (a)
- **KasSee multisig**: import a 45' descriptor, watch the wallet, pick UTXOs
  across addresses, consolidate, relay between cosigners, broadcast.
- **KasSee network layer reworked**: the public node is held for the session,
  failing resolvers are remembered and skipped, the WebSocket is pooled, a
  timeout drops the socket instead of counting as success, and history scans run
  spaced instead of all at once. Wallet load went from minutes to seconds on a
  wallet with deep history and the CORS noise is gone.

### Fixed
- **The sighash self-tests had never executed in any build.** They halted on
  the stack guard before reaching the test and nothing reported it. Moved to the
  heap, promoted into the boot known-answer set, and measured 27/27 on hardware.
- **Covenant binding validation**: a malformed `covenantId` could leave the
  field zeroed with the binding still active, or carry an attacker-chosen prefix.
  Both members are now required, range and duplicate checked, and a decode error
  rejects the transaction rather than warning. (a)
- **`covenantId` was dropped from the round trip** and covenant outputs lost
  their binding when re-emitted. Both restored.
- **Covenant spends were under-paying fees** and would have been rejected at
  broadcast; fee floor corrected, proven on mainnet.
- **PSKB round trip**: the device accepted more inputs than it could return.
  Emit buffer raised, a pre-flight check before any key operation, capacity from
  5 inputs to 9. SD transaction files were capped at 1,024 bytes in three places;
  the encrypted KSPT round trip could not complete; the emitted frame count could
  wrap above 255. All fixed, and a QR density that will not fit is greyed out
  with the reason shown.
- **Parser hardening**: declared counts are now checked, `{` and `[` are
  tracked separately with a depth ceiling, all duplicate keys are guarded, and
  both binary parsers require the buffer to be fully consumed. (a)
- **SD reads**: a short FAT chain and a circular FAT chain are now both
  detected and named on screen instead of returning a truncated file as success. (a)
- **KasSee amounts** above 2^53 sompi lost precision in `Number()`; all spend
  paths now use BigInt. (a)
- **QR decoder bounds**: three grid bounds added after host fuzzing of
  `rqrr_nostd`, one reachable at real capture geometry. Decode rates unchanged.
- **Multi-frame QR limit** raised from 40 to 64 frames, matched between KasSee
  and firmware. (a)
- **Multisig signing was doing hundreds of derivations per input**: the hinted
  key was derived once per input and once per cosigner position. Hoisted; signing
  is now effectively independent of N.
- **A created 45' wallet did not sort its cosigners** and produced an address no
  other implementation computes; the kpub export still emitted 44' after
  creation moved to 45'; the output serializer stripped every output's
  derivation map; a multisig transaction matching no key still emitted a
  signature. All fixed and verified on two devices.
- **The descriptor QR was drawn under signed-transaction overlays.**
- **The camera XCLK check reported a dead clock on a working device.**

### Security
- Several security reviews of v1.0.5 answered in full. Every claim was verified
  against the code before anything changed; several were refuted from source.
  What was fixed is in this entry; the reasoning behind what was declined is in
  [SECURITY.md](SECURITY.md).
- **Backup KDF stays at PBKDF2-HMAC-SHA256, 100,000 rounds, by decision.** A
  six-fold increase buys under three bits against rented GPUs; the salt and the
  password are where the security is. The container reserves a KDF id for a
  memory-hard replacement.
- **Integer overflow checks** now enabled on the KasSee release profile. (a)
- **Measurement features cannot reach a shipped build**: every diagnostic flag
  is a compile error together with `production`.
- **Hardware RNG min-entropy measured for the first time** (SP 800-90B, offline)
  and health checks enforced on every draw: a degraded window refuses to sign,
  encrypt or generate a salt.

(a) Reported by [KodinglsFun](https://x.com/KodinglsFun) in a review of v1.0.5.

### Known limitations
- A 45' PSKB from an external coordinator that carries no derivation hints
  cannot yet be signed; KasSee always writes them, so this affects other
  coordinators only.
- Multi-frame QR transfers still carry no session identifier. Every mixed
  assembly we can construct fails the parse, so the practical effect is a
  failed scan, but universal rejection is not proven; the device review
  screen remains the control on what is signed.
- The multisig descriptor is a second secret with the same backup requirement as
  the seed. Losing it loses access to the funds.

## [1.0.5]: 2026-08-03

A **security and hardening** release. A full security review of the codebase
was answered; this release closes most of what it found. It also adds a second
way to hide a seed backup inside a photograph, and fixes three defects that made
the existing one identifiable.

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

  **This does not mean seeds from earlier versions rested on nothing.** Seed
  generation mixes eight camera captures into the entropy pool, and the camera
  carried it while the RNG contributed nothing. But the per-pixel health checks
  that verify those captures actually varied shipped in this release, not before:
  on 1.0.0 through 1.0.4 the camera check was satisfied by the capture buffer
  pointer being non-null and never tested the data. So for those releases the
  camera contribution is unverified rather than absent, and users holding
  significant funds on an automatically generated seed from that era should
  consider migrating. It is rated Critical because a redundant source silently
  returning zeros for the life of a project is exactly the failure that must
  never go undetected.
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
- Multi-frame QR transfers still carry no session identifier. Every mixed
  assembly we can construct fails the parse, so the practical effect is a
  failed scan, but universal rejection is not proven; the device review
  screen remains the control on what is signed.

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
- **ZK Price Oracle (KasSee)**: live KAS/USD sourced from Pyth + Wormhole and proven on-chain with a zero-knowledge proof; ambient read plus pay-to-refresh.
- **Stealth payments (KasSee)**: dual-key stealth addresses (ECDH with view tags) so anyone can pay you without linking payments to your public address; send, scan, and an optional stealth indexer for recovery.
- **Covenant-aware PSKB signing (KasSigner)**: the KSPT format gains v3 (u16 redeem length for larger covenant scripts) and a covenant-binding flag (`0x04`): outputs carry a `covenant_id` and auth-input index, parsed and preserved through the sign round-trip. The signer recognizes the P2SH covenant redeem scripts and signs the matching input.
- **On-device covenant review (KasSigner)**: a transaction spending a covenant P2SH is labelled as such on the confirm screen, and every output is shown with its amount and its bech32 destination. Before any of that, the redeem script supplied by the host is checked to hash to the P2SH commitment in the UTXO being spent, and an input whose script does not match is reported as unrecognised and left unsigned. The device does not decode covenant parameters such as recipient, cap, timelock or heir.
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
- **CRITICAL: Waveshare seed generation was deterministic**: every entropy source returned zeros (TRNG at the wrong register, camera reading stale PSRAM, SYSTIMER unlatched); the pool was SHA-256 of zeros on every generation. Fixed by reading the DMA write buffer, latching SYSTIMER, and mixing eFuse chip-unique data.
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
- Supports V1 to V13, all ECC levels, full Reed-Solomon error correction
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
