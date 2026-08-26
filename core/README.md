<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# kassigner-core

The hardware-free half of the KasSigner firmware, as a separate crate.

Everything security-critical that does not touch a peripheral lives here: key
derivation, mnemonics, the transaction parsers and serializers, sighash,
Schnorr signing, storage encryption, and the FAT32 layer. The firmware
(`bootloader/`) consumes it as a path dependency and re-exports its modules
under the paths it has always used, so the split changed no call site.

The point of the split is that this code builds and runs on any host. Before
1.0.7 it was inside a `no_main` bare-metal binary and the only way to exercise
it was to flash a device. Now:

```
cd core
cargo test
```

Stock stable Rust. No ESP-IDF, no Xtensa toolchain, no espflash, no hardware.
If you are auditing KasSigner, this is where to start.

## What it contains

| module | what |
|---|---|
| `wallet::bip39`, `bip32`, `bip85` | mnemonics, seeds, key derivation, deterministic child mnemonics |
| `wallet::schnorr` | BIP-340 signing and verification, RFC-6979 nonces hedged with hardware entropy |
| `wallet::sighash`, `transaction` | Kaspa consensus sighash, transaction model, script classification, multisig |
| `wallet::pskt`, `std_pskt` | KSPT (the device's compact binary) and PSKB (the rusty-kaspa interchange format) |
| `wallet::xpub`, `address` | kpub/xprv import and export, Kaspa address encoding |
| `wallet::storage`, `ecies` | seed-at-rest encryption, ECIES for covenant payloads |
| `crypto::constant_time`, `flow` | constant-time comparison, flow-integrity counters |
| `qr::payload` | QR payload envelope classification |
| `fat32` | the FAT32 filesystem layer, over a `BlockDevice` trait |
| `types`, `ext` | shared data types; the extended pubkey bank scan |

## What it deliberately does not contain

No peripheral access, no `esp-hal`, no interrupt handlers, no clock. The two
things this code needs from the hardware arrive through registration points
the firmware sets once at boot, and both fail closed when nothing is
registered:

- **`log::set_logger`**, the serial printer. With none registered, `log!`
  formats nothing at all. This is how `silent` production builds stay silent.
- **`entropy::set_source`**, the hardware entropy fill. With none registered,
  `entropy::fill` returns `Err`, `schnorr_sign` returns
  `SchnorrError::EntropyUnavailable`, and **no signature is produced**. A test
  that forgets to register a source therefore refuses to sign rather than
  signing with a predictable nonce. `self_tests::signing_refuses_without_entropy`
  pins that behaviour.

Hardware entropy collection itself (`crypto::entropy` in the firmware: SAR
ADC, RC_FAST, systimer, IMU and camera noise), the QR encoder, the camera, the
display and the two SD transports all stay in `bootloader/`.

## Tests

37 tests, about seven seconds. Three groups:

**`self_tests`**. The same known-answer tests the device runs at every boot,
through the same entry points (`app/boot_test.rs` calls them on hardware).
Pass criterion is identical: every vector in every set. Covers BIP39, BIP32,
BIP85, Schnorr, sighash (including the 27 rusty-kaspa 2.0.1 consensus
vectors), storage, multisig, xpub, address, KSPT/PSKT round trips, the QR
payload classifier, and the fail-closed entropy property above.

**`fat32_tests`**. The FAT32 layer against an in-memory card image, formatted
by the crate's own formatter and mounted by its own mount. Round trips,
multi-cluster chains, delete and overwrite, mounting through an MBR and
refusing an unsigned one, disk-full, and the I/O counts the batched allocator
and delete paths are supposed to hit (a 7-cluster file costs 2 FAT sector
writes, not 26). A corrupt circular chain must terminate rather than hang.

**`fuzz_smoke`**. The nine parser fuzz targets driven from `cargo test`:
valid seeds minted by the crate's own serializers, structural edge cases, and
a fixed 3,000-step mutation schedule each, roughly 27,000 parser executions.
The schedule is deterministic, so a failure reproduces without a corpus file.

```
cargo test                              # the default set, as the device boots it
cargo test --features boot-kats-full    # the full BIP32 and Schnorr sets
cargo test --features verbose-boot      # entry points gated behind that feature
cargo test --features fuzz-api          # adds the fuzz smoke loop
```

CI runs all four on every push, plus clippy (see
`.github/workflows/core.yml`).

## Fuzzing

The `cargo test` smoke loop above is the layer that runs everywhere. For
coverage-guided fuzzing with libFuzzer, `core/fuzz/` is a cargo-fuzz project
over the same target bodies (`src/fuzz_api.rs`), so both drive identical code
with identical invariant checks. It needs nightly:

```
cargo install cargo-fuzz
(cd fuzz && cargo run --bin seed_corpus)   # writes fuzz/corpus/<target>/
cargo +nightly fuzz run kspt_parse -- -max_len=8192
```

See `fuzz/README.md` for the target list and what each one asserts.

## Reporting

Found something? `SECURITY.md` at the repo root has the disclosure process.
A reproducer as a failing test in this crate is the most useful form it can
take: add the input to the structural set in `src/fuzz_smoke.rs` and it runs
under plain `cargo test` from then on.
