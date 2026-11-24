<!--
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
-->

# Contributing to KasSigner

Thank you for your interest in KasSigner. It signs real funds, so every change
is held to one standard: it must be right, and it must be easy to check.

## Security vulnerabilities

**Do not open a public issue for a security vulnerability.** Email
kassigner@proton.me with the subject `[SECURITY]`. See
[SECURITY.md](SECURITY.md) for the full policy.

## What we need help with

Most of it needs no code.

- **Security review**, first of `crates/kassigner-crypto`,
  `crates/kassigner-kaspa`, `crates/kassigner-protocol` and
  `firmware/kassigner-fw`.
- **Testing on your own unit**: the boot screen and its self-tests, making and
  restoring seeds, scanning, signing, backups. A report from a unit we do not
  hold is worth a lot.
- **QR scanning** with each board's camera, in real light, from real screens.
- **New boards**, each one a crate of its own behind `kassigner-hal`'s traits.
- **Wallets integrating the SDK**, and word of what is missing or unclear in
  it.
- **Documentation.**

## Reporting a bug

Open an issue with:

- the board, and the version and `Hash:` line its boot screen shows;
- what you did, step by step;
- what you expected, and what happened instead;
- the console log, if you can; a `diag` build adds what the unit was doing
  ([On a unit](#on-a-unit)).

**Never post your words, a SeedQR, a backup, or a photo of a screen showing a
secret.**

## Before you start

For anything bigger than a fix, open an issue first, so we agree on the
approach before you spend days on it.

Some things will not be merged, however well they are done:

- coins other than Kaspa;
- anything that turns on a radio, or moves data over a cable;
- anything written to the unit's flash;
- rules of our own on top of Kaspa's: rusty-kaspa decides;
- telemetry, accounts, or anything that reports home.

## How to contribute

1. Fork the repository, and set up once ([Set up](#set-up)).
2. Create a branch: `git checkout -b feature/my-feature`.
3. Make your change, with the tests that pin it.
4. From the repository root, run the host chain. It must pass whole:

   ```sh
   cargo fmt --all -- --check && cargo +esp195 test-all && cargo +esp195 clippy-all && cargo deny check
   ```

5. If you touched one of these, check it as CI does:

   | You touched | Run |
   | --- | --- |
   | The SDK packages, or a dependency | `sh crates/kassigner-sdk-wasm/build.sh`, `sh crates/kassigner-sdk-wasm/build.sh watch`, `sh crates/kassigner-sdk-ffi/build.sh` and `sh release/notices.sh --check` |
   | A shell script, or a workflow | `shellcheck` on the scripts, and `actionlint` |
   | `vendor/rqrr` | `cargo test` and `cargo clippy --all-targets -- -D warnings`, from that folder |

   Each script lists what it needs at its top.

6. If you touched `firmware/` or a crate it depends on, flash every board you
   have ([On a unit](#on-a-unit)). Every self-test must pass at boot.
7. If your change alters a generated file, make it again with its command
   ([Auto-generated files](#auto-generated-files)), never by hand.
8. Commit with clear messages. One change per pull request.
9. Open the pull request. Its template asks what you verified, and what you
   did not.

## Code standards

- Every crate the unit runs is `no_std`. Prefer stack buffers with bounds
  known at compile time.
- All code, comments and strings in English.
- Every source file carries its crate's licence header: MPL-2.0 in the SDK and
  the crates it is built from, GPL-3.0-or-later in `kassigner-crypto`,
  `kassigner-fat32` and everything under `firmware/`. Copy it from a file
  beside yours. A GPL crate may depend on an MPL one, never the other way
  round.
- Each crate sits at a level, listed in the root `Cargo.toml`, and depends only
  on its own level and those below: 0 someone else's specification, 1 this
  project's design, 2 key material, 3 the boards, the flow and the SDK, 4 the
  program. Anything that holds or moves private key material is level 2. The
  SDK never reaches level 2, and `crates/kassigner-sdk/tests/no_keys.rs`
  checks it.
- `kassigner-kaspa` follows rusty-kaspa 2.1.0 and is tested against it. Where
  the two disagree, rusty-kaspa is right.
- `unsafe` lives only in `kassigner-hal-esp32s3` and `kassigner-hal-esp32p4`,
  as little as possible, each block with a `// SAFETY:` comment saying why it
  is sound. Every other crate of ours a unit runs forbids it, the vendored QR
  decoder included; the two SDK binding crates deny it, as their binding
  macros generate it. When the flow needs
  what only `unsafe` gives, `kassigner-hal` defines a safe trait, each board
  implements it, and the logic lives once in `kassigner-fw`.
- A type that holds a secret wipes itself when dropped. A secret leaves the
  unit sealed, or in the clear to the person (words, SeedQR); never in the
  clear to a file, a card or the console.
- No network-capable dependencies in the firmware.
- A new board is a new crate under `firmware/`. `kassigner-fw` never names a
  board.
- Zero warnings: clippy runs with `-D warnings`.

## Building and testing

### Set up

Rust 1.95 for the host, and the esp-rs toolchain of the same release, named
`esp195`, for the units:

```sh
rustup toolchain install 1.95.0
cargo install espup cargo-deny --locked
cargo install espflash --version 4.6.0 --locked
espup install --name esp195 --toolchain-version 1.95.0.0
. ~/export-esp.sh
```

Source `~/export-esp.sh` in every new terminal before building for a unit.
Then, once after every clone, from the repository root:

```sh
sh firmware/kassigner-hal-esp32p4/esp-hal-fork/fork.sh
```

It makes the esp-hal fork the ESP32-P4 needs, from crates.io sources checked
against the index. Until it has run, no cargo command in the workspace
resolves.

For the SDK packages, also the browser target on the same Rust and the two
tools their build checks at exact versions:

```sh
rustup target add wasm32-unknown-unknown --toolchain 1.95.0
cargo install wasm-bindgen-cli --version 0.2.100 --locked
```

and Binaryen's `wasm-opt` 133 (`brew install binaryen`, or Binaryen's own
release).

### On the host

The host chain is step 4 above. `test-all` and `clippy-all` add the S3 board
features, so its host tests run too. No board is needed, and the stock
`+1.95.0` toolchain works as well as `+esp195`.

### On a unit

From `firmware/kassigner-signer`, with the unit on USB:

| Unit | Build, flash and open the console | With bench logging |
| --- | --- | --- |
| M5Stack CoreS3 | `cargo +esp195 m5` | `cargo +esp195 m5-diag` |
| Waveshare ESP32-S3-Touch-LCD-2 | `cargo +esp195 ws` | `cargo +esp195 ws-diag` |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | `cargo +esp195 p4` | `cargo +esp195 p4-diag` |

The hardware tests: `cargo +esp195 m5-hwtest` or `cargo +esp195 ws-hwtest` from
`firmware/kassigner-hal-esp32s3`, and `cargo +esp195 p4-hwtest` from
`firmware/kassigner-hal-esp32p4`.

### Auto-generated files

| Files | Make them again with |
| --- | --- |
| `crates/kassigner-kaspa/src/kat_sighash.rs` | `KAT_REGENERATE=1 cargo +esp195 test -p kassigner-kaspa --test upstream boot_sighash` |
| `firmware/kassigner-fw/src/ui/gen/` | `UI_REGENERATE=1 cargo +esp195 test -p kassigner-fw --test ui_assets` |
| `spec/vectors/v110/sdk/` | `KASSIGNER_SDK_VECTORS=write cargo +esp195 test -p kassigner-fw --test sdk` |
| `spec/vectors/v110/node/` | `KASSIGNER_NODE_VECTORS=write cargo +esp195 test -p kassigner-kaspa -p kassigner-sdk-host` |
| `THIRD_PARTY_NOTICES` of the SDK packages and the firmware | `sh release/notices.sh` |

Vectors copied from elsewhere, such as `spec/vectors/v110/covenants/`, stay
byte for byte as their source has them.

## Licence

By contributing, you agree that your contribution is licensed under the
licence of the crate it lands in.
