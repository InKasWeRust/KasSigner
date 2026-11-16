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

# Changelog

Every notable change to KasSigner is recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

The history of v1.0.0 to v1.0.7 is on the
[`v1.0.x` branch](https://github.com/InKasWeRust/KasSigner/blob/v1.0.x/CHANGELOG.md).

## [1.1.0]: 2026-11-16

A fresh start. Every line is new: KasSigner is rebuilt as fifteen Rust crates
in one workspace, runs on a third board, and comes with an SDK that any Kaspa
wallet can use.

### Added

- **A third unit, the Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5.** Its Wi-Fi chip,
  an ESP32-C6, is held powered down from boot and can be removed from the
  board. The firmware runs on chip revision 1.3 only: a board with a v3.x
  chip is not supported.
- **The SDK.** `kassigner-sdk` and `kassigner-sdk-host` for Rust,
  `kassigner-sdk-wasm` for JavaScript and TypeScript, `kassigner-sdk-ffi` for
  Swift, Kotlin and Python. It imports what a unit hands over, builds requests,
  reads the signed replies and finishes the transaction. It holds no seed and
  cannot reach the key crate. Each release carries its browser package and
  bindings, under the same signature as the firmware.
- **PSKB**, rusty-kaspa's standard bundle, read and answered beside KSPT. The
  unit replies in the format it was given.
- **Secure Boot with your own key.** The release carries the S3's and the P4's
  Secure Boot bootloaders unsigned, for each owner to sign. The boot screen
  judges the fuses: Verified OK, Not provisioned, or NOT SECURE with every open
  hole named.
- **The image hash on screen.** At every boot the unit hashes its own firmware
  and shows it, to compare with the release's `SHA256SUMS`, signed with Sign
  Message by `kassigner.kas`.
- **A reproducible build** of every release file in one pinned Docker image
  ([REPRODUCIBLE.md](REPRODUCIBLE.md)).
- **Boot self-tests.** Each crate carries known answers that the unit checks at
  every boot and the tests check on any host. Kaspa's sighash table among them
  is generated from rusty-kaspa 2.1.0.
- **Argon2id** (16 MiB, 4 passes) for SD backups made on the P4. Such a backup
  opens only on a P4; one made on an S3 opens on every unit.
- **KCC-3 addresses** at `m/22'/111111'/0'`, a proposal not yet adopted.
- **Time-Locked Savings** covenant cards, written in SilverScript, signed and
  checked on the unit. The card's source is in the repository, and a test
  compiles it and compares the result with the program the unit holds.
- **The User Manual**, a PDF with every release.

### Changed

- **One firmware per board, for every unit.** The same build runs on a blank
  unit, and, signed with its owner's key, on a provisioned one.
- **Refused on arrival.** A request the unit cannot show or sign in full, one
  with an input the seed cannot sign, or a multisig that repeats a key, is
  refused when it is scanned, before any page is shown.
- **One way to make a seed.** Every entropy source the unit has must give its
  share. The chip's own generator is mixed in and counted as nothing.
- **The fingerprint** is the standard BIP32 one, so other wallets show the
  same eight characters.
- **Finding your own inputs.** Inputs further along the account are found by
  searching, up to 1,000 keys on each chain.
- **Multisig** follows the `45'` scheme only, with up to five keys.
- **A passphrase is typed twice**, as passwords are, so a key pressed by
  mistake is caught.
- **kassigner.org** is now the project's test tool. The copy hosted there
  cannot send; the full tool is in its own repository, for an owner to run.
- **Licence.** The firmware is GPL-3.0-or-later. The SDK and the crates it is
  built from are MPL-2.0, so any wallet can integrate them.

### Removed

- **The firmware's own signature check.** Secure Boot with the owner's key and
  the image hash on screen replace it.
- **Stealth payments**, reading included.
- **Saving a seed's xprv to the card.** The master and account keys are shown
  on screen only. xprv backups made by v1.0.7 still open.

### Coming from v1.0.7

- Your seed stays the same seed. Words, SeedQRs and SD backups from v1.0.7 open,
  xprv backups included, and so do photos made by v1.0.5 to v1.0.7 that hide
  up to 256 bytes.
- Covenant cards made with v1.0.7 were test cards and are no longer supported.
  Run the v1.0.7 site from the `v1.0.x` branch, load your kpub, and withdraw
  the funds or keep the cards' backups. The manuals are on that branch.
- Requests from a v1.0.7 companion are still read. A wallet built on v1.0.7
  gets its single-key answer in the form it reads: for such a request, SIGNED
  TX QR's Wallet card shows the reply as a v1.0.7 unit did, and says
  "KSPT v1.0.7". This stays until those wallets move to the SDK.
- The fingerprint shown for a seed changes. Its addresses do not.
- A multisig group needs every cosigner on v1.1.0. Groups built on `44'` keys,
  which ended in v1.0.5, are not recognised: move their funds with an earlier
  release first.

[1.1.0]: https://github.com/InKasWeRust/KasSigner/releases/tag/v1.1.0
