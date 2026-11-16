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

# Security

KasSigner is an air-gapped offline signing device that handles cryptographic
keys and transaction signing. It is NOT a hardware wallet. It has no secure
element and no key storage on the unit. All keys exist in RAM only and are
destroyed on power-off. Security is the project's highest priority.

## Reporting a vulnerability

Please do not open a public issue. Email **kassigner@proton.me** with the
subject `[SECURITY]`, and include:

- what you found, and where in the tree;
- how to reproduce it; a failing test is the best form (see
  [Check it yourself](#check-it-yourself));
- what an attacker would gain.

You get an acknowledgment within 48 hours, an assessment within 7 days, and a
fix or a mitigation plan within 30 days. Fixes ship in a release and are
credited in [CHANGELOG.md](CHANGELOG.md), unless you ask not to be named.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | No. Frozen on the `v1.0.x` branch |

On the three units: M5Stack CoreS3, Waveshare ESP32-S3-Touch-LCD-2 and
Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 (chip revision 1.3 only). Mainnet only.

## The security model

Security is not a single feature. It is a series of independent walls, and an
attacker has to get through all of them.

| Wall | What it does |
| --- | --- |
| Air gap | No network stack. Switching the radio off is the first thing the firmware does at boot; on the P4 board, its separate Wi-Fi chip is held powered down. Data moves only as QR codes on a screen or files on an SD card, never across a cable. A unit not locked with Secure Boot (below) keeps its USB port open for flashing and logs, and runs whatever anyone flashes to it: it is for testing only. Locking is the owner's choice, and theirs to do: lock a unit before trusting it with a seed. |
| Memory only | Nothing is ever written to flash, settings included. Seeds and keys live in RAM, and are wiped when their screen is left, on a 6-second hold of the logo, after 4 idle minutes, on a crash and at power-off. |
| Boot self-tests | At every boot the unit checks its arithmetic, its memory and its cryptography against known answers, Kaspa's sighash among them. Any failure stops it. |
| Secure Boot, your key | An owner can lock a unit to firmware signed with their own key. The release is built with no key of any kind, and no project key is ever trusted on a unit. The boot screen names every hole left open: a free key slot, JTAG, download mode. |
| Image hash on screen | At every boot the unit hashes its own firmware and shows the hash, to compare with the release's signed list ([REPRODUCIBLE.md](REPRODUCIBLE.md)). The hash is the firmware's own report: it confirms a flash you made yourself, and says nothing for firmware someone else wrote. |
| Full review | Every output, amount and fee is shown before you sign. An output is labelled CHANGE or YOURS only when the unit works out the address itself. A request it cannot show or sign in full is refused on arrival. |
| Checked twice | The request's bytes are checked against the ones reviewed, at confirm and at signing. Each reply is read back, and every signature verified, before it is shown. |
| Rust, no OS | 100% Rust, `no_std`, on bare metal. `unsafe` lives only in the two board crates, each block with a `// SAFETY:` comment that a lint requires; every other crate a unit runs forbids it. Overflow checks stay on in release builds. |
| Fresh seeds | Every entropy source the unit has must give its share, each credited well under what was measured for it. The chip's own generator is mixed in and counted as nothing. |
| Encrypted backups | AES-256-GCM, with a fresh salt and nonce for every file. The key comes from PBKDF2-HMAC-SHA256 with 100,000 rounds on the S3 units, and from Argon2id with 16 MiB and 4 passes on the P4. The unit refuses a weak password, and the backup is only as strong as the password you choose; the BIP39 passphrase, never stored anywhere, is the last protection of your funds. |
| Hidden backups | A sealed seed can hide inside an ordinary JPEG photo ([docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md)). |
| BIP39 passphrase | Never stored, on the unit or in any backup it writes. Someone with your words and not the passphrase opens a different wallet. |

Two things are absent by decision, not by oversight. There is no flash
encryption, because there is nothing secret in flash: the firmware is public.
There is no anti-rollback, because Secure Boot with your key decides what runs,
and an owner may choose to run an older signed release.

## Your wallet is not a security boundary

Every wallet built on the SDK, and kassigner.org's test tool, run on an online
computer or phone. A phishing copy can show one address and put another in the
request; malware can change a transaction in memory. The unit shows what is in
the transaction data, not what the wallet claims. Check the addresses and the
amounts on the unit's screen, every time.

## What it does not protect against

- **Physical attacks.** With the unit in hand, voltage glitching, opening the
  chip or reading memory after a cold restart are possible. There is no secure
  element and no tamper detection.
- **Side channels.** No claim to resist power or electromagnetic analysis by
  someone close by with equipment.
- **A swapped or reflashed unit.** Other firmware can draw any boot screen it
  likes, hash and fuse line included. The boot screen cannot vouch for a unit
  that has been out of your hands. An unlocked unit runs whatever was last
  flashed to it, which is why it is for testing only; a locked one runs only
  what its owner's key signed. Nothing tells a lookalike from the real unit.
- **A compromised build.** A backdoored toolchain or dependency would end up in
  the binary. Rebuild the release and compare.
- **A leaked signing key.** Whoever holds an owner's Secure Boot key can sign
  firmware that owner's unit will run, and the unit cannot tell who signed.
  Keep the key offline. Keep a copy too: without it a locked unit takes no
  further firmware.
- **Firmware bugs.** v1.0.x went through several outside security reviews.
  v1.1.0 is all new code: it has been through several full reviews of the
  whole tree and was fuzzed against rusty-kaspa 2.1.0, each finding checked
  against the source. KasSigner has not been reviewed by an independent
  professional security firm; a formal third-party audit is a goal for a
  future release.
- **Social engineering.** If you reveal your seed backup or your BIP39
  passphrase, the unit cannot protect you. Neither can it if someone finds
  them.

## Check it yourself

Everything that does not touch the hardware builds and tests on any computer
with Rust 1.95: no board and no ESP toolchain needed
([CONTRIBUTING.md](CONTRIBUTING.md)). The tests run the same known-answer
checks a unit runs at boot, and compare the Kaspa crate against rusty-kaspa
2.1.0 itself.

Where review counts most:

| Where | Why |
| --- | --- |
| `crates/kassigner-crypto` | Seeds, keys, signing, backup encryption |
| `crates/kassigner-kaspa`, `crates/kassigner-protocol` | Everything that reads data from outside |
| `firmware/kassigner-fw` | The review: what is shown, and what is signed |
| `firmware/kassigner-hal-esp32s3`, `firmware/kassigner-hal-esp32p4` | The only `unsafe` |

The full model, threat by threat, is in the User Manual's "Security model"
chapter, a PDF in every release.
