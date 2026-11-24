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

# Reproducible builds

Anyone can rebuild a KasSigner release from its source and get the same
files, byte for byte. That is what lets you check that a release holds
exactly the code in this repository, without trusting whoever built it.

## What a release holds

One Docker build makes every file, for `<board>` in `m5stack`, `waveshare`
and `p4`:

| File | What it is |
| --- | --- |
| `kassigner-<version>-<board>.bin` | The firmware image, at `0x10000`. Its SHA-256 is the hash a unit shows at boot |
| `kassigner-<version>-<board>-full.bin` | Bootloader, partition table and firmware in one file, for a new unit |
| `kassigner-<version>-esp32s3-secure-bootloader.bin` | The S3's Secure Boot bootloader, unsigned, for each owner to sign; at `0x0` |
| `kassigner-<version>-esp32p4-secure-bootloader.bin` | The P4's, likewise; at `0x2000` |
| `kassigner-<version>-partition-table.bin` | The partition table, at `0x8000` |
| `kassigner-<version>-partition-table-p4-secure.bin` | The table of a P4 locked with Secure Boot, at `0xC000` |
| `COPYING`, `THIRD_PARTY_NOTICES` | The firmware's licence, and those of the third-party software in it |
| `kassigner-sdk-<version>-web.tar.gz` | The SDK's browser package, full and watch-only |
| `kassigner-sdk-<version>-bindings.tar.gz` | The SDK's Swift, Kotlin and Python bindings |
| `SHA256SUMS` | The SHA-256 of every file above |
| `SIGN.TXT` | `KasSigner v<version> SHA256SUMS <hash>`: the one line that gets signed, carrying the hash of `SHA256SUMS` |

No key of any kind enters the build or is needed to repeat it.

## Rebuild a release

You need Docker and the source at the release's tag:

```sh
git clone https://github.com/InKasWeRust/KasSigner
cd KasSigner
git checkout v<version>
docker build --platform linux/amd64 -f release/Dockerfile --output type=local,dest=release-out .
```

`release-out/` then holds the files above. `--platform linux/amd64` is
required on every machine, an ARM Mac included, so the result does not depend
on the computer.

Download `SHA256SUMS` from the release page into this folder, then compare
your list with it:

```sh
diff release-out/SHA256SUMS SHA256SUMS
```

It prints nothing when every file is identical. The line in
`release-out/SIGN.TXT` is then the same line the release's signed message,
`KasSg<digits>.txt`, carries ([docs/INSTALL.md](docs/INSTALL.md) shows how to
check that signature).

## Build it twice

To check the build itself, run it twice from nothing and compare:

```sh
docker builder prune -af
docker build --no-cache --platform linux/amd64 -f release/Dockerfile --output type=local,dest=release-out-2 .
diff release-out/SHA256SUMS release-out-2/SHA256SUMS
```

Any difference means an input is not pinned. Do not use the files until it is
found, and please report it.

## What is pinned

Every input is fixed by its content, so a file republished under the same
name fails the build:

| Input | Fixed by |
| --- | --- |
| The base images: Ubuntu 24.04, and Espressif's ESP-IDF v6.1 | Their digest |
| System packages | Exact versions, from a dated snapshot of Ubuntu's archive |
| esp-rs's Rust 1.95.0.0 and its source, Espressif's Xtensa GCC, espflash 4.6.0 | Their SHA-256 |
| Every crate | `Cargo.lock`, built with `--locked` |
| The esp-hal fork the ESP32-P4 needs | Six crates fetched by version, each checked against the crates.io index, and one patch in this repository |
| The build date | `SOURCE_DATE_EPOCH=0` |
| The build folder | Fixed, since Rust writes source paths into the image |

The bootloaders are Espressif's own: the Secure Boot ones built inside the
ESP-IDF image from the settings in `release/bootloader-esp32s3` and
`release/bootloader-esp32p4`, and the plain one in each `-full.bin` as
espflash ships it. They are the only code in a unit's flash that is neither
this project's nor Rust.

## The hash a unit shows

At every boot a unit hashes its own firmware in flash and shows the first 8
and last 8 characters. It hashes the image as the build wrote it, so the
number is the `kassigner-<version>-<board>.bin` line of `SHA256SUMS`.

An owner who locks a unit signs that image with their own key
([docs/LOCKING.md](docs/LOCKING.md)). Signing adds padding and a signature
after the image, and the unit hashes neither, so a locked unit shows the same
hash as an unlocked one.

## What is not reproducible

- **An owner's signed images.** Every signing makes a new signature, so no
  rebuild can produce the same signed file. That is why releases ship
  unsigned and the hash covers the unsigned image.
- **The signature on the list.** `KasSg<digits>.txt` is made by a
  KasSigner unit with the release address. Signing the same line again gives
  another valid signature, never the same bytes.
- **The documentation.** `SHA256SUMS` lists only what this build makes. The
  User Manual PDF published beside it is not in the list, and neither are the
  documents in the repository.

## How a release is signed

1. The release build writes `SHA256SUMS` and `SIGN.TXT`.
2. The build is run twice from nothing on one machine and once on GitHub's
   x86 Linux, and the three lists compared.
3. `SIGN.TXT` goes to a KasSigner unit on a card and is signed there, in Sign
   Message, with the release address. The unit refuses a text ending in a
   line break, which is why `SIGN.TXT` has none.
4. The unit saves the signed message unencrypted, under the name given to it
   there: `KasSg` and the version's digits without its dots, `KasSg111.txt`
   for 1.1.1. It is published beside `SHA256SUMS` under that name.

## The same build in CI

The `release` workflow runs this Docker build on GitHub's x86 Linux, by hand
or when a `v*` tag is pushed. On a tag it first waits for `crates.yml` to pass
on the tagged commit, and stops if the tag is not the tree's version. It
checks every file against the list and prints `SHA256SUMS` and the `SIGN.TXT`
line on the run's summary page, to compare with a build made elsewhere. It
publishes nothing.

## Notes

- **Disk.** The build unpacks the toolchain and the ESP-IDF image at the same
  time. On GitHub's runner, 15 GB free was not enough and 37 GB was; the
  workflow frees space before it builds.
- **ARM Macs.** The build runs emulated there. It is slower, the bootloader
  step most of all. If that step stands still for many minutes, stop the build
  and run it again.
- **Two warnings** about `--platform` in `FROM` lines are expected: the
  platform is fixed on purpose.
