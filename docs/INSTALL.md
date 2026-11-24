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

# Installing KasSigner

From a board in its box to a signer you have checked yourself. No Rust and no
build are needed: you flash a release image, then check it on the unit's own
screen.

> [!WARNING]
> **Mainnet only.** There is no testnet mode.

## What you need

| Board | Chip | Its release image |
| --- | --- | --- |
| M5Stack CoreS3 | ESP32-S3 | `kassigner-<version>-m5stack-full.bin` |
| Waveshare ESP32-S3-Touch-LCD-2 | ESP32-S3 | `kassigner-<version>-waveshare-full.bin` |
| Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5 | ESP32-P4, revision 1.3 only | `kassigner-<version>-p4-full.bin` |

- **A camera on the Waveshare ESP32-S3 board.** It takes an OV5640 module on
  its camera connector. The other two boards have theirs built in.
- **The right P4 chip: revision 1.3 only.** The P4 firmware is built for chip
  revision 1.3 and checks for it at boot. A board with a v3.x chip is not
  supported yet: the firmware stops at boot and the unit does not start.
- **A microSD card**, for backups and for moving files to and from your
  wallet.
- **A USB data cable** and a computer, for flashing only.
- **espflash 4.6.0**, the version the release is built with: from its
  [release page](https://github.com/esp-rs/espflash/releases/tag/v4.6.0), or
  with Rust installed:

  ```sh
  cargo install espflash --version 4.6.0 --locked
  ```

## 1. Download the release and check it

From the [release page](https://github.com/InKasWeRust/KasSigner/releases),
take your board's `-full.bin`, `SHA256SUMS` and the signed message,
`KasSg<digits>.txt`: the digits are the version's without its dots, so
`KasSg111.txt` for 1.1.1. Then four checks, each proving one thing:

| Check | Proves |
| --- | --- |
| The signed message is valid, and its address is the release address | The line came from the project |
| The SHA-256 of `SHA256SUMS` is the hash in that line | The list is the one that was signed |
| Each file you downloaded matches its line in `SHA256SUMS` | The files are the ones in the list |
| After flashing, the hash on the unit's screen matches the list | Your flash took. The firmware reports its own hash, so this holds for a unit you flashed yourself |

### The signed message

`KasSg<digits>.txt` is one line of text, signed with Kaspa's standard
message signature by a KasSigner unit:

```text
-----BEGIN KASPA SIGNED MESSAGE-----
KasSigner v<version> SHA256SUMS <the SHA-256 of SHA256SUMS>
-----BEGIN SIGNATURE-----
<the release address>
<the signature, 128 hex characters>
-----END KASPA SIGNED MESSAGE-----
```

Check it with any of these; each says which address signed:

- **[kassigner.org](https://kassigner.org)**: its "Check a message" page.
- **A KasSigner unit**: copy the file to the card, then Tools, Sign Message,
  "Load .TXT from SD", and CHECK. It answers **VALID SIGNATURE** and
  "Signed by:" with the address. No seed is needed.
- **rusty-kaspa's command-line wallet**: `message verify <address>
  <signature>`, then the line of text when it asks for the message.

A valid signature only says which address signed. **Compare that address with
the release address, taken from somewhere other than the release:**

```text
kaspa:qqz0xdq9tu92hgraa89rcmae23f8h09zzzsy4f4agvasmsw3958cza0mv7x86
```

It is published in three places: on kassigner.org, on the project's X
account, [@KasSigner](https://x.com/KasSigner), and as the Kaspa Name Service
record of `kassigner.kas`. It never changes. The address is what counts; the
name only points at it.

### The list and the files

The hash of the list, to compare with the one in the signed line:

```sh
sha256sum SHA256SUMS
```

Every downloaded file against the list:

```sh
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS the same two are `shasum -a 256 SHA256SUMS` and
`shasum -a 256 --ignore-missing -c SHA256SUMS`. On Windows,
`certutil -hashfile <file> SHA256` prints one file's hash to compare by eye.

## 2. Flash the unit

Plug the board in and write the full image at `0x0`. It holds the bootloader,
the partition table and the firmware.

M5Stack CoreS3:

```sh
espflash write-bin 0x0 kassigner-<version>-m5stack-full.bin
```

Waveshare ESP32-S3-Touch-LCD-2:

```sh
espflash write-bin 0x0 kassigner-<version>-waveshare-full.bin
```

Waveshare ESP32-P4-WIFI6-Touch-LCD-3.5, chip revision 1.3 only, which needs
`--no-stub`:

```sh
espflash write-bin --no-stub 0x0 kassigner-<version>-p4-full.bin
```

With several serial devices connected, add `--port` and the board's port:

```sh
espflash write-bin --port <port> 0x0 kassigner-<version>-m5stack-full.bin
```

To find the port, list them with the board unplugged and again with it
plugged in; the one that appears is the board's. espflash lists them the same
way on every system:

```sh
espflash list-ports
```

Or with the system's own command:

| System | Command | A port looks like |
| --- | --- | --- |
| macOS | `ls /dev/cu.*` | `/dev/cu.usbmodem101` |
| Linux | `ls /dev/ttyACM* /dev/ttyUSB*` | `/dev/ttyACM0` |
| Windows, in PowerShell | `[System.IO.Ports.SerialPort]::GetPortNames()` | `COM3` |

If espflash cannot connect, put the board in download mode first: switch it
off and unplug it, hold its BOOT button, plug it in, release. Unplugging alone
does not switch off the M5 or the P4, which have batteries.

## 3. First boot: check what the unit runs

When the write ends the unit restarts; if it does not, press its reset button
once, briefly. At every boot it runs its self-tests and shows its verification
screen for three seconds:

| Line | A new unit shows |
| --- | --- |
| `Version:` | The release's version |
| `Hash:` | The first 8 and last 8 characters of its firmware's SHA-256 |
| `eFuse: Secure Boot off` | In orange |
| `Not provisioned` | In orange |

The unit computes that hash from its own flash at every boot. Compare it with
the line of the app image, `kassigner-<version>-<board>.bin`, in
`SHA256SUMS`: not the `-full.bin` line. If the two agree, the firmware you
flashed is the one in the signed list. The firmware reports this hash itself,
so it vouches for a flash you made yourself, not for a unit others have had
([SECURITY.md](../SECURITY.md)).

Settings, About shows the same screen again at any time.

A self-test that fails stops the unit with "Self-test failed". Do not use it.

## 4. The SD card

The unit reads and writes FAT32. To prepare a card on the unit itself:
Settings, SD Card, "Format FAT32". It removes every file on the card, but
does not wipe their old data. Deleting a file on the unit does: it is
overwritten with zeros. A card's own controller can still keep old copies
where no overwrite reaches, so treat a card that held a backup as still
holding it.

Making a seed, signing and backups are in the User Manual, a PDF in the
release.

## 5. Updating

Flash the new release's full image as in step 2, after checking it as in
step 1. Nothing is lost: a unit keeps no seed, no setting and no file in its
flash.

A locked unit (below) is updated another way: it takes only the firmware,
signed with its owner's key, and not the full image. See "Updating a locked
unit" in [LOCKING.md](LOCKING.md).

## 6. Locking the unit with your own key

A new unit is not provisioned: any firmware can be written to it over USB,
and its USB port stays open. Until it is locked it is for testing only.
Secure Boot changes that. You make a key, sign the release's Secure Boot
bootloader and firmware with it, and the chip then runs only what your key
has signed. Its verification screen says **Verified OK**, or **NOT SECURE**
with every hole left open named.

- The key is yours alone. No project key is ever trusted on a unit, and the
  release is built with no key of any kind.
- It is permanent: the fuses it burns cannot be unburned.
- Lock a unit before trusting it with a seed ([SECURITY.md](../SECURITY.md)).

The release carries what you sign, unsigned:
`kassigner-<version>-esp32s3-secure-bootloader.bin` and
`kassigner-<version>-esp32p4-secure-bootloader.bin`.

The step-by-step procedure, from making the key to checking the lock, is
[LOCKING.md](LOCKING.md). It assumes no experience with terminals, and says
which units it has been run on.

## Building it yourself

To rebuild the release's files and compare them byte for byte:
[REPRODUCIBLE.md](../REPRODUCIBLE.md). To build from source and flash a unit
directly: [CONTRIBUTING.md](../CONTRIBUTING.md).
