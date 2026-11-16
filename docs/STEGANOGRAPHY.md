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

# The Invisible Vault

How KasSigner hides your seed in plain sight.

Imagine you lose everything: fire, flood, theft. The unit is gone, the metal
plate melted, the safe opened. Now imagine your seed also lives inside a photo
of your dog. It sits on your cloud drive, in your email, on a USB stick, on an
old phone. Not one copy: twenty. Nobody can tell, because they are photos.

The photo is the vault, and the caption you wrote for it, "Rocky at the beach,
summer 2024", is the key. It reads as an ordinary caption. That is the whole
trick.

## Many copies, not one clever file

The safety does not come from one perfect file. It comes from many, spread
over places that fail in different ways. Some copies will lose their metadata,
some will be compressed again, some accounts will close. Losing any one costs
nothing, so make a lot of them and keep them where your photos already live.

What makes scattering them safe is that a photo alone opens nothing that
matters. The words inside are encrypted, and the wallet that holds your funds
sits behind a passphrase that is in no file at all.

## The carriers

A backup hides in one of two places, or both. They survive opposite things,
which is why there are two.

| Carrier | Where the backup goes |
| --- | --- |
| **Descriptor** | The photo's EXIF metadata: the backup in `UserComment`, the descriptor as the caption in `ImageDescription`, where anyone can read it. The picture itself is not touched. |
| **Picture** | The image's own compressed data, along a path only the descriptor gives. The descriptor is written nowhere in the file. |
| **Both** | Both, in one pass, under the same descriptor. The strongest single copy. |

| What happens to the file | Descriptor | Picture | Both |
| --- | --- | --- | --- |
| Copied as a file: USB stick, SD card, a cloud drive that keeps the original, an email attachment | Opens | Opens | Opens |
| Metadata stripped | Lost | Opens | Opens |
| Edited, filtered or saved again | If the metadata is kept | Lost | If the metadata is kept |
| Sent through a messaging app or posted on social media | Lost | May open | May open |
| A screenshot, resized, or converted to another format | Lost | Lost | Lost |

Apps that strip metadata usually compress the photo again too, so a Picture
copy there may open, never will. Before you trust a channel, send one copy
through it, bring it back and open it on the unit.

## Three layers

Someone after your funds has to get past all three. They are not equally
strong, and the third carries the weight.

1. **Which photo?** One among thousands, looking like the rest. A Descriptor
   backup keeps the photo's own metadata, camera details and thumbnail
   included; a photo with none, like a screenshot, gets what a photo program
   would write. This stops a casual look, not a trained analyst with the
   right tools.
2. **Which descriptor?** With Descriptor it is the photo's caption, readable
   by anyone: what protects it is that nobody knows it is a password. That is
   obscurity, not a wall. With Picture it is written nowhere and has to be
   guessed. Either way there is no partial answer, only right or wrong.
3. **Which passphrase?** The BIP39 passphrase is in no photo, no print and no
   file the unit writes. The words alone open a different wallet: keep a
   little in it, so it looks real. This is the wall.

## The recovery hint

A passphrase only works if you remember it, years from now. So a backup can
carry a hint: a question whose answer is your passphrase, one of three ready
ones or your own, up to 64 characters. It is sealed with the words in the
same container, and shown only after the photo opens.

The hint covers the passphrase, nothing else. It sits behind the descriptor:
lose the descriptor, and the hint goes with it.

## The printed copy

Print the photo, on paper, and write the descriptor on the back, exactly as
you typed it, as people have labelled photos for a hundred years.

Paper survives everything that destroys a file: no metadata to strip, no
compression, no account to close. And it answers the two questions your memory
will not, ten years from now: which photo was it, and what was the
descriptor? A Picture copy keeps no descriptor of its own, so without a print
or your memory it cannot be opened.

A print is safe in the open: in an album, in a book, framed on the wall. Whoever
finds it has a photo and a caption. The print holds no seed: a scan of it is a
new image and opens nothing. It points you to the file, and the files hold the
rest.

## Using it

The steps are in the User Manual, "Backup: hidden in a photo":

- **Hide:** Seeds › Export › Steganography. Pick the carrier, the photo, the
  descriptor and the hint. The result is read back and compared before the
  photo is replaced; if it does not match, nothing is written.
- **Open:** Tools › Import / Export › Import › Stego Import. Pick the photo and
  give the descriptor. The unit reads both carriers and says where it found
  the backup.

Use a fresh photo for each backup. A Picture backup cannot be seen, not even
by the unit, so nothing warns you before it is hidden over. With Descriptor
or Both, a photo that already holds a backup in its metadata asks OVERWRITE?
and then that backup's own descriptor. Photos made by v1.0.5 to v1.0.7 that
hide up to 256 bytes still open.

Open every copy before you trust it, and check that the passphrase gives the
addresses you expect. A backup you have never opened is not a backup.

## Technical specification

### The sealed container

Words and hint are sealed together in one container, the same format as an SD
backup, with its own purpose so the two never open as each other.

| Offset | Size | Field |
| --- | --- | --- |
| `0x00` | 4 | Magic, `KAS\x06` |
| `0x04` | 1 | Version, 1 |
| `0x05` | 1 | Purpose, 8: steganography |
| `0x06` | 1 | KDF, 1: PBKDF2-HMAC-SHA256, 100,000 iterations |
| `0x07` | 2 | Plaintext length, little-endian |
| `0x09` | 16 | Salt, fresh for every photo |
| `0x19` | 12 | Nonce, fresh for every photo |
| `0x25` | length | Ciphertext, AES-256-GCM |
| end | 16 | Authentication tag |

The key is 32 bytes of PBKDF2-HMAC-SHA256 over the descriptor's bytes. Its
salt is the container's salt followed by the purpose byte, 17 bytes in all.
Always PBKDF2, the P4 included: a photo should outlive the unit that made it,
and every unit opens PBKDF2. The associated data is the header through the
salt, so a change to any byte fails the same way a wrong descriptor does.

The plaintext:

```text
[words: u8] [index: u16 LE] × words [hint: ASCII, 0 to 64 bytes]
```

The hint is whatever follows the indices: no separator, and no hint is no
bytes.

### What is hidden

Not the container as it is. Its first six bytes, magic, version and purpose,
are the same in every backup, a string a search would find in a folder of
photos. They are taken off going in and put back coming out, so what is
hidden begins with the KDF byte and a random salt follows.

Older shapes are read, never written: the one from v1.0.7 begins with the
seed's length, the one from v1.0.5 and v1.0.6 with base64 text. The first
byte tells them apart without a key.

### The Descriptor carrier

The backup goes in EXIF `UserComment` (type `UNDEFINED`, an 8-byte zero
charset, then raw bytes); the descriptor in `ImageDescription`. The EXIF
block is, by preference:

1. **The photo's own**, copied whole so every offset holds, with a new first
   directory: its entries and the two new ones, in tag order.
2. **A software-export block**, for a photo with none: a program's, not a
   camera's, with a program and date from the unit's random bytes.
3. **Two entries alone**, when the frame's size cannot be read: easier to
   find, but a backup that opens beats none.

Each is read back before use; one that fails drops to the next. The image
data is copied byte for byte.

### The Picture carrier

The backup goes in the non-zero AC coefficients of the JPEG's own scan. Each
carries the low bit of its magnitude; to carry the other bit, the magnitude
drops by one toward zero (F5's rule), which moves values as quantization does
rather than pairing them up for a chi-square test to see. A `±1` that drops to
`0` carries nothing and is skipped by both writer and reader. The payload is
preceded by its length in two bytes, big-endian.

The coefficients are visited in a keyed order spread over the whole picture:
a four-round Feistel permutation of their positions, with cycle walking,
keyed by `SHA-256("KasSigner-stego-perm-v1" || descriptor)`. The order hides
nothing; the seal does. A wrong descriptor walks a different path and finds
nothing, which looks exactly like no backup.

Baseline sequential JPEG only. A progressive photo is refused by name.

### Export and import

An export reads its own result back, both carriers, before the photo is
written. An import always reads both carriers, so a stale payload in one
cannot hide a good one in the other, and a photo with two different backups
under one descriptor offers both.

| Limit | Value |
| --- | --- |
| Descriptor | printable ASCII, up to 64 characters written, up to 128 read |
| Hint | up to 64 characters |
| Photo | baseline JPEG, up to 2,000,000 bytes |

The unit names what went wrong: Progressive JPEG, Photo too small, Photo too
large, Not a JPEG, Photo damaged, Verify failed, EXIF failed.

### Stated plainly

- Layer 1 stops a casual look, not a trained analyst. Steganalysis is a
  mature field.
- PBKDF2 is not memory-hard. With Descriptor that hardly matters, since the
  password is in the photo; with Picture it has to be guessed.
- The passphrase is what protects the funds. Everything else buys time.

### In the code

| Where | What |
| --- | --- |
| `crates/kassigner-jpeg` | JPEG and EXIF as their specifications define them |
| `crates/kassigner-protocol/src/stego/` | The carriers, the keyed walk, what is hidden |
| `crates/kassigner-crypto/src/stego.rs` | Sealing and opening, the walk key |
| `firmware/kassigner-fw/src/flow/stego.rs` | Hide and open on the unit |
