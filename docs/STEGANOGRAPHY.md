<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# The Invisible Vault

## How KasSigner Hides Your Seed in Plain Sight

Imagine you lose everything. Fire, flood, theft, whatever. Your signing device is gone. Your metal seed plate melted. Your safety deposit box was compromised. Years of accumulated wealth, evaporated.

Now imagine a different scenario. Your seed lives inside a photo of your dog. It sits in your Google Drive, in your email, on a USB stick in your desk drawer, on your phone's camera roll. Not one copy. Twenty. Nobody knows. Nobody can tell. The photos look like every other photo, because they are photos.

That photo *is* your vault, and the descriptor you wrote on it, "Rocky at the beach, summer 2024", is the key. It reads as an ordinary photo caption. That is the whole trick.

---

## The Model: Redundancy, Not One Clever File

This is the part to understand before anything else, because every other decision follows from it.

The security does not come from one perfect artifact. It comes from **many**, spread across places and channels that fail in different ways. Some copies will be stripped of metadata. Some will be re-compressed. Some accounts will close, some drives will die. The design assumes that attrition and survives it, because losing any single copy costs nothing.

So: make a lot of them. Put them everywhere. In plain sight, because that is the point.

What makes this safe to scatter is that a photo on its own is not enough. The seed inside it is encrypted, and the wallet that matters lives behind a passphrase that was never written into any file. An attacker who finds an artifact, identifies it as an artifact, and opens it still arrives at a decoy.

---

## The Two Carriers

An artifact can hide its payload in two places, chosen at export. They survive opposite things, which is exactly why both exist.

**Descriptor** puts the payload in the photo's EXIF metadata. EXIF is the standard metadata format every digital camera writes: date, GPS coordinates, camera model, exposure settings, and text fields like `ImageDescription`. Photo management software, cloud storage and operating systems all read it.

**Picture** puts the payload in the image's own compressed data, in the quantized coefficients the JPEG is built from. It does not touch metadata at all.

| | Descriptor | Picture |
|---|---|---|
| Photo re-saved or re-compressed | survives | destroyed |
| Metadata stripped | destroyed | survives |

Metadata stripping is routine. Every messaging app and most social platforms do it. Re-compression happens whenever an image is edited or re-encoded. Nothing about one export removes the other, so **running both on the same photo is how a single artifact covers both risks**. On import the device tries both carriers and reports which one held the backup.

### The two EXIF fields

**`ImageDescription`**: this is your password. Not a cover story for the password. Not a hint toward the password. It *is* the password, typed into the photo's metadata where any viewer can see it. It looks like a caption: *"Sunset at Playa Blanca, Aug 2024"*. Anyone inspecting the EXIF sees a normal description. What they cannot know is that this exact string of characters, every letter and space and comma, was fed through PBKDF2 with 100,000 iterations of HMAC-SHA256 to derive a 256-bit AES key.

**`UserComment`**: this holds the encrypted seed, stored as raw bytes. Inside it: a per-file random salt, a per-file random nonce, the seed word indices encrypted with AES-256-GCM, and a 16-byte authentication tag that ensures even a single bit flip is detected.

The descriptor is the key. It is visible to everyone, and useless to everyone who does not know what it is.

### What the Picture carrier does differently

The Picture carrier writes no EXIF at all. The descriptor keys both the encryption and the walk through the coefficients, and is never stored in the file.

That has a consequence worth stating plainly: **a Picture-only artifact carries no copy of its own password**. If every surviving copy is Picture-only and the descriptor has been forgotten, the seed is unreachable. The files are intact and useless.

This is not a reason to avoid the Picture carrier. It is one of the reasons the printed copy exists. The print carries the two weakest pieces of the puzzle, the ones that live only in your memory and nowhere in the files: which photograph it was, because the print is the image, and what the descriptor was, written on the back. Everything else the artifacts carry themselves.

---

## Why This Is Different

Every other seed backup method has the same problem: it looks like a seed backup.

A metal plate stamped with 24 words is obviously a seed backup. A Cryptosteel capsule is obviously a seed backup. A paper wallet in a safe is obviously a seed backup. An encrypted file named `seed_backup.enc` is obviously a seed backup. Any attacker who finds these knows exactly what they have and exactly what to do with it.

A photo of your dog is not a seed backup. It is a photo of your dog.

An attacker does not begin by cracking encryption. They begin by working out that encryption is there at all, across every photo you own, and there is nothing in a photo that suggests it.

---

## The Three Layers

An attacker must get past all three to reach your funds. They are different kinds of problem, and they are not equally strong. Layer 3 is the one holding the weight.

### Layer 1: Which File?

You have 4,000 photos on your Google Drive. One of them contains your seed. Which one?

This is the layer everything visible rests on, and **in v1.0.4 and earlier it did not hold.** A security audit showed that artifacts of that era could be picked out of a folder of ordinary photos reliably and cheaply. Those weaknesses are closed as of v1.0.5, and the same test now finds nothing.

An artifact now keeps the host photo's own metadata, camera details and thumbnail included, with KasSigner's two fields merged in. Nothing about it is constant from one artifact to the next. A photo that arrived with no metadata, as screenshots and messaging-app downloads do, gets a plausible one built for it.

**Stated plainly:** this defeats casual inspection, not a trained analyst with the right tools, and it was never meant to be the layer your funds depend on.

### Layer 2: What Caption?

Say the attacker identifies the correct photo. They extract the payload and work out it is an encrypted blob. Now they need the key.

The key is the descriptor: *"Me at the age of 20 with my family"*. It is right there, and they can read it. What they have to work out is that it is the key at all. It is not labeled, not formatted like a password, and does not look like one because it was never designed to.

So be clear about what this layer is. With the Descriptor carrier the password travels in the file. Anyone holding it already has the key; what stops them is not knowing that. That is obscurity. Worth having, but not a wall. The Picture carrier stores no descriptor at all, and there the password has to be guessed for real.

Either way, guessing is all-or-nothing. AES-256-GCM gives one answer, right or wrong, with no partial decryption and nothing to converge on.

### Layer 3: What Word?

This is the final wall, and it exists nowhere.

Even if the attacker has the correct file, decrypts it with the correct descriptor, and recovers all 24 BIP39 mnemonic words, they do not have your wallet. They have *a* wallet. A decoy. Put some dust in it. Make it look real.

Your actual funds live on a derivation path created by the BIP39 passphrase, the 25th word. This passphrase is folded into the seed during derivation. Different passphrase means different master key, different addresses, different wallet. Same 24 words, completely separate universe of keys.

The 25th word is never written down. Never stored on any device. Never transmitted. Never recorded in the metadata, on the SD card, in the encrypted backup, anywhere. It exists only in the owner's memory. The only way to obtain it is to ask the owner, and the owner can point to the decoy wallet and say "that's all there is."

This is the layer that carries the weight. Layers 1 and 2 buy time and obscurity. Layer 3 is the one that is actually hard.

---

## The Recovery Hint

Humans forget. Over years, even the most important memories fade. The 25th word protects your wealth, but it only works if you remember it.

KasSigner addresses this with an encrypted recovery hint stored alongside the seed. During export, you can attach a question whose answer is your 25th word:

- *"My favorite place I lived?"*
- *"Name of my loved one?"*
- *"Song I can't stop humming?"*
- Or any custom text you write.

The hint is encrypted with the same descriptor and stored in the same payload, so it appears on screen only after the seed is decrypted: a private reminder, visible only to someone who has already proved they know the descriptor.

It is not the answer, only a question shaped to trigger one. The 25th word itself is never stored. It travels from your memory to the keypad and back, touching nothing permanent on the way.

One catch. The hint covers the passphrase, nothing else. It is locked behind the descriptor, so if the descriptor is what you lost, the hint is lost with it. Which is why the descriptor is the piece to duplicate hardest: in every Descriptor-carrier artifact you make, and on the back of every print.

---

## Technical Specification

### Container format (v3)

The seed is encrypted with the `sd_backup` module, shared with SD card backups. One container serves every encrypted artifact the device writes.

```
Offset  Size     Field
------  -------  ------------------------------------------
0x00    4 bytes  Magic "KAS\x04"
0x04    1 byte   Version (3)
0x05    1 byte   Purpose (1 seed, 2 xprv, 3 raw, 4 kspt)
0x06    1 byte   KDF id (1 = PBKDF2-HMAC-SHA256, 100,000)
0x07    1 byte   Plaintext length
0x08    16 bytes Salt, per file, from the hardware RNG
0x18    12 bytes Nonce, per file, from the hardware RNG
0x24    len      Ciphertext
+len    16 bytes AES-256-GCM authentication tag
```

Associated data is bytes 0x00 to 0x18, taken as one contiguous slice so no caller can assemble it in the wrong order. Any modification to ciphertext, nonce or header fails as "Wrong password". There is no silent corruption.

Salt and nonce are per file. An earlier format used a fixed salt for every device, which would have let one precomputed table break every artifact ever produced, and derived the nonce from the secret itself, which made it a password-testing oracle. The KDF id exists so a memory-hard replacement can ship later without breaking old backups.

### What gets embedded

Not the container verbatim. Its first seven bytes are identical in every seed artifact, so they are stripped on embed and rebuilt on import. What is stored starts with the length byte and the random salt, so every artifact begins with different bytes.

Stored raw, not base64: `UserComment` uses the UNDEFINED charset, which is what raw bytes are for.

Seed and hint are concatenated with no separator. The leading length byte splits them, since a separator character cannot survive raw storage.

**Where the KDF matters.** PBKDF2-HMAC-SHA256 is not memory-hard. With the Descriptor carrier that is close to irrelevant, because the password is written in the photo and an attacker holding the file reads it rather than guessing. With the Picture carrier the descriptor is nowhere in the file, so it has to be guessed, and there its strength does real work.

### Metadata structure (Descriptor carrier)

The builder copies the host photo's metadata verbatim, keeping every internal offset valid including the thumbnail, and appends an entry list carrying the host's own tags plus KasSigner's two: `ImageDescription` for the password, `UserComment` for the payload. Both byte orders are read and written.

Before writing, the device re-extracts its own payload from the block it just built and compares byte for byte, falling back to a minimal builder on mismatch. A malformed cover photo cannot produce an artifact that fails only on the day it is needed.

All image data is copied byte for byte, so a Descriptor-carrier artifact is mathematically identical to the original image.

### The Picture carrier

The payload goes into the JPEG's quantized coefficients using magnitude decrement, walked in an order derived from the descriptor. A wrong descriptor produces a different walk and no payload: the same uniform failure as a wrong password anywhere else.

Baseline sequential JPEGs only; progressive files are refused rather than mishandled. Embedding takes a few seconds on the device. Pixel-domain hiding was tested and rejected, because it does not survive a single JPEG save.

**Steganalysis exposure, stated plainly.** The embedding rate sits where statistical detectors are weakest, but this is a mature field and a trained detector with the right tooling is a real adversary.

### File impact

The Descriptor carrier adds a few hundred bytes to a file of 500 KB to 5 MB. The Picture carrier changes values rather than adding bytes, so the size barely moves. Either way it is below the noise floor of JPEG compression.

---

## What Survives

The two carriers survive opposite things, and that is the reason to use both.

Descriptor survives anything that copies a file intact or re-saves the image: USB sticks, SD cards, network shares, Google Drive, Dropbox, iCloud, email attachments, NAS backups. It dies the moment something strips metadata, which every messaging app and most social platforms do routinely.

Picture is the reverse. It shrugs off metadata stripping and dies to re-compression. Platforms that strip usually re-encode as well, so treat it as "may survive" there rather than "will".

Neither survives a screenshot, OCR, resizing or a format conversion. A screenshot is a new image, and the others rewrite it.

**Always test your backup path.** Send an artifact through the channel you intend to use, bring it back, and import it on the device. Do this before trusting the channel with real funds.

---

## The Printed Copy

Print the photograph. A real print, on paper, with the descriptor written on the back, exactly as people have labelled photographs for a hundred years.

Paper does not care about any of the things above. No metadata to strip, no compression to redo, no format to obsolete, no account to close, no sync engine to quietly rewrite it. Every failure mode that kills a digital artifact leaves a print untouched. It fails to fire, water and the bin, which is why you make several and keep them apart.

It also answers the two questions the digital copies cannot always answer for themselves.

**Which photo was it?** You may have thousands. In ten years you will not remember which one, and there is nothing in any of them to say. The print *is* the answer: it is the image. Hold it up and you know what you are looking for.

**What was the descriptor?** The Picture carrier never stores it, and a stripped artifact has lost its own copy. The back of the print carries it.

That is why the print sits close to the passphrase in importance. Not equal to it, since the passphrase is what protects the funds, but the print is what keeps the other two layers reachable. Lose every print and forget the descriptor, and you can still be holding a hundred perfect artifacts you cannot open.

**It is safe to keep in the open, and this is the point.** A framed photo on a shelf, a print in an album, a postcard in a book. What does a person who finds it have? A photograph and a caption. They do not know it is anything else, they do not have the passphrase, and without that they reach a decoy even if they work out everything else.

A photograph with writing on the back is not a suspicious object. That is the whole idea, carried out of the files and into the world.

Make several. Different photos, different places. Frame one and hang it on the wall if you like: that is the most ordinary thing anyone can do with a photograph, and it is as good a hiding place as a drawer.

---

## One Last Thing

Verify before you trust it. Import each artifact back on the device, confirm the seed recovers, the hint displays, and the passphrase produces the addresses you expect. A backup you have never opened is not a backup.

The rest is yours to arrange. How many copies, which photos, which channels, what the descriptor says, whether the funds sit behind a passphrase at all. The device does not impose a scheme and this document is not one.

---

## Implementation

| File | Role |
|------|------|
| `features/stego.rs` | Metadata builder and parser, JPEG injector, carrier selection |
| `features/stego_dct.rs` | Picture carrier: coefficient-domain embedding |
| `features/stego_perm.rs` | Keyed permutation over coefficient positions |
| `handlers/stego.rs` | Export and import flow |
| `hw/sd_backup.rs` | Container v3, AES-256-GCM, PBKDF2 |

Pure Rust, `no_std`. Stack buffers with compile-time bounds throughout the small paths; the heap holds what would otherwise overflow the stack, including the JPEG itself in PSRAM.
