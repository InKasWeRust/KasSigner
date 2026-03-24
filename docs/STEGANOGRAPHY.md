# The Invisible Vault

## How KasSigner Hides Your Seed in Plain Sight

Imagine you lose everything. Fire, flood, theft — whatever. Your hardware wallet is gone. Your metal seed plate melted. Your safety deposit box was compromised. Years of accumulated wealth, evaporated.

Now imagine a different scenario. Your seed lives inside a photo of your dog. It sits in your Google Drive, in your email, on a USB stick in your desk drawer, on your phone's camera roll. Nobody knows. Nobody can tell. The photo looks like every other photo — because it is a photo. The pixels are untouched. The file size is normal. No forensic tool will flag it. No thief will think twice about it.

That photo *is* your vault. And the caption you wrote on it — "Rocky at the beach, summer 2024" — is the key.

---

## The Architecture

KasSigner embeds encrypted seeds into JPEG photographs using EXIF metadata. EXIF is the standard metadata format that every digital camera writes: date, GPS coordinates, camera model, exposure settings — and text fields like `ImageDescription`. Photo management software, cloud storage, and operating systems all read and preserve EXIF. It is the most ordinary, most invisible, most overlooked data structure in digital photography.

KasSigner uses two EXIF fields:

**`ImageDescription`** — This is your passphrase. Not a cover story for the passphrase. Not a hint toward the passphrase. It *is* the passphrase, typed into the photo's metadata where any viewer can see it. It looks like a caption: *"Sunset at Playa Blanca, Aug 2024"*. Anyone inspecting the EXIF sees a normal description. What they cannot know is that this exact string of characters — every letter, every space, every comma — was fed through PBKDF2 with 10,000 iterations of HMAC-SHA512 to derive a 256-bit AES key.

**`UserComment`** — This holds the encrypted seed. Base64-encoded, it looks like garbled metadata — the kind of string a camera firmware might write, the kind nobody questions. Inside it: a 12-byte random nonce, the seed word indices encrypted with AES-256-GCM, and a 16-byte authentication tag that ensures even a single bit flip is detected.

The key is the caption. The caption is the key. They are the same thing, and it is visible to everyone, and it is useless to everyone who doesn't know what it is.

---

## Why This Is Different

Every other seed backup method has the same problem: it looks like a seed backup.

A metal plate stamped with 24 words is obviously a seed backup. A Cryptosteel capsule is obviously a seed backup. A paper wallet in a safe is obviously a seed backup. An encrypted file named `seed_backup.enc` is obviously a seed backup. Any attacker who finds these knows exactly what they have and exactly what to do with it.

A photo of your dog is not a seed backup. It is a photo of your dog.

The security does not depend on hiding the file. You can put it anywhere — cloud storage, email, USB drives, printed and framed on your wall. The security comes from the fact that the file is indistinguishable from the billions of JPEG photographs that exist in the world. An attacker doesn't need to crack the encryption. They need to realize encryption exists in the first place, and there is nothing to suggest it does.

---

## The Three Layers

An attacker must defeat all three independent layers to reach your funds. Each layer is a fundamentally different kind of problem.

### Layer 1 — Which File?

You have 4,000 photos on your Google Drive. One of them contains your seed. Which one?

There is no way to tell. The EXIF metadata format is identical to what any camera produces. The `UserComment` field contains base64 text that looks like firmware data. The `ImageDescription` contains text that looks like a caption. No statistical analysis, no entropy test, no forensic tool will flag this file as different from the other 3,999.

The attacker's problem is not decryption. It is identification. They are searching for a needle in a haystack, and the needle looks exactly like hay.

### Layer 2 — What Caption?

Say the attacker somehow identifies the correct photo. They extract the EXIF and find the `UserComment`. They recognize the base64 encoding. They even figure out it's an AES-256-GCM encrypted blob. Now they need the key.

The key was derived from the `ImageDescription` field: *"Me at the age of 20 with my family"*. It's right there. They can read it. But they don't know it's the key. And even if they suspect EXIF-based steganography, the `ImageDescription` looks like what it says it is — a description of the image. The attacker must make the conceptual leap that this visible, ordinary text string is the cryptographic passphrase. There is nothing in the data to suggest this. It is not labeled. It is not formatted like a password. It does not look like a key because it was never designed to look like a key.

And if they do make that leap — if they try every EXIF field as a potential passphrase — then AES-256-GCM gives them exactly one answer: right or wrong. No partial decryption. No gradual convergence. The GCM authentication tag either validates or it doesn't.

### Layer 3 — What Word?

This is the final wall, and it exists nowhere.

Even if the attacker has the correct file, decrypts the correct `UserComment` with the correct `ImageDescription`, and recovers all 24 BIP39 mnemonic words — they do not have your wallet. They have *a* wallet. A decoy. Put some dust in it. Make it look real.

Your actual funds live on a derivation path created by the BIP39 passphrase — the 25th word. This passphrase is concatenated with the mnemonic during PBKDF2 seed derivation. Different passphrase means different master key, different addresses, different wallet. Same 24 words, completely separate universe of keys.

The 25th word is never written down. Never stored on any device. Never transmitted. Never recorded in the EXIF, on the SD card, in the encrypted backup, anywhere. It exists only in the owner's memory. The only way to obtain it is to ask the owner, and the owner can point to the decoy wallet and say "that's all there is."

---

## The Recovery Hint

Humans forget. Over years, even the most important memories fade. The 25th word protects your wealth, but it only works if you remember it.

KasSigner addresses this with an encrypted recovery hint embedded alongside the seed. During export, you can attach a question whose answer is your 25th word:

- *"My favorite place I lived?"*
- *"Name of my loved one?"*  
- *"Song I can't stop humming?"*
- Or any custom text you write.

The hint is encrypted with the same `ImageDescription` passphrase and appended to the `UserComment` after a `|` separator. During import, after the seed is decrypted, the hint is decrypted and displayed on screen — a private reminder, visible only to someone who already proved they know the descriptor text.

The hint is not the answer. It is a question designed to trigger a memory. The answer — the 25th word — is never stored. It travels from your memory to the device's keypad and back to your memory, touching nothing permanent along the way.

---

## Technical Specification

### Encrypted Seed Format

The seed is encrypted using the `sd_backup` module (shared with the SD card backup feature):

```
Offset  Size     Field
──────  ───────  ──────────────────────────
0x00    4 bytes  Magic: "KAS\x01"
0x04    1 byte   Word count (12 or 24)
0x05    12 bytes Nonce (hardware TRNG)
0x11    24 or 48 Ciphertext (word indices, 2 bytes each)
0x29/41 16 bytes AES-256-GCM authentication tag
──────────────────────────────────────────
Total:  57 bytes (12-word seed) or 81 bytes (24-word seed)
```

This blob is base64-encoded (76–108 characters) before storage in EXIF.

### Key Derivation

```
ImageDescription text (UTF-8 bytes)
    │
    ▼
PBKDF2-HMAC-SHA512
    Salt: "KasSigner-SD-v1" (15 bytes, fixed)
    Iterations: 10,000
    │
    ▼
256-bit AES key
    │
    ▼
AES-256-GCM encrypt/decrypt
    Nonce: 12 bytes (random, stored in blob)
    AAD: [0x4B, 0x41, 0x53, 0x01, word_count]
    │
    ▼
Ciphertext + 16-byte GCM tag
```

The GCM authentication tag provides tamper detection. Any modification to the ciphertext, nonce, or associated data (including the word count) causes decryption to fail with "Wrong passphrase" — there is no silent corruption.

### EXIF APP1 Structure

```
FF E1 [length]              JPEG APP1 marker
"Exif\0\0"                  EXIF header (6 bytes)
"II" 0x2A00 0x08000000      TIFF header (little-endian, IFD at offset 8)

IFD0 (2 entries):
  Tag 0x010E  ImageDescription  ASCII   → The passphrase (visible caption)
  Tag 0x9286  UserComment       UNDEF   → "ASCII\0\0\0" + base64(encrypted_seed)
                                           Optional: "|" + base64(encrypted_hint)

Next IFD pointer: 0x00000000 (no more IFDs)
Data area: description bytes + null terminator + comment bytes
```

The new APP1 segment is injected after the JPEG SOI marker (`FF D8`). Any existing APP1 (previous EXIF) is removed. All image pixel data — every scan line, every MCU block, every Huffman table — is copied byte-for-byte. The image is mathematically identical.

### Recovery Hint Format

When a hint is provided, it is encrypted separately using the same key derivation (ImageDescription → PBKDF2 → AES-256-GCM) and appended to the UserComment:

```
UserComment = "ASCII\0\0\0" + base64(encrypted_seed) + "|" + base64(encrypted_hint)
```

During import:
1. Split UserComment on `|`
2. Decrypt seed with ImageDescription
3. If `|` separator found: decrypt hint with same key, display on screen
4. User reads hint, types 25th word from memory
5. Device derives wallet using 24 words + 25th word

### File Impact

The EXIF overhead is 200–400 bytes on a file that's typically 500KB–5MB. The size change is below the noise floor of JPEG quantization. No viewer, no thumbnail generator, no cloud sync engine will notice.

---

## What Survives

**Safe channels** — file copy (USB, SD, network), Google Drive, Dropbox, iCloud, email attachments, NAS backup, JPEG recompression (pixels change but EXIF metadata survives).

**Unsafe channels** — Twitter/X (strips all EXIF), Instagram (strips all EXIF), Facebook (strips most EXIF), WhatsApp (strips metadata on send), any "metadata removal" tool, screenshots (new image, no EXIF), OCR or re-encoding.

**Always test your backup path.** Upload a JPEG with custom EXIF to your intended storage, download it back, and verify the EXIF fields survived. Do this before trusting the channel with real funds.

---

## Operational Security

**Choose your descriptor carefully.** It should be memorable, natural-sounding, and specific enough that you won't confuse it with another photo's caption. A full sentence is better than a few words. *"The old house on Elm Street where we had Christmas 2019"* is stronger and more memorable than *"password123"*.

**Use the recovery hint.** Years from now, you need to remember the 25th word. A hint that triggers the right memory — *"My favorite place I lived?"* → *"Montevideo"* — is the difference between recovery and permanent loss.

**Multiple copies across different photos.** Embed the same seed in three different JPEGs with the same descriptor. Store them in different places. If one storage channel strips metadata, the others survive.

**Verify before you trust.** After embedding, import the stego JPEG back on the device. Confirm the seed recovers correctly. Confirm the hint displays. Confirm the 25th word produces the right addresses. Do not skip this step.

**The decoy wallet matters.** Send a small amount to the wallet derived from the 24 words alone (no 25th word). If an attacker ever gets to Layer 3, they find real funds and may stop looking. An empty decoy wallet is suspicious. A wallet with some activity is convincing.

---

## Implementation

| File | Role |
|------|------|
| `features/stego.rs` | EXIF APP1 builder, base64 codec, EXIF parser, JPEG injector |
| `handlers/stego.rs` | Export and import UI flow (16 app states) |
| `hw/sd_backup.rs` | AES-256-GCM encrypt/decrypt, PBKDF2 key derivation |

The entire steganography system is implemented in pure Rust, `no_std`, with zero heap allocation. All buffers are stack-allocated or in PSRAM. The JPEG file is read into PSRAM (up to ~2MB), the EXIF is built in a stack buffer, and the modified JPEG is written back to SD card in a single pass.
