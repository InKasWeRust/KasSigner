<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- License: GPL-3.0-only -->

# JPEG steganographic wallet backup

KasSigner supports a **current JPEG steganographic wallet backup** for mnemonic
wallets using both original carriers:

- **Descriptor** — stores the authenticated encrypted wallet payload in EXIF
  `UserComment`; it is lost if metadata is stripped.
- **Picture** — stores the same payload in keyed JPEG coefficient positions; it
  survives metadata stripping but is lost if the image is re-saved/recompressed.

The image descriptor remains ordinary recovery/carrier text. Descriptor mode
also stores that text as the EXIF image description, so the descriptor is **not
a secret** and is never used as the Portable backup password.

## Backup security choice

Every new JPEG backup presents two production choices:

- **Device-bound** — requires the original KasSigner. The payload is protected by
  AES-256-GCM using a key bound to the creating signer's non-exportable,
  read-protected ESP32-S3 eFuse HMAC capability. A Device-bound JPEG is therefore
  **not a complete disaster-recovery backup** and should not be the user's only
  recovery copy.
- **Portable Backup** — complete cross-device recovery requires exactly:
  **JPEG + Password**. It works on another supported KasSigner and does not
  require a second recovery secret.

Portable export asks the user to enter and confirm the password, then writes the
self-contained authenticated payload into the selected JPEG carrier. Import
recognizes the explicit current Portable format and asks for the backup password.
There is no generic KDF probing and no Argon2id-to-PBKDF2 fallback.

## Portable cryptographic boundary

Current Portable JPEG payloads use **Argon2id, Argon2 version 1.3 (v=19)** to
turn the user password and a fresh random salt into a 32-byte AES-256-GCM key.
The current format stores all non-secret recovery metadata required by another
KasSigner:

- format version;
- security/carrier identifiers;
- KDF identifier and KDF-profile version;
- Argon2 version, memory cost, time cost, and parallelism;
- random salt;
- AEAD nonce;
- ciphertext and authentication tag.

The format/KDF metadata, carrier/security mode, and descriptor binding are
included in AES-GCM associated data. Changing the KDF ID, Argon2 parameters,
salt, carrier, security mode, or descriptor binding therefore fails closed.
Current readers also reject parameters below the published profile minimum or
parameters that do not match the current versioned profile. Production does not
weaken the KDF after an allocation failure.

Portable Backup is intentionally self-contained. That means possession of the
JPEG provides an **offline password-guessing target**. Argon2id makes each guess
substantially more expensive; it does not make a weak password safe. Use a
strong, unique backup password and keep the JPEG and password under appropriate
separate controls.

The current Portable format replaces an unreleased password-plus-recovery-key design. KasSigner does not emit that obsolete two-secret format and does not retain a compatibility parser for artifacts that were never part of a supported release.

## Device-bound cryptographic boundary

Device-bound mode remains deliberately different. It derives a descriptor
credential and combines that with the device HMAC boundary before AES-256-GCM.
The original device is required. The authenticated payload remains separated by
carrier/security purpose so Portable and Device-bound ciphertext cannot be
substituted for one another.

Both current modes use a fixed-size encrypted plaintext containing the mnemonic
and optional recovery hint. Parsing is exact, the recovered mnemonic checksum
and type are revalidated, canonical padding is required, and authentication
failure clears recovery outputs.

## Password KDF policy

KasSigner-owned **new password formats** use the central versioned Argon2id KDF
abstraction. Explicit legacy readers may retain PBKDF2 only for artifacts that
were actually emitted by an earlier supported format; the legacy format magic or
version chooses that reader directly.

This policy does **not** change BIP39. Mnemonic-to-seed derivation remains exactly
PBKDF2-HMAC-SHA512 with 2048 iterations and a 64-byte seed, as required for BIP39
interoperability.

## Historical formats

Historical Base64/password-only JPEG payload formats remain unsupported and no
legacy migration decoder is retained. Likewise, the unreleased development
Portable two-secret format is not treated as a permanent compatibility burden.
The durable independent wallet-recovery boundary remains the mnemonic words plus
any BIP39 passphrase.
