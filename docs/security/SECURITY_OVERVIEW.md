[KasSigner](../../README.md) › [Documentation](../README.md) › Security › Overview

# Security overview

KasSigner is security-sensitive software running on consumer ESP32-S3 hardware. Its automated assurance is extensive, but testing does not replace independent review, broad hardware validation, physical attack testing, entropy characterization, or field history. See the repository [security policy](../../SECURITY.md) for reporting and detailed security constraints.

## Air-gap enforcement

The firmware does not use a wallet network stack. Data enters/leaves through QR, SD, touch/display, and explicitly controlled USB/serial paths used for development/provisioning. Production policy disables or gates debug/data paths; eFuse provisioning is a separate irreversible manufacturing step.

## Key lifecycle

1. Create/import a mnemonic, account XPrv, or raw private key.
2. Keep active wallet material in RAM, or explicitly opt into device-bound encrypted persistence.
3. Derive signing keys only for the reviewed operation.
4. Zeroize sensitive transient buffers after use where the implementation owns them.
5. Recover across devices from mnemonic words + optional passphrase, not from device-bound ciphertext.

## Boot verification and owner authority

Software self-verification checks the running image against build-time identity/signature evidence. The normal reproducible production release intentionally excludes the Pop It!/owner-authority UI and all application boot-control request staging, so flashing and using that profile cannot opt into eFuse provisioning. CoreS3 hardware-rooted provisioning uses separate explicit profiles: `secure-provisioning` for vendor + optional owner authority, or `secure-owner-only` for the restored sole-owner hardware trust root. Both special profiles are non-destructive at ordinary boot: release-mode flash-encryption initialization/enabling, Secure Boot v2 enablement, and hardware anti-rollback advancement remain deferred until the user completes the typed Pop It! action. Owner RSA-3072 enrollment is a separate typed action before Pop It!: it is optional in dual-authority mode and mandatory in owner-only mode; development firmware exposes the same UI only as a simulation and performs no eFuse writes. After Pop It!, the ROM authenticates the second-stage bootloader according to the selected profile: dual-authority devices retain vendor authority (and, when enrolled, owner authority), while owner-only devices trust only the owner RSA key. Software self-checking alone is not a silicon root of trust. In dual mode the live vendor/owner revoke controls are protected; loss of the owner key still leaves vendor-authorized updates. In owner-only mode digest 0 is the protected sole owner authority and unused authority slots are revoked, so loss or compromise of that owner key cannot be repaired by a vendor signing key.

## Cryptographic primitives

KasSigner uses BIP39/BIP32/BIP85, secp256k1 Schnorr/BIP-340-compatible signing, SHA-256/HMAC, Kaspa transaction hashing, PBKDF2, AES-256-GCM, and ECDH where required. Protocol-specific domain separation and isolated derivation branches are used for covenant, anti-klepto, and stealth functions.

## Assurance boundaries

KasSigner is:

- an offline signer and seed generator;
- optionally stateless through **Always Start Fresh**;
- open source with reproducible-build and aggressive automated QA gates.

KasSigner is **not**:

- a secure-element hardware wallet;
- resistant to lab-grade physical attack;
- formally verified or security-certified;
- a substitute for recovery words.

Historical independent/source security review informed substantial hardening. Formal production-release claims additionally require the externally signed evidence defined in `qa/release/README.md`; repository QA is not a substitute for those attestations.

## What it does not protect against

- Compromised build toolchains unless reproducible evidence catches the difference
- A compromised companion browser/OS before on-device review
- Weak or disclosed Portable-backup passwords; a self-contained Portable JPEG permits offline guesses, with Argon2id increasing the cost per guess
- Social engineering or disclosure of mnemonic/passphrase
- Physical/fault/side-channel attacks beyond the tested source/software controls

## Entropy source policy

The current seed mixer, source-credit rules, CoreS3 BMI270 boundary, and E-12 limitation are documented in [Entropy Sources](ENTROPY_SOURCES.md).
