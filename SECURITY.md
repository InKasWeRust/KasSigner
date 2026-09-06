<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Security Policy

KasSigner handles wallet secrets and transaction authorization on consumer ESP32-S3 hardware. It is an **experimental offline signing device**, not a secure-element hardware wallet. Security-sensitive changes must fail closed, preserve on-device review, and remain reproducible/testable.

## Supported Versions

The maintained source line is **2.0.0**. Published 1.x history is retained in [CHANGELOG.md](CHANGELOG.md); security fixes are developed on the maintained line and should not be assumed to be backported to every historical release.

Hardware code targets M5Stack CoreS3/CoreS3 Lite and Waveshare ESP32-S3-Touch-LCD-2 variants. **M5Stack CoreS3, KasSee Web, Android, and the iOS app on macOS Sonoma/Xcode 16.2 with an iPhone 16 Pro Simulator have been tested.** Waveshare/other ESP32-S3 hardware variants remain physical-qualification gaps. Signed iOS Release plus physical-device smoke remains release evidence rather than an unresolved application-support gap. See the validation warning in [README.md](README.md).

## Reporting a Vulnerability

**Do not open a public issue for an undisclosed security vulnerability.**

Email **kassigner@proton.me** with subject `[SECURITY]` and include the affected version/build, reproducible steps or proof, impact, and any proposed mitigation. The project will acknowledge, assess, fix/mitigate, and coordinate disclosure as quickly as practical; no fixed response time is a security guarantee.

## Security Model

### Layer 1 - Offline authorization boundary

The firmware does not operate a wallet network stack. Transaction/watch data is exchanged through QR and SD workflows; touch/display is the human approval boundary. Development/provisioning USB/serial paths are separate from normal wallet operation and production policy restricts diagnostic/debug combinations.

### Layer 2 - Wallet key lifecycle

Users choose one of two hardware wallet-session modes:

- **Always Start Fresh** - wallet slots remain RAM-only and are not restored after power loss.
- **Device-bound wallet storage** - authenticated ciphertext is persisted and unlocked with the user's PIN/password plus the non-exportable/read-protected ESP32-S3 HMAC eFuse capability.

The mnemonic recovery words, together with the optional BIP39 passphrase, remain the permanent portable recovery path. Device-bound ciphertext is not a replacement for recovery words.

### Layer 3 - Hardware Secure Boot and owner authority

ESP32-S3 Secure Boot v2 can anchor the boot chain in eFuse with RSA-3072. The normal CoreS3 release does not contain eFuse-provisioning UI or request logic. Two separate opt-in production provisioning profiles expose **Pop It!** as the user-controlled irreversible transition: `secure-provisioning` keeps the vendor RSA authority and can optionally add an independent owner authority, while `secure-owner-only` restores the original sole-owner model in which the owner RSA key is digest 0 and no vendor Secure Boot authority remains trusted. Neither special profile performs irreversible Flash Encryption, Secure Boot, or anti-rollback eFuse transitions during ordinary boot/use; those changes are deferred until explicit Owner/Pop It consent. Development firmware simulates this path and cannot arm production eFuse operations. Provisioning must therefore be rehearsed on sacrificial hardware and every private key required by the selected policy must remain offline. See [docs/security/POP_IT_SECURE_BOOT.md](docs/security/POP_IT_SECURE_BOOT.md) and [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md).

### Layer 4 - Software firmware verification

KasSigner also verifies software build identity/hash/signature evidence at boot. This catches corruption and participates in production attestation, but software self-verification is not by itself a silicon root of trust because the verifier and its key material are part of the image. Hardware Secure Boot is the stronger anchor.

### Layer 5 - Rust memory safety and secret handling

The firmware signing path is bare-metal `no_std` Rust. `unsafe` is confined to hardware/MMIO, volatile zeroization, and reviewed low-level memory construction/access boundaries. Repository checks reject new broad suppressions and track zeroization, signing-state authorization, parser bounds, and critical source contracts. Rust memory safety reduces common memory-corruption classes; it does not prove absence of logic, side-channel, compiler, or hardware faults.

### Layer 6 - Authenticated backup/storage

Current device-bound persistence and current SD seed/XPrv backups use purpose/domain-separated AES-256-GCM with a credential-derived component and the device HMAC eFuse capability. They **work only with the KasSigner device that created them** and are expected to fail authentication on another signer.

Current JPEG steganographic backup has two modes:

- **Device-bound (recommended)** - protected by the creating device's eFuse HMAC capability.
- **Portable Backup** - complete cross-device recovery requires **JPEG + password**. Current Portable payloads use versioned Argon2id v=19 password stretching and AES-256-GCM. The JPEG carries the non-secret KDF parameters, random salt, nonce, ciphertext/tag, and carrier metadata needed by another KasSigner; those parameters are authenticated as AEAD associated data. Because the format is self-contained, possession of the JPEG permits offline password guesses. Argon2id raises the cost of each guess but does not make weak passwords safe.

See [docs/security/STEGANOGRAPHY.md](docs/security/STEGANOGRAPHY.md).

### Layer 7 - Session-bound QR transport

Current multi-frame QR transport uses a versioned 96-bit session identifier, fragment metadata/conflict checks, and a final payload digest. Foreign frames cannot silently replace or contaminate an active assembly. Legacy sessionless framing is not a current signing path.

### Layer 8 - Reproducible builds and QA

The repository pins build/QA toolchains and provides reproducible Docker release builds. QA includes mutation testing, crypto-domain mutation requirements, fuzzing, branch coverage, CRAP/complexity checks, architecture/source inventory gates, browser behavioral coverage, and security control-evidence contracts. These controls reduce software risk; they are not a substitute for independent review or physical validation.

See [docs/development/REPRODUCIBLE_BUILD.md](docs/development/REPRODUCIBLE_BUILD.md) and `qa/release/README.md`.

## KasSee Security Boundary

KasSee runs on an online browser/device and is **not** the trusted spending display. It should not receive wallet spending private keys. A compromised browser, OS, extension, network path, or node may alter displayed data or the unsigned transaction it constructs. The signer must independently parse/review the actual payload and the user must verify the device screen before approval.

Public node use also leaks queried addresses/IP/network metadata to the node operator. Run your own node when that privacy/trust trade-off matters.

The Android and iOS applications are platform shells around the same KasSee runtime rather than independent wallet implementations. Native shell security (app lock, permissions, WebView/WKWebView policy, decoy/privacy cover) does not make the online device a spending-key trust boundary.

## Backward-Compatible Recovery Boundary

KasSigner retains only narrowly scoped compatibility needed to recover current wallet ownership without reopening retired signing protocols.

Password-only wallet-secret containers are **not** part of this exception. Historical password-only seed/XPrv/recovery containers are **intentionally unsupported**. Current device-bound seed/XPrv backup is a distinct authenticated format and does not act as a legacy reader.

Approved/current recovery behavior:

- Historical Base58 kpub text is accepted only by an isolated decode-only adapter and immediately normalized to the canonical current representation; current software does not emit Base58 kpub.
- Imported account XPrvs preserve the metadata required to reproduce their expected account serialization and receive/change chains.
- The **mnemonic recovery words** plus optional BIP39 passphrase are the permanent cross-device master recovery backup.
- Device-bound wallet storage and device-bound SD backups are convenience storage and **work only with the KasSigner device that created them**; copying ciphertext to another device is expected to fail.
- Current JPEG Portable mode is a password-only, self-contained Argon2id/AES-256-GCM format whose recovery contract is **JPEG + password**; it does not restore the historical Base64/password-only decoder or the unreleased development password-plus-recovery-key format.
- Current Oracle-v1, ZK Crowdfunding, Private Swap v2, KSPT v4, and session-bound QR use new current protocols. Historical raw-hash Oracle/Crowdfunding, adaptor-v1, KSSN v1, sessionless QR, and legacy KSPT transaction-session formats are not resumed or signed.

Users recover wallet material and rebuild unfinished historical transactions in the current format rather than exposing the current signer to obsolete transaction/session parsers.

## Covenant-Signing Boundary

Generic wallet-key `SIGN HASH` is retired. Human-readable wallet message signing remains domain-separated. Third-party covenant commitments use **`COVENANT SIGN`**, which derives mnemonic-only isolated covenant keys and keeps the KasSigner safety envelope separate from the exact external 32-byte commitment.

Recognized schemes are recomputed/validated on-device. Opaque/custom requests require stronger warning/confirmation and still use the isolated covenant hierarchy. The ordinary wallet-spending key hierarchy does not receive generic caller-selected-digest authority.

See [docs/protocol/COVENANT_SIGN.md](docs/protocol/COVENANT_SIGN.md).

## Private Swap Boundary

Private Swap v2 restores the adaptor-signature privacy goal without restoring historical adaptor-v1. Adaptor pre-signatures are bound to exact canonical Kaspa `SIGHASH_ALL` claim transactions, use isolated swap-only claim/binding/adaptor branches, and participate in host-assisted anti-klepto nonce binding. Completed on-chain claims are ordinary BIP340 transaction signatures; CLTV owner refunds remain the failure path. The protocol does not use an HTLC/hashlock preimage or shared on-chain protocol hash.

## What KasSigner Does NOT Protect Against

- Lab-grade physical attacks, invasive probing, voltage/clock glitching, EM/power/cache/bus side channels, or fault injection unless separately demonstrated by hardware evidence.
- A compromised compiler/toolchain that still reproduces across all builders used by the user.
- Weak Portable-backup passwords. A self-contained Portable JPEG necessarily permits offline password guesses; Argon2id makes each guess more expensive but password strength still matters.
- Social engineering or disclosure of mnemonic/passphrase/PIN/password.
- A compromised companion browser/OS before the signer parses and the user reviews the actual transaction.
- Bugs in hardware variants that have not yet completed physical qualification, or mobile behavior not covered by the signed physical-device release-evidence matrix.

## Known Limitations and Audit Status

The v1.0.5 history records an external/source security audit that produced 40 findings and drove substantial hardening. The 2.0.0 source tree also has extensive repository-owned source review and automated assurance.

The source repository does not embed the completed external audit/HIL records required by `qa/release/README.md`; those records are artifact- and hardware-bound release evidence kept outside Git. Repository-generated `current-control-evidence.json`, mutation results, coverage, fuzzing, and related checks are project-owned engineering evidence, not third-party certification. KasSigner therefore does not claim formal verification or independent certification merely because repository QA passes.

## Cryptographic Primitives

| Purpose | Primitive / boundary |
|---|---|
| Mnemonic / recovery | BIP39, optional BIP39 passphrase |
| HD derivation | BIP32 Kaspa account paths |
| Child mnemonics | BIP85 |
| Transaction/message signatures | secp256k1 Schnorr / BIP340-compatible challenge rules as required by Kaspa/current protocol |
| Transaction hashing | Kaspa consensus hashing / keyed Blake2b where required |
| Credential stretching | Argon2id v=19 for current KasSigner-owned password formats; PBKDF2 only for BIP39 and explicitly versioned deployed-legacy readers |
| Authenticated encryption | AES-256-GCM with purpose/domain separation |
| Stealth / ECIES-style flows | secp256k1 ECDH + protocol KDF/AEAD |
| Firmware identity | SHA-256 + Schnorr software evidence; optional RSA-3072 Secure Boot v2 hardware chain |
| Constant-time boundaries | fixed-time comparisons and reviewed scalar/key operations where required |

Exact constants/format versions are source-of-truth in the current implementation and protocol docs; this table intentionally avoids duplicating volatile implementation constants.

## Assurance Policy

Current source policy includes:

- >=92% viable-mutant kill rate for the global critical mutation gate.
- 100% viable non-equivalent kill requirement for the explicitly enumerated host-testable crypto/key/signing mutation domain, with zero allowed timeouts.
- 90% host/critical-domain branch targets in the current coverage policy.
- Pinned fuzz/toolchain inputs, CRAP/complexity checks, architecture/source inventory gates, browser behavioral coverage, and test-quality evidence checks.
- Separate release-readiness evidence for independent review, clean builders, HIL/fused hardware, physical entropy, signing custody, fault/update testing, and other claims that source tests cannot establish.

These numbers describe repository gates, not a probability that the system is secure.

## Responsible Disclosure

1. Report privately to the security email above.
2. The project confirms and scopes the issue.
3. A fix/mitigation and regression evidence are developed.
4. Affected users receive an update path.
5. Details and credit are coordinated after users have reasonable time to update, unless immediate disclosure is necessary.

## eFuse / Secure Boot Notes

ESP32-S3 eFuse changes can be irreversible. Losing a production signing key or burning the wrong purpose/protection bits can permanently prevent updates or destroy the intended security boundary. Never use copied commands from an old guide without validating them against the current source/toolchain and sacrificial hardware.

See [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md).

## Bug Bounty

There is currently no formal paid bug-bounty program. Responsible security researchers may be credited unless anonymity is requested.
