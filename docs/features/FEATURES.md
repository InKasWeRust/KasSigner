[KasSigner](../../README.md) › [Documentation](../README.md) › Features

# Features

KasSigner 2.0.0 combines an air-gapped ESP32-S3 signer, the KasSee watch-only companion, native Android/iOS shells, hardened transaction/covenant protocols, optional device-bound persistence, and high-assurance QA. Release/security history lives in [CHANGELOG.md](../../CHANGELOG.md).

## Core signer

- **Fully air-gapped signing** — firmware has no wallet-network path; transaction data moves through QR/SD and is reviewed on-device.
- **BIP39 seed generation** — 12 or 24 words from camera + health-checked hardware RNG + device/timing inputs, **or manual dice rolls**; Touch Seed is also available.
- **BIP32 / BIP85** — Kaspa HD derivation, optional BIP39 passphrase (25th word), and deterministic child mnemonics.
- **Optionally stateless** — **Always Start Fresh** keeps wallet secrets in RAM only and destroys them on power-off; device-bound encrypted persistence is optional.
- **Schnorr signing** — Kaspa transactions and arbitrary-message signing using secp256k1.
- **PSKT/PSKB + compact KSPT v4** — session-bound QR framing, conflict checks, and payload digests for air-gapped exchange.
- **Multisig** — M-of-N P2SH creation, co-signing, relay, and broadcast workflows.
- **Secure boot / firmware verification** — normal production uses software self-verification and omits provisioning UI/request logic. The opt-in CoreS3 `secure-provisioning` profile adds vendor + optional owner Secure Boot v2 authority, while `secure-owner-only` restores the original model where the owner RSA-3072 key is the sole hardware authority. Both defer irreversible eFuse transitions to explicit Owner/Pop It actions; development firmware only simulates those paths.

## Wallet slots and recovery

KasSigner supports up to 16 active wallet slots:

- **Mnemonic (12/24 words)** — full BIP39 wallet; supports HD addresses, BIP85, signing, kpub/XPrv, and SeedQR.
- **Account XPrv** — account-level extended private key with preserved derivation metadata; mnemonic-only operations are unavailable.
- **Raw private key** — a single 32-byte secp256k1 scalar controlling one matching address. Imported as 64 hex characters via the on-device hex keypad or compatible file workflow. **Compatible with KasWare-style raw-key exports.**

Backups include mnemonic recovery words, CompactSeedQR, authenticated SD seed/XPrv backups, and JPEG steganographic carriers. Historical Base58 kpub text is accepted only through an isolated decode-only adapter and normalized to the current representation. Historical password-only secret containers and retired transaction/session wire formats are intentionally not restored.

## Steganographic backup

KasSigner can hide an encrypted mnemonic in an ordinary JPEG using either:

- **Descriptor** — authenticated payload in EXIF metadata; metadata stripping destroys it.
- **Picture** — authenticated payload in keyed JPEG coefficient positions; recompression destroys it.

Current exports offer **Device-bound** protection using the creating KasSigner's read-protected eFuse HMAC capability, or **Portable Backup** for cross-device recovery. Device-bound requires the original device and must not be the user's only disaster-recovery copy. Portable recovery requires exactly **JPEG + password**, uses versioned Argon2id v=19 plus AES-256-GCM, and works on another supported KasSigner. Because the Portable JPEG is self-contained, it permits offline password guesses; Argon2id raises the cost of each guess but does not make weak passwords safe.

See [JPEG Steganographic Backup](../security/STEGANOGRAPHY.md).

## Covenants++

KasSee builds covenant transactions, KasSigner reviews/signs them offline, and KasSee broadcasts them. Current families include:

- Piggy Bank
- Time-Locked Savings
- Dead Man's Switch
- Allowance
- Spending Limit
- Merkle Whitelist
- Direct Channel
- PayJoin
- Commit-Reveal
- **Private Swap v2** — transaction-sighash-bound adaptor signatures with isolated swap keys; no hashlock/preimage or shared protocol hash on-chain
- KIP-20 Vaults
- **Oracle-v1** — isolated oracle covenant key signs the exact canonical release-statement commitment
- **ZK Crowdfunding** — campaign-specific contribution covenants, Groth16 goal proof, bounded sweep, and contributor timeout refund
- ZK Price Oracle
- Stealth payments

Recognized covenant transactions are validated against their protocol contracts. `COVENANT SIGN` handles exact third-party commitments under isolated covenant keys with stronger warnings for opaque/custom requests. See [`COVENANT SIGN`](../protocol/COVENANT_SIGN.md) and the [Covenants & Stealth Guide](../guides/KasSigner_Kassee_Covenants_Stealth_Guide.pdf).

## Companion and assurance features

- **KasSee Web** — watch-only wallet, transaction construction, UTXO controls, QR signing workflow, assets, covenants, stealth, recovery, node selection, and broadcast.
- **Android + iOS apps** — native shells around the same KasSee runtime rather than separate wallet engines.
- **Reproducible builds and high-assurance QA** — pinned toolchains, mutation/fuzz/coverage/CRAP gates, architecture checks, and explicit release-readiness evidence requirements.

For KasSee detail, see [KasSee](../kassee/KASSEE.md). For assurance boundaries, see [Security](../security/SECURITY_OVERVIEW.md).
