# KasSigner — Key Derivation Architecture

## The Derivation Tree

Every Kaspa wallet starts from a seed phrase. Each level below is derived via one-way cryptographic hashing. You can always go **down** the tree, never **up**.

```
 SEED PHRASE (12 or 24 BIP39 words)
 │
 │  BIP39: words → entropy → PBKDF2("mnemonic" + passphrase, 2048 rounds)
 │  Output: 512-bit (64-byte) seed
 │  ★ This is the ONLY level that can regenerate everything
 │
 ▼
 MASTER KEY ─────────────────────────────────────────────────
 │  HMAC-SHA512("Bitcoin seed", seed)
 │  = 32-byte private key + 32-byte chain_code
 │  The chain_code is "derivation DNA" — without it, no children
 │
 ├── m/44' ──────────────────────── Purpose (BIP44)
 │     Hardened derivation: HMAC-SHA512(chain_code, 0x00 || key || index)
 │     Uses the PRIVATE key as HMAC input → irreversible from public side
 │
 ├──── m/44'/111111' ───────────── Coin Type (Kaspa)
 │       Same hardened HMAC-SHA512
 │
 ├─────── m/44'/111111'/0' ─────── Account 0  ← THIS IS THE "xprv" LEVEL
 │          key (32 bytes) + chain_code (32 bytes) + metadata
 │          ★ Can derive ALL addresses for this account (0, 1, 2, ... ∞)
 │          ✗ Cannot derive other accounts or go back to seed
 │
 ├────────── m/44'/111111'/0'/0 ── External chain (receiving)
 │             Normal derivation: uses PUBLIC key as HMAC input
 │             Still carries chain_code
 │
 ├─────────────  /0'/0/0 ────────── Address index 0  ← RAW PRIVATE KEY
 │               /0'/0/1 ────────── Address index 1
 │               /0'/0/2 ────────── Address index 2
 │               /0'/0/N ────────── Address index N
 │
 │  Each index = 32-byte secp256k1 scalar
 │  NO chain_code → DEAD END → can only sign, nothing else
 │  Cannot derive siblings, cannot go up, cannot create children
 │
 ▼
 PUBLIC KEY = private_key × G (generator point on secp256k1)
   One-way: private key → public key ✓
            public key → private key ✗ (would require breaking elliptic curves)
   The x-coordinate of the public key point = your Kaspa address
```

## Why Each Level Exists

### Seed Phrase (12/24 words)
- **Human-readable backup** — write on paper, stamp in metal
- Contains full entropy — everything can be rebuilt from these words
- BIP39 passphrase adds an extra dimension: same words + different passphrase = completely different wallet
- PBKDF2 with 2048 iterations deliberately slows brute-force attacks

### Master Key
- First derivation from seed — the root of the HD (Hierarchical Deterministic) tree
- The chain_code ensures that knowing one child key doesn't reveal siblings
- Without chain_code, a private key is just a dead-end number

### Account Key (xprv)
- The "useful" export level — contains everything needed to manage one account
- Wallets like Kaspa-NG use this for import/export
- Hardened path (all ' levels) means: even if someone gets a child private key + the parent public key, they still can't compute the parent private key
- Multiple accounts (0', 1', 2') can exist under the same seed — each is an independent wallet

### Address Key (raw private key)
- The signing key for one specific address
- Wallets like KasWare allow importing individual private keys
- Useful for: receiving funds at a specific address, sweeping funds, paper wallets
- Limitation: only one address, no derivation tree

### Public Key
- Derived from private key via elliptic curve multiplication (one-way)
- The x-coordinate (32 bytes) is the Kaspa Schnorr address
- Encoded as `kaspa:qr...` in Bech32 format

## The Chain Code — Why It Matters

The chain_code is what makes BIP32 derivation possible:

```
Parent (key + chain_code) + index → HMAC-SHA512 → Child (key + chain_code)
```

Without chain_code:
- A private key can sign transactions ✓
- A private key can derive its public key ✓  
- A private key CANNOT derive child keys ✗
- A private key CANNOT derive sibling keys ✗

This is why an xprv (which includes chain_code) can derive unlimited addresses, but a raw private key (no chain_code) is stuck at one address.

## KasSigner Slot Types

KasSigner stores wallets in 4 RAM slots. Each slot can hold one of three types:

### Mnemonic Slot (word_count = 12 or 24)
Stores the BIP39 word indices. Has everything.

| Capability | Supported |
|---|---|
| Derive addresses 0 to ∞ | ✓ |
| Sign transactions (any address) | ✓ |
| Export kpub (watch-only) | ✓ |
| Export xprv (full account) | ✓ |
| Export SeedQR | ✓ |
| BIP85 child seeds | ✓ |
| Export single address private key | ✓ |
| Encrypted SD backup | ✓ |
| Paper recovery (words on paper) | ✓ |

### XPrv Slot (word_count = 2)
Stores the account-level extended private key (key + chain_code). Imported from SD or QR.

| Capability | Supported |
|---|---|
| Derive addresses 0 to ∞ | ✓ |
| Sign transactions (any address) | ✓ |
| Export kpub (watch-only) | ✓ |
| Export xprv | ✗ (needs parent fingerprint from seed) |
| Export SeedQR | ✗ (no mnemonic words) |
| BIP85 child seeds | ✗ (needs master key) |
| Export single address private key | ✓ |
| Encrypted SD backup | ✓ (as xprv) |
| Paper recovery | ✗ (xprv string is ~111 chars) |

### Raw Key Slot (word_count = 1)
Stores a single 32-byte private key. Imported via hex keypad.

| Capability | Supported |
|---|---|
| Derive addresses 0 to ∞ | ✗ (one address only) |
| Sign transactions | ✓ (one address only) |
| Export kpub | ✗ (no chain_code) |
| Export xprv | ✗ (no chain_code) |
| Export SeedQR | ✗ (no mnemonic words) |
| BIP85 child seeds | ✗ |
| Export private key hex | ✓ |
| Encrypted SD backup | ✗ (use seed backup instead) |
| Paper recovery | ✓ (64 hex chars — manageable) |

## Conversion Rules

```
Seed Phrase  →  xprv     ✓  (derive m/44'/111111'/0')
Seed Phrase  →  raw key  ✓  (derive m/44'/111111'/0'/0/N)
xprv         →  raw key  ✓  (derive /0/N from account key)
raw key      →  xprv     ✗  (chain_code is lost)
raw key      →  seed     ✗  (entropy is lost)  
xprv         →  seed     ✗  (parent levels are lost)
```

Each downward conversion is a one-way HMAC-SHA512 hash. There is no mathematical way to reverse it.

## Security Implications

- **Seed phrase** is the crown jewel. Protect it above all else. Anyone with your 12/24 words controls ALL your funds across ALL addresses and ALL accounts.

- **xprv** is almost as sensitive as the seed. It controls all addresses in one account. But it can't derive other accounts or BIP85 children.

- **Raw private key** controls exactly one address. If compromised, only that address is affected. Other addresses from the same seed remain safe.

- **kpub (extended public key)** is the safest to share. It allows viewing all addresses and balances but cannot sign transactions or move funds. Use this for watch-only wallets.

## Kaspa-Specific Details

- **Derivation path:** `m/44'/111111'/0'` (coin type 111111 for Kaspa mainnet)
- **Legacy path:** `m/44'/972/0'` (used by KDX and old web wallet — deprecated)
- **Key type:** secp256k1 (same curve as Bitcoin)
- **Signature:** Schnorr (not ECDSA — Kaspa uses Schnorr for all transaction signing)
- **Address format:** Bech32 with `kaspa:` prefix, using the x-coordinate of the public key
- **No WIF:** Kaspa does not use Bitcoin's Wallet Import Format. Private keys are plain hex.
- **xprv version bytes:** `0x038f2ef4` (encodes to "xprv" prefix in base58)
- **kpub version bytes:** `0x038f332e` (encodes to "kpub" prefix in base58)
