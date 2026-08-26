<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner

**Air-gapped offline signing device for the Kaspa blockchain.**

> ⚠️ **IMPORTANT: KasSigner is an EXPERIMENTAL offline signing device. It is NOT a hardware wallet. It has NO secure element and NO persistent storage. All keys are wiped on power-off. This software has NOT been professionally audited. Do NOT use KasSigner to manage funds you cannot afford to lose.**

> ⚠️ **SEEDS GENERATED ON 1.0.4 OR EARLIER:** two defects in seed generation, both closed in 1.0.5. Dice rolls were printed to the USB serial log, and automatic seeds made in poor light could rest on very little entropy. Neither affects signing or any address you hold, but if either could apply to you, generate a fresh seed and move the balance. Details in [CHANGELOG.md](CHANGELOG.md).

KasSigner is an open-source signing device built on ESP32-S3. It generates private keys offline, signs transactions via QR code exchange, and never connects to any network. All key material lives in RAM only and is destroyed when the device powers off. If you have not run the eFuse runbook, treat the USB port as a debug port, not a power port. Power only from sources you own, never import a seed while connected to a computer, and consider a data-blocker.

Published images build with the `production` feature, which compiles out the serial log entirely and gates the USB Serial/JTAG peripheral into reset after boot verification. Download mode stays reachable by the BOOT-button sequence, which needs physical possession of the device.

100% Rust. Bare-metal `no_std`. No operating system. No vendor libraries in the signing path.

## Features

- **Fully air-gapped**: no WiFi, Bluetooth, or USB data. All I/O via QR codes, touchscreen, and SD card
- **No persistent storage**: all keys live in RAM only, wiped on every power-off
- **BIP39 seed generation**: 12 or 24 words from one of three sources you choose: camera (sensor noise from eight frames plus IMU noise on Waveshare, mixed with timing jitter via SHA-256, refused if the scene is too dark or still), dice rolls (manual entry), or touch (your own taps and their timing). The hardware RNG is not a seed source; it feeds nonces and salts and is health-checked on every draw
- **BIP32 HD key derivation**: `m/44'/111111'/0'` for single-sig, `m/45'/111111'/0'/<cosigner>` for multisig
- **BIP39 passphrase (25th word)**: optional passphrase creates a hidden wallet; decoy wallet without it
- **BIP85 child mnemonics**: derive independent child wallets from a master seed
- **Schnorr signing**: native Kaspa transaction signing (secp256k1)
- **PSKB/KSPT support**: scan, parse, sign, and export Partially Signed Kaspa Binary transactions via QR
- **Message signing**: sign arbitrary messages with address keys (type or load from SD)
- **Multisig**: M-of-N 45' multisig, the Kaspa standard scheme: sorted cosigners, descriptor backup, change verification, co-signing between devices via QR. First air-gapped multisig on Kaspa mainnet. See [Multisig](#multisig)
- **Multi-seed management**: store and switch between up to 16 seed slots in RAM (never persisted)
- **Steganographic backup**: hide encrypted seeds inside ordinary JPEG photos
- **Encrypted SD backup**: seeds, xprvs, raw keys, multisig descriptors and unsigned KSPTs can all be saved to MicroSD as AES-256-GCM containers, one format, purpose-bound key, per-file salt and nonce
- **Boot verification**: firmware hash + Schnorr signature and cryptographic known-answer tests at every boot, enforced in `production` builds; ROM Secure Boot V2 (RSA-3072) via eFuse
- **QR scanner**: built-in camera with rqrr decoder, V1 to V13 (Reed-Solomon verified, single-pass) for PSKBs, SeedQR import, and pubkey exchange
- **CompactSeedQR**: SeedSigner-compatible compact seed backup with grid view for manual card filling
- **KRC-20 token detection**: recognizes KRC-20 token transactions during review
- **Covenant signing**: reviews and signs covenant-bound transactions (KSPT v4 with covenant binding). The device shows every input and output, the payload hash and the covenant id when present, and verifies the redeem script against the P2SH commitment before signing
- **kpub/xprv export**: account-level public key export for watch-only wallets, encrypted xprv via SD
- **Reproducible builds**: Docker-based, so a binary can be rebuilt from source and compared

## Verify First: Reproducible Builds

Before anything else: verify that the firmware you flash matches the source code, bit for bit. This is the most important step. Requires Docker.

```bash
# Build toolchain base image (once)
docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v3 .

# Build firmware (both platforms)
docker build --platform linux/amd64 -t kassigner-build .

# Verify hashes
docker run --rm kassigner-build
```

See [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) for details.

## Steganographic Backup: A beautiful way

KasSigner's steganographic backup hides your seed inside an ordinary JPEG photograph. Three layers of protection make this fundamentally different from a plaintext backup:

**Layer 1. Steganography.** The encrypted seed is hidden inside an ordinary JPEG. The image looks completely ordinary. Nobody knows which file matters. Not a safe, not a metal plate, just a photo among thousands. Two carriers are available, chosen at export:

- **Descriptor**: the payload lives in the photo's EXIF metadata. Survives re-saving the image; destroyed if anything strips metadata, which messaging apps and most social platforms do routinely.
- **Picture**: the payload lives in the image's own compressed data. Ignores metadata stripping entirely; destroyed if the photo is re-compressed.

They fail on opposite operations. Run the export twice to write both; on import the device tries both and reports which one carried the backup.

**Layer 2. Encryption.** The seed is encrypted with AES-256-GCM using a password you choose, and that password is written into the photo's caption field, where it reads as an ordinary description. This is deliberate: it means the payload is opaque bytes rather than anything recognisable, and it means you never have to remember a second secret. It is not what keeps an attacker out. Someone who has the file and knows the scheme has the password too. Layers 1 and 3 do that work.

**Layer 3. BIP39 passphrase (25th word).** Even if someone decrypts the 24 words, the real wallet needs the passphrase as well. It is never stored on the device, in the photo or in any backup the device writes. The decrypted seed without it leads to a decoy wallet with trivial funds.

See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the complete steganographic backup system design.

## Covenants++

KasSee builds programmable covenant transactions; KasSigner reviews and signs them air-gapped; KasSee broadcasts. The same build, sign offline, broadcast flow, now for covenants on Kaspa mainnet since the Toccata upgrade (script introspection, `OP_CAT`, `OP_ZK_PRECOMPILE`).

- **Piggy Bank**: save toward a goal or deadline; break it open to withdraw
- **Time-Locked Savings**: lock funds until a date; no early access, not even by you
- **Dead Man's Switch**: heir inherits after inactivity; a heartbeat resets the timer
- **Allowance**: a beneficiary withdraws up to a cap, with a cooldown between withdrawals
- **Spending Limit**: a per-withdrawal cap with cooldown, across the whole balance
- **Merkle Whitelist**: spend only to an approved set, proven with a Merkle proof (`OP_CAT`)
- **Direct Channel**: payment channel with arbiter dispute resolution
- **Oracle**: release on an oracle attestation
- **PayJoin**: anonymous payment covenant
- **Commit-Reveal**: MEV-resistant inscriptions
- **Private Swap**: atomic swap via adaptor signatures: no preimage, no on-chain link
- **ZK Price Oracle**: live KAS/USD from Pyth + Wormhole, proven on-chain with a zero-knowledge proof

The signer verifies the covenant redeem script against the P2SH commitment being spent and signs the matching input. It shows every input and output, the payload hash and the covenant id on-device before you approve; the covenant address you verified when it was created is the anchor.

## Multisig

KasSigner implements the Kaspa 45' multisig scheme, written up in [KIP: Multisig Wallet Conventions for Kaspa](https://github.com/kaspanet/kips/pull/39/commits/ec5db96): cosigners derive at `m/45'/111111'/0'/<cosigner>/<chain>/<index>`, keys are sorted so every implementation computes the same address, chain 1 is change.

- **Create**: scan each cosigner's multisig kpub, choose M-of-N; the device shows the address and the descriptor as a QR and can save the descriptor to SD, plain or encrypted
- **Back up seed and descriptor**: the descriptor is a second secret. A seed alone cannot find or spend multisig funds
- **Sign**: scan the PSKB from KasSee or another coordinator, review, sign, hand the QR to the next cosigner or back to KasSee
- **Change verification**: change claimed by the transaction is checked against the loaded descriptor. Verified is shown in teal, unverifiable in orange with a `?`, and a claim the descriptor contradicts is marked FORGED in red and refused

Multisig wallets created before 45' used 44' HD keys (`multi_hd` descriptors); they still load and spend. New wallets are 45' only.

## Wallet Slot Types

KasSigner stores wallets in up to 16 RAM slots (never persisted to flash). Each slot can hold:

**Mnemonic (12 or 24 words)**: full BIP39 seed. Can derive unlimited addresses, sign transactions, export kpub/xprv, generate BIP85 children, create SeedQR backups. This is the most capable slot type.

**XPrv (extended private key)**: account-level key with chain code. Can derive all addresses and sign transactions, but cannot generate BIP85 children or export SeedQR (no mnemonic words). Imported from SD or QR.

**Raw private key**: a single 32-byte secp256k1 scalar. Controls exactly one address. Imported via hex keypad.


## Supported Hardware

KasSigner runs on two ESP32-S3 platforms:

| | Waveshare ESP32-S3-Touch-LCD-2 | M5Stack CoreS3 Lite |
|---|---|---|
| **Status** | Fully functional | Fully functional |
| **MCU** | ESP32-S3 dual-core 240MHz | ESP32-S3 dual-core 240MHz |
| **Display** | ST7789T3 320×240 SPI | ILI9342C 320×240 SPI |
| **Camera** | OV2640 / OV5640 DVP (auto-detect) | GC0308 QVGA DVP |
| **Touch** | CST816D capacitive I2C | FT6336U capacitive I2C |
| **SD Card** | SDHOST native 1-bit mode | Bitbang SPI |
| **Audio** | none | AW88298 I2S speaker |
| **PMU** | none (backlight PWM via LEDC) | AXP2101 + AW9523B |
| **PSRAM** | 8 MB octal | 8 MB quad |

A community 3D-printable case for the Waveshare board (snap-fit, LiPo 602030
cradle, USB-C access) is included under [`hardware/case-waveshare/`](hardware/case-waveshare/)
design by Sandmann21 (GPL), see the folder README for attribution.

## Building

### Prerequisites

- Rust with the Xtensa ESP32-S3 target (`espup install`)
- [espflash](https://github.com/esp-rs/espflash) for flashing
- USB-C data cable (not charge-only)

Run the setup checker to verify your environment:

```bash
cd tools
cargo run --bin kassigner-setup
```

### Quick start

```bash
git clone https://github.com/InKasWeRust/KasSigner.git
cd KasSigner/bootloader

# Waveshare ESP32-S3-Touch-LCD-2 (default: auto-detects OV2640/OV5640)
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release

# M5Stack CoreS3 Lite
cargo run --release --no-default-features --features m5stack
```

### Flash a pre-built release binary

Download from [Releases](https://github.com/InKasWeRust/KasSigner/releases), verify the SHA-256 hash, then flash. Use the image matching your board: `waveshare`, `waveshare-af` (for the autofocus camera module, which is mounted flipped and needs an orientation correction), or `m5stack`. The `-full` images include the bootloader and partition table and go at `0x0`; the app-only images go at `0x10000`.

```bash
pip3 install esptool
python3 -m esptool --port /dev/cu.usbmodem* --baud 460800 \
  write_flash 0x0 kassigner-waveshare-full.bin
```

**Released binaries close the USB port a second or two after boot.** This is intentional: they are production builds, and the firmware gates the USB Serial/JTAG peripheral once verification completes. They also print nothing over serial. A dead port and a silent log after flashing a release are the device working correctly, not a failed flash.

To reflash afterwards, put the board in download mode first: unplug USB, hold the BOOT button (the reset button on M5Stack CoreS3 Lite), plug USB back in, then release. See [docs/BUILD_FLASH_GUIDE.md](docs/BUILD_FLASH_GUIDE.md).

### Feature flags

| Flag | Purpose |
|------|---------|
| `af` | Load the OV5640 autofocus firmware |
| `boot-kats-full` | Run the extended crypto known-answer tests at boot |
| `e12-capture` | Raw seed-path camera bytes to SD, for entropy analysis |
| `icon-browser` | Developer icon gallery instead of the normal UI |
| `imu-dump` | Raw gyro samples over serial |
| `m5stack` | M5Stack CoreS3 Lite |
| `mirror` | Live display mirror. Streams screen to Mac/PC via serial |
| `ov2640-wide` | OV2640 wide-angle camera (Waveshare) |
| `ov5640-af` | OV5640 with autofocus (Waveshare) |
| `production` | Silent boot + strict firmware verification |
| `rng-probe` | Raw entropy-source sampling over serial |
| `screenshot` | Raw display frame capture over serial (`mirror` builds on it) |
| `sentinel-scan` | Stack-residue scan for a known test key |
| `sha-bench` | SHA path benchmark |
| `silent` | Suppress all serial output |
| `skip-tests` | Skip the boot self-tests and crypto known-answer tests |
| `test-psram` | Include the PSRAM check in the boot self-tests |
| `verbose-boot` | Extra boot diagnostics on UART |
| `waveshare` | Waveshare ESP32-S3-Touch-LCD-2 (default) |
| `wdev-capture` | Raw hardware RNG words to SD, for entropy analysis |

Development and measurement tools (`e12-capture`, `icon-browser`, `imu-dump`,
`mirror`, `rng-probe`, `screenshot`, `sentinel-scan`, `sha-bench`, `skip-tests`,
`verbose-boot`, `wdev-capture`) do not compile into a `production` build.


## KasSee: Watch-Only Companion Wallet

KasSee is a browser-based watch-only wallet that pairs with KasSigner. It imports your kpub (extended public key), derives all receive and change addresses, tracks UTXOs via a Kaspa node, builds unsigned transactions, and broadcasts signed ones. It never sees your private keys.

Pure Rust compiled to WebAssembly. Zero install. No backend. Runs entirely in your browser.

### Using KasSee

Visit [kassigner.org](https://kassigner.org), or serve `kassee/web/` locally (see Building KasSee from source below). It must be served over HTTP, not opened as a file.

KasSee connects to a public Kaspa node automatically. To use your own node, open Settings and enter your WebSocket URL (`wss://` or `ws://`).

### Features

- **Import kpub**: scan QR or paste the extended public key exported from KasSigner
- **Dashboard**: live balance, UTXO count, funded addresses
- **Send**: build unsigned KSPT transactions with fee estimation (low / normal / priority)
- **Send Max**: sweep all UTXOs to a single destination
- **UTXO selection**: manually select up to 32 UTXOs when sending, the signer's input limit (8 outputs)
- **Receive**: display next unused receive address with QR code (auto-skips funded and used addresses)
- **Address reuse prevention**: funded addresses show an orange badge, used (spent-empty) addresses a red one; explorer links on every address
- **Broadcast**: scan signed QR from KasSigner and submit to the network
- **Dual format support**: handles both PSKT/PSKB (Kaspa standard) and KSPT (KasSigner compact transport)
- **UTXO explorer**: view all UTXOs with selectable checkboxes for consolidation
- **UTXO consolidation**: select up to 32 UTXOs and merge them into a single output; repeat in batches
- **Address list**: all derived addresses with funded/used badges, explorer links, tap-to-verify and long-press-to-copy
- **Address verification**: display address QR + derivation path for on-device verification
- **Multisig**: import a 45' descriptor, watch the wallet, build spends across several addresses (PSKT/PSKB), relay between co-signers, broadcast fully signed transactions
- **Covenants**: build, fund, and spend the covenant suite (see Covenants++ above)
- **Stealth payments**: receive without linking payments to your public address (dual-key ECDH stealth addresses)
- **ZK price oracle**: on-chain KAS/USD (Pyth + Wormhole), zero-knowledge proven
- **Token display**: KRC-20 token balances, KRC-721 NFT listings, KNS domain names
- **Custom node**: connect to your own Kaspa node via Settings
- **Camera scanner**: scan QR codes directly from the browser (kpub, signed TX, descriptors)
- **Animated QR**: multi-frame QR display with pause/play control and frame indicator
- **Address history**: optional used-address detection via self-hosted kaspa-rest-server
- **Donation**: tap the KasSigner logo to see the project's donation address or prefill a send
- **PWA**: installable as a progressive web app on mobile

### Building KasSee from source

KasSee ships with pre-built WASM in `kassee/web/pkg/`: it works out of the box. To rebuild from source:

```bash
cd kassee

# Prerequisites (once)
cargo install wasm-pack
rustup target add wasm32-unknown-unknown --toolchain stable

# Build
RUSTUP_TOOLCHAIN=stable ./build.sh
```

KasSee must be served over HTTP, not opened as a file:

```bash
cd web && python3 -m http.server 8080
# Open http://localhost:8080
```

### Safety features

- **Custom node connection**: connect to your own Kaspa node via Settings
- **Public node resolver**: auto-discovers healthy public nodes when no custom node is set
- **Fee estimation**: queries node for current feerate with low / normal / priority levels
- **Storage mass awareness (KIP-9)**: no fixed minimum; storage mass depends on output size relative to inputs. KasSee warns before creating a change output below 0.1 KAS
- **WebSocket retry**: automatic reconnection on connection drops
- **Animated QR frames**: balanced frame splitting with indicator for reliable scanning

## What KasSigner Is

- An **offline signing device**: generates keys, signs transactions, exports via QR
- A **seed generator**: creates BIP39 mnemonics from hardware entropy or dice rolls
- A **steganographic backup tool**: hides encrypted seeds inside ordinary JPEG photos
- **Stateless**: all key material lives in RAM and is destroyed on power-off
- **Open source**: 100% Rust, every line auditable, reproducible Docker builds

## What KasSigner Is NOT

- **NOT a hardware wallet, and not a replacement for one**: it has no secure element, no tamper detection and no persistent key storage. Hardware wallets have dedicated security chips designed to resist physical attacks; KasSigner runs on a consumer ESP32-S3 microcontroller and does not.
- **NOT audited by a professional security firm**: the codebase has been through several security reviews and every finding was checked against the source (see [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md)). That is not the same as a paid engagement with an independent firm. The code is open for community review.
- **NOT resistant to physical attacks**: an attacker with physical access and lab equipment (decapping, voltage glitching) may be able to extract secrets from the ESP32-S3 while it is powered on.
- **NOT a place to store keys long-term**: the device wipes everything on power-off, wipes all loaded seeds after four minutes idle, and has a hold-to-confirm manual wipe. Your backup (seed words, stego JPEG, SD card) is your permanent storage, not the device.

## Security

Eight independent layers: air-gap, volatile keys, hardware Secure Boot, software firmware verification, Rust memory safety, encrypted backup, steganographic hiding and the BIP39 passphrase, plus reproducible builds and cryptographic known-answer tests at every boot. The model, the primitives and what the device does not protect against are in [SECURITY.md](SECURITY.md).

**A kpub is public, and that has a privacy cost worth understanding.** An account-level extended public key is exported precisely so a watch-only wallet can use it, so KasSigner writes it to SD and shows it as a QR without encryption. That is the feature, not an oversight: encrypting it would defeat what it is for. But a kpub derives every receive and change address for that account, so anyone holding it can see your entire balance and transaction history for that wallet, forever. It cannot spend, and it cannot be turned back into a private key. Treat an exported kpub like a bank statement rather than like a password: losing it costs privacy, not funds. If that matters for a particular wallet, export the kpub to a card you keep, not one you leave in a laptop, and use a separate account for anything you want unlinked.

## Documentation

- [docs/KasSigner_User_Guide.pdf](docs/KasSigner_User_Guide.pdf): complete user guide 
- [docs/KasSigner_Quick_Start_Guide.pdf](docs/KasSigner_Quick_Start_Guide.pdf): quick start 
- [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf): security architecture
- [docs/KasSee_User_Guide.pdf](docs/KasSee_User_Guide.pdf): KasSee Web companion wallet guide
- [docs/KasSigner_Kassee_Covenants_Stealth_Guide.pdf](docs/KasSigner_Kassee_Covenants_Stealth_Guide.pdf): covenants and stealth payments guide
- [docs/KasSigner_Seed_Cards.pdf](docs/KasSigner_Seed_Cards.pdf): printable seed backup cards
- [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md): JPEG EXIF steganographic backup system
- [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md): eFuse secure boot procedure (irreversible!)
- [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md): verify builds with Docker
- [docs/BUILD_FLASH_GUIDE.md](docs/BUILD_FLASH_GUIDE.md): build, flash and recover a board
- [docs/ENTROPY.md](docs/ENTROPY.md): entropy sources, what was measured and what is only checked
- [core/README.md](core/README.md): the security-critical code as a host-testable crate, `cargo test` with no hardware
- [SECURITY.md](SECURITY.md): security model, threat analysis, responsible disclosure
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): community standards
- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute, code standards
- [CHANGELOG.md](CHANGELOG.md): version history

## Hardware References

KasSigner runs on the Waveshare ESP32-S3-Touch-LCD-2 and M5Stack CoreS3 Lite. These are the datasheets and reference manuals for the components used:

- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf): register-level peripheral documentation
- [ESP32-S3 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf): pinout, electrical characteristics, memory map
- [Waveshare ESP32-S3-Touch-LCD-2 Wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2): board schematic, GPIO assignments, setup guide
- [OV2640 Datasheet](https://www.uctronics.com/download/cam_module/OV2640DS.pdf): camera sensor registers, DVP interface
- [ST7789 Datasheet](https://www.newhavendisplay.com/appnotes/datasheets/LCDs/ST7789V.pdf): display controller commands, SPI protocol, initialization sequence

## Cryptographic Notice

This software contains cryptographic functionality. Export, import, or use may be subject to laws in your jurisdiction. All algorithms used are published, standardized, and open.

## Contributing

Contributions welcome, especially:

- **Security review** of `wallet/` and `crypto/` modules
- **QR scanning** improvements (edge cases with hand-drawn CompactSeedQR)
- **Hardware ports** to other ESP32-S3 boards
- **UI/UX** refinements and accessibility

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [SECURITY.md](SECURITY.md) before reporting security issues.

## License

[GNU General Public License v3.0](LICENSE)

## Disclaimer

**KasSigner is experimental software on consumer hardware with no secure element, and has not been audited by a professional security firm.** The authors are not responsible for any loss of funds. Always verify transactions on a trusted watch-only wallet before signing, and never use KasSigner to manage more than you can afford to lose.
