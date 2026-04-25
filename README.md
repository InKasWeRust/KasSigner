<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# KasSigner

**Air-gapped offline signing device for the Kaspa blockchain.**

> ⚠️ **IMPORTANT: KasSigner is an EXPERIMENTAL offline signing device. It is NOT a hardware wallet. It has NO secure element and NO persistent storage — all keys are wiped on power-off. This software has NOT been professionally audited. Do NOT use KasSigner to manage funds you cannot afford to lose.**

KasSigner is an open-source signing device built on ESP32-S3. It generates private keys offline, signs transactions via QR code exchange, and never connects to any network. All key material lives in RAM only and is destroyed when the device powers off.

100% Rust. Bare-metal `no_std`. No operating system. No vendor libraries in the signing path.

> **This project is under active development.** It has not yet undergone a formal security audit. Do not store significant funds until the codebase has been independently reviewed.

## Features

- **Fully air-gapped** — no WiFi, Bluetooth, or USB data. All I/O via QR codes, touchscreen, and SD card
- **No persistent storage** — all keys live in RAM only, wiped on every power-off
- **BIP39 seed generation** — 12 or 24 words from camera frame entropy + eFuse UID + SYSTIMER + timing jitter (mixed via SHA-256), or manual dice rolls
- **BIP32 HD key derivation** — Kaspa path `m/44'/111111'/0'`
- **BIP39 passphrase (25th word)** — optional passphrase creates a hidden wallet; decoy wallet without it
- **BIP85 child mnemonics** — derive independent child wallets from a master seed
- **Schnorr signing** — native Kaspa transaction signing (secp256k1)
- **PSKB/KSPT support** — scan, parse, sign, and export Partially Signed Kaspa Binary transactions via QR
- **Message signing** — sign arbitrary messages with address keys (type or load from SD)
- **Multisig** — M-of-N P2SH multisig: create addresses, co-sign between devices via QR, broadcast. First air-gapped multisig on Kaspa mainnet.
- **Multi-seed management** — store and switch between up to 16 seed slots in RAM (never persisted)
- **Steganographic backup** — hide encrypted seeds inside ordinary JPEG photos on SD card
- **Encrypted SD backup** — AES-256-GCM encrypted seed backup to MicroSD
- **Secure boot** — firmware hash + Schnorr signature verified at every boot
- **QR scanner** — built-in camera with rqrr V1–V40 decoder (Reed-Solomon verified, single-pass) for PSKBs, SeedQR import, and pubkey exchange
- **CompactSeedQR** — SeedSigner-compatible compact seed backup with grid view for manual card filling
- **KRC-20 token detection** — recognizes KRC-20 token transactions during review
- **kpub/xprv export** — account-level public key export for watch-only wallets, encrypted xprv via SD
- **Reproducible builds** — Docker-based, bit-identical binaries on any platform

## Verify First — Reproducible Builds

Before anything else: verify that the firmware you flash matches the source code. This is the most important step.

Verify that a binary matches the source — bit for bit. Requires Docker.

```bash
# Build toolchain base image (once)
docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v2 .

# Build firmware (both platforms)
docker build --platform linux/amd64 -t kassigner-build .

# Verify hashes
docker run --rm kassigner-build
```

See [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) for details.


## Steganographic Backup — A beautiful way

KasSigner's steganographic backup hides your seed inside an ordinary JPEG photograph. Three layers of protection make this fundamentally different from a plaintext backup:

**Layer 1 — Steganography.** The encrypted seed is stored in JPEG EXIF metadata fields. The image looks completely ordinary. Nobody knows which file matters — not a safe, not a metal plate, just a photo among thousands.

**Layer 2 — Encryption.** The seed is encrypted with AES-256-GCM using a password you choose, stored as the EXIF ImageDescription (looks like a photo caption). Even with the file, an attacker needs your password to decrypt.

**Layer 3 — BIP39 passphrase (25th word).** Even if someone decrypts the 24 words, the real wallet lives behind a passphrase that exists only in your memory — never written, never stored. The decrypted seed without it leads to a decoy wallet with trivial funds.

The password (ImageDescription) is the key. The 25th word is the lock. Neither is stored on the device.

See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the complete steganographic backup system design.

## Wallet Slot Types

KasSigner stores wallets in up to 16 RAM slots (never persisted to flash). Each slot can hold:

**Mnemonic (12 or 24 words)** — full BIP39 seed. Can derive unlimited addresses, sign transactions, export kpub/xprv, generate BIP85 children, create SeedQR backups. This is the most capable slot type.

**XPrv (extended private key)** — account-level key with chain code. Can derive all addresses and sign transactions, but cannot generate BIP85 children or export SeedQR (no mnemonic words). Imported from SD or QR.

**Raw private key** — a single 32-byte secp256k1 scalar. Controls exactly one address. Imported via hex keypad. Compatible with KasWare-style key exports.


## Supported Hardware

KasSigner runs on two ESP32-S3 platforms:

| | Waveshare ESP32-S3-Touch-LCD-2 | M5Stack CoreS3 / CoreS3 Lite |
|---|---|---|
| **Status** | Secure Boot ready | Fully functional |
| **MCU** | ESP32-S3 dual-core 240MHz | ESP32-S3 dual-core 240MHz |
| **Display** | ST7789T3 320×240 SPI | ILI9342C 320×240 SPI |
| **Camera** | OV2640 / OV5640 DVP (auto-detect) | GC0308 QVGA DVP |
| **Touch** | CST816D capacitive I2C | FT6336U capacitive I2C |
| **SD Card** | SDHOST native 1-bit mode | Bitbang SPI |
| **Audio** | — | AW88298 I2S speaker |
| **PMU** | — | AXP2101 + AW9523B |
| **PSRAM** | 8MB octal | 8MB octal |

### Pin Map (Waveshare)

```
Camera DVP:  XCLK=8  PCLK=9  VSYNC=6  HREF=4  D0-D7=12,13,15,11,14,10,7,2
Camera I2C1: SDA=21  SCL=16  PWDN=17
Display SPI: MOSI=38 SCLK=39 CS=45    DC=42   RST=0  BL=1 (LEDC PWM)
Touch I2C0:  SDA=48  SCL=47  INT=46
SD SDHOST:   CLK=39  CMD=38  D0=40
Battery:     ADC=GPIO5
```

### Pin Map (M5Stack CoreS3)

```
Camera DVP:  XCLK=2 (LEDC)  PCLK=45  VSYNC=46  HREF=38
             D0=39  D1=40  D2=41  D3=42  D4=15  D5=16  D6=48  D7=47
Camera I2C:  SDA=12  SCL=11  (shared bus with touch + PMU)
Display SPI: MOSI=37 SCLK=36 CS=3   DC/MISO=35  (shared bus with SD)
Touch I2C:   SDA=12  SCL=11  (shared bus)
SD bitbang:  SCK=36  MOSI=37  MISO=35  CS=4  (shared SPI with LCD)
PMU:         AXP2101 (0x34) + AW9523B (0x58) on I2C0
Speaker:     AW88298 via I2S1 (DMA)
```

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

# Waveshare ESP32-S3-Touch-LCD-2 (default, OV5640)
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features skip-tests

# Waveshare (OV2640 wide-angle camera)
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features skip-tests,ov2640-wide

# M5Stack CoreS3 / CoreS3 Lite
cargo run --release --no-default-features --features m5stack
```

### Flash a pre-built release binary

Download from [Releases](https://github.com/InKasWeRust/KasSigner/releases), verify the SHA-256 hash, then flash:

```bash
pip3 install esptool
python3 -m esptool --port /dev/cu.usbmodem* --baud 460800 \
  write_flash 0x10000 kassigner-waveshare.bin
```

### One-step installer (macOS only)

For macOS users, the install script handles everything — toolchain installation, build, and flash:

```bash
bash Install.sh
```

The script asks permission at every step (Y/N). It detects your environment, installs missing tools (Xcode CLI Tools, Rust, ESP32 toolchain, espflash), builds from source, and flashes the device. Linux and Windows users should follow the manual build steps above.

### Feature flags

| Flag | Purpose |
|------|---------|
| `waveshare` | Waveshare ESP32-S3-Touch-LCD-2 (default) |
| `m5stack` | M5Stack CoreS3 / CoreS3 Lite |
| `skip-tests` | Skip boot-time hardware self-tests (dev builds) |
| `production` | Silent boot + strict firmware verification |
| `verbose-boot` | Extra boot diagnostics on UART |
| `mirror` | Live display mirror — streams screen to Mac/PC via serial |

### Live display mirror (for presentations)

Stream the device screen to a Mac/PC window in real-time. Requires two terminals.

```bash
# Terminal 1: Build and flash firmware with mirror enabled
cd bootloader
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features waveshare,mirror,skip-tests

# Terminal 2: Run the mirror viewer
cd tools
cargo run --release --bin kassigner-mirror -- /dev/cu.usbmodem21201
```

## KasSee — Watch-Only Companion Wallet

KasSee is a browser-based watch-only wallet that pairs with KasSigner. It imports your kpub (extended public key), derives all receive and change addresses, tracks UTXOs via a Kaspa node, builds unsigned transactions, and broadcasts signed ones. It never sees your private keys.

Pure Rust compiled to WebAssembly. Zero install. No backend. Runs entirely in your browser.

### Using KasSee

Open `kassee/web/index.html` in any modern browser, or visit [kassigner.org](https://kassigner.org).

KasSee connects to a public Kaspa node automatically. To use your own node, open Settings and enter your WebSocket URL (`wss://` or `ws://`).

### Features

- **Import kpub** — scan QR or paste the extended public key exported from KasSigner
- **Dashboard** — live balance, UTXO count, funded addresses
- **Send** — build unsigned KSPT transactions with fee estimation (low / normal / priority)
- **Send Max** — sweep all UTXOs to a single destination
- **UTXO selection** — manually select up to 8 UTXOs when sending to stay within the signer's input limit
- **Receive** — display next unused receive address with QR code (auto-skips funded and used addresses)
- **Address reuse prevention** — funded addresses show an orange badge, spent addresses show gray; explorer links on every address
- **Broadcast** — scan signed QR from KasSigner and submit to the network
- **Dual format support** — handles both PSKT/PSKB (Kaspa standard) and KSPT (KasSigner compact transport)
- **UTXO explorer** — view all UTXOs with selectable checkboxes for consolidation
- **UTXO consolidation** — select up to 8 UTXOs and merge them into a single output; repeat in batches
- **Address list** — all derived addresses with funded/used badges, explorer links, tap-to-verify and long-press-to-copy
- **Address verification** — display address QR + derivation path for on-device verification
- **Multisig** — create P2SH multisig addresses, build multisig spend transactions (PSKT/PSKB), relay between co-signers, broadcast fully signed transactions
- **Token display** — KRC-20 token balances, KRC-721 NFT listings, KNS domain names
- **Custom node** — connect to your own Kaspa node via Settings
- **Camera scanner** — scan QR codes directly from the browser (kpub, signed TX, descriptors)
- **Animated QR** — multi-frame QR display with pause/play control and frame indicator
- **Address history** — optional used-address detection via self-hosted kaspa-rest-server
- **Donation** — tap the KasSigner logo to see the project's donation address or prefill a send
- **PWA** — installable as a progressive web app on mobile

### Building KasSee from source

KasSee ships with pre-built WASM in `kassee/web/pkg/` — it works out of the box. To rebuild from source:

```bash
cd kassee

# Prerequisites (once)
cargo install wasm-pack
rustup target add wasm32-unknown-unknown --toolchain stable

# Build
RUSTUP_TOOLCHAIN=stable ./build.sh
```

Then open `kassee/web/index.html` in a browser or serve locally:

```bash
cd web && python3 -m http.server 8080
# Open http://localhost:8080
```

### Air-gapped signing flow

```
KasSee (browser)                KasSigner (device)
────────────────                ──────────────────
1. Build unsigned TX (KSPT)
2. Display as animated QR ─────→ 3. Scan QR
                                  4. Review TX on screen
                                  5. Sign with private key
6. Scan signed QR ←────────────── 7. Display signed QR
8. Broadcast to network
```

### Multisig co-signing flow

```
KasSee (browser)          Device A              Device B
────────────────          ────────              ────────
1. Build PSKT/PSKB
2. Display QR ──────────→ 3. Scan, review
                          4. Sign (1/2)
                          5. Show partial QR ──→ 6. Scan from A's screen
                                                 7. Sign (2/2)
                                                 8. Show fully signed QR
9. Scan signed QR
10. Broadcast to network
```

### Safety features

- **Custom node connection** — connect to your own Kaspa node via Settings
- **Public node resolver** — auto-discovers healthy public nodes when no custom node is set
- **Fee estimation** — queries node for current feerate with low / normal / priority levels
- **Storage mass awareness** — warns for outputs below 0.2 KAS (KIP-9/Crescendo)
- **WebSocket retry** — automatic reconnection on connection drops
- **Animated QR frames** — balanced frame splitting with indicator for reliable scanning
- **Sorted multisig keys** — deterministic P2SH addresses regardless of kpub input order

## What KasSigner Is

- An **offline signing device** — generates keys, signs transactions, exports via QR
- A **seed generator** — creates BIP39 mnemonics from hardware entropy or dice rolls
- A **steganographic backup tool** — hides encrypted seeds inside ordinary JPEG photos
- **Stateless** — all key material lives in RAM and is destroyed on power-off
- **Open source** — 100% Rust, every line auditable, reproducible Docker builds

## What KasSigner Is NOT

- **NOT a hardware wallet** — it has no secure element, no tamper detection, no persistent key storage. It runs on a consumer ESP32-S3 microcontroller.
- **NOT a replacement for hardware wallets** — hardware wallets have dedicated security chips designed to resist physical attacks. KasSigner does not.
- **NOT professionally audited** — the codebase has undergone internal security review (see [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf)) but has not been reviewed by an independent professional security firm. Known findings are documented and tracked. The code is open for community review.
- **NOT resistant to physical attacks** — an attacker with physical access and lab equipment (JTAG probes, voltage glitching, flash readers) may be able to extract secrets from the ESP32-S3 while it is powered on.
- **NOT a place to store keys long-term** — the device wipes everything on power-off. Your backup (seed words, stego JPEG, SD card) is your permanent storage, not the device.

## Security Architecture

### Air-gap enforcement

KasSigner has **no network stack**. The ESP32-S3's WiFi and Bluetooth radios are never initialized. The only data paths are:

- **QR codes** — camera input (scan PSKB / SeedQR / pubkeys) and display output (signed TX / addresses)
- **SD card** — encrypted backup/restore and steganographic operations
- **Touchscreen** — user input

### Key lifecycle

```
Entropy (camera noise + eFuse + timing / dice)
    ↓
BIP39 mnemonic (12 or 24 words)
    ↓
+ optional BIP39 passphrase (25th word, in user's memory only)
    ↓
PBKDF2-HMAC-SHA512 → 512-bit seed
    ↓
BIP32 master key → m/44'/111111'/0' (Kaspa account)
    ↓
Address keys derived on demand (index 0, 1, 2, ...)
```

Private keys are:

1. **Zeroized after use** — memory clearing after signing operations
2. **Never persisted** — all seed slots live in RAM only, lost on power-off
3. **Encrypted for SD backup** — AES-256-GCM with user passphrase

### Boot verification

Every boot:

1. Hardware self-tests (SRAM pattern, flash CRC, SHA-256 engine)
2. Firmware hash computed over the application segment
3. Hash compared to build-time embedded constant
4. Schnorr signature verified against developer public key

A tampered binary fails verification and halts boot.

### Cryptographic primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Seed generation | BIP39 mnemonic | BIP-0039 |
| Key derivation | BIP32 HD keys | BIP-0032 |
| Child mnemonics | BIP85 | BIP-0085 |
| Key stretching | PBKDF2-HMAC-SHA512 (2048 rounds) | RFC 8018 |
| Transaction signing | Schnorr (secp256k1) | Kaspa spec |
| Transaction hashing | Keyed Blake2b-256 | Kaspa consensus |
| Seed encryption (SD) | AES-256-GCM | NIST SP 800-38D |
| Seed encryption (stego) | AES-256-GCM via PBKDF2 | NIST / RFC 8018 |
| Hashing | SHA-256, HMAC-SHA512, Blake2b | FIPS 180-4, RFC 7693 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare | Side-channel mitigation |

### What KasSigner does NOT protect against

- **Lab-grade physical attacks** — JTAG probes, voltage glitching, or decapping the ESP32-S3 die. This is a limitation of consumer hardware.
- **Compromised build toolchain** — if your compiler is backdoored, the binary is untrustworthy. Always verify builds from source.
- **Social engineering** — if you reveal your seed or passphrase, no device can protect you.
- **Evil maid + no 25th word** — if someone physically accesses your stego backup AND knows your ImageDescription passphrase AND you didn't use a BIP39 25th word, they have your keys.

## Documentation

- [docs/KasSigner_User_Guide.pdf](docs/KasSigner_User_Guide.pdf) — complete user guide (38 pages)
- [docs/KasSigner_Quick_Start_Guide.pdf](docs/KasSigner_Quick_Start_Guide.pdf) — quick start (5 pages)
- [docs/KasSigner_Security_Architecture.pdf](docs/KasSigner_Security_Architecture.pdf) — security architecture
- [docs/KasSee_User_Guide.pdf](docs/KasSee_User_Guide.pdf) — KasSee Web companion wallet guide
- [docs/KasSigner_Seed_Cards.pdf](docs/KasSigner_Seed_Cards.pdf) — printable seed backup cards
- [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) — JPEG EXIF steganographic backup system
- [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) — eFuse secure boot procedure (irreversible!)
- [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) — verify builds with Docker
- [Constellation](https://kassigner.org/constellation/) — interactive key derivation & architecture explorer
- [SECURITY.md](SECURITY.md) — security model, threat analysis, responsible disclosure
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — community standards
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute, code standards
- [CHANGELOG.md](CHANGELOG.md) — version history

## Hardware References

KasSigner runs on the Waveshare ESP32-S3-Touch-LCD-2 and M5Stack CoreS3. These are the datasheets and reference manuals for the components used:

- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf) — register-level peripheral documentation
- [ESP32-S3 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf) — pinout, electrical characteristics, memory map
- [Waveshare ESP32-S3-Touch-LCD-2 Wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2) — board schematic, GPIO assignments, setup guide
- [OV2640 Datasheet](https://www.uctronics.com/download/cam_module/OV2640DS.pdf) — camera sensor registers, DVP interface
- [ST7789 Datasheet](https://www.newhavendisplay.com/appnotes/datasheets/LCDs/ST7789V.pdf) — display controller commands, SPI protocol, initialization sequence

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

**KasSigner is experimental software running on consumer hardware with no secure element. It has not been audited by a professional security firm.** The authors are not responsible for any loss of funds. KasSigner is an offline signing device, not a hardware wallet — all keys exist in RAM only and are destroyed on power-off. Always verify transactions on a trusted watch-only wallet before signing. Never use KasSigner to manage more cryptocurrency than you can afford to lose.
