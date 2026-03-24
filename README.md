# KasSigner

**Air-gapped hardware wallet for the Kaspa blockchain.**

KasSigner is an open-source signing device built on ESP32-S3. It generates private keys offline, signs transactions via QR code exchange, and never connects to any network. Your keys never leave the device.

> **This project is under active development.** It has not yet undergone a formal security audit. Do not store significant funds until the codebase has been independently reviewed.

## Features

- **Fully air-gapped** — no WiFi, Bluetooth, or USB data. All I/O via QR codes, touchscreen, and SD card
- **BIP39 seed generation** — 12 or 24 words from hardware TRNG or manual dice rolls (verifiable entropy)
- **BIP32 HD key derivation** — Kaspa path `m/44'/111111'/0'`
- **BIP39 passphrase (25th word)** — optional passphrase creates a hidden wallet; decoy wallet without it
- **BIP85 child mnemonics** — derive independent child wallets from a master seed
- **Schnorr signing** — native Kaspa transaction signing (secp256k1)
- **PSKT support** — scan, parse, sign, and export Partially Signed Kaspa Transactions
- **Message signing** — sign arbitrary messages with address keys (type or load from SD)
- **Multisig** — M-of-N address generation and co-signing with multiple seeds or scanned pubkeys
- **Multi-seed management** — store and switch between multiple seed slots in RAM (never persisted)
- **Steganographic backup** — hide encrypted seeds inside ordinary JPEG photos on SD card
- **Encrypted SD backup** — AES-256-GCM encrypted seed backup to MicroSD
- **Secure boot** — firmware hash + Schnorr signature verified at every boot
- **QR scanner** — built-in camera for scanning PSKTs, SeedQR import, and pubkey exchange
- **CompactSeedQR** — SeedSigner-compatible compact seed backup with grid view for manual card filling
- **KRC-20 token detection** — recognizes KRC-20 token transactions during review
- **kpub/xprv export** — account-level public key export for watch-only wallets, encrypted xprv via SD

## Steganographic Backup — The Key Innovation

KasSigner's steganographic backup hides your seed inside an ordinary JPEG photograph. Three layers of protection make this fundamentally different from a plaintext backup:

**Layer 1 — Steganography.** The encrypted seed is stored in JPEG EXIF metadata fields. The image looks completely ordinary. Nobody knows which file matters — not a safe, not a metal plate, just a photo among thousands.

**Layer 2 — Encryption.** The seed is encrypted with AES-256-GCM using a passphrase you choose, stored as the EXIF ImageDescription (looks like a photo caption). Even with the file, an attacker needs your passphrase to decrypt.

**Layer 3 — BIP39 passphrase (25th word).** Even if someone decrypts the 24 words, the real wallet lives behind a passphrase that exists only in your memory — never written, never stored. The decrypted seed without it leads to a decoy wallet with trivial funds.

The passphrase (ImageDescription) is the key. The 25th word is the lock. Neither is stored on the device.

See [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) for the complete steganographic backup system design.

## Wallet Slot Types

KasSigner stores wallets in 4 RAM slots (never persisted to flash). Each slot can hold:

**Mnemonic (12 or 24 words)** — full BIP39 seed. Can derive unlimited addresses, sign transactions, export kpub/xprv, generate BIP85 children, create SeedQR backups. This is the most capable slot type.

**XPrv (extended private key)** — account-level key with chain code. Can derive all addresses and sign transactions, but cannot generate BIP85 children or export SeedQR (no mnemonic words). Imported from SD or QR.

**Raw private key** — a single 32-byte secp256k1 scalar. Controls exactly one address. Imported via hex keypad. Compatible with KasWare-style key exports.

See [docs/KEY_DERIVATION.md](docs/KEY_DERIVATION.md) for the full derivation architecture.

## Supported Hardware

KasSigner runs on ESP32-S3 platforms. The Waveshare board is the primary target:

| | Waveshare ESP32-S3-Touch-LCD-2 | M5Stack CoreS3 |
|---|---|---|
| **Status** | Primary (active) | Legacy (feature-flagged) |
| **MCU** | ESP32-S3 dual-core 240MHz | ESP32-S3 dual-core 240MHz |
| **Display** | ST7789T3 320×240 SPI | ILI9342C 320×240 SPI |
| **Camera** | OV5640 5MP DVP (autofocus) | GC0308 QVGA DVP |
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

## Building

### Prerequisites

- Rust with the Xtensa ESP32-S3 target (`espup install`)
- [espflash](https://github.com/esp-rs/espflash) for flashing

### Quick start

```bash
git clone https://github.com/user/kassigner.git
cd kassigner/bootloader

# Development build (skip hardware self-tests for faster iteration)
cargo run --features skip-tests

# Release build
cargo build --release
```

### Signed production build

KasSigner verifies firmware integrity at boot using a Schnorr signature. The build system iterates compilation until the embedded hash converges:

```bash
# Generate a signing keypair (ONE TIME — back up the private key!)
cargo run --manifest-path tools/Cargo.toml --bin gen-keypair

# Build with hash convergence + signing
./tools/build_with_hash.sh --key dev_signing_key.bin

# Production build (enables silent mode + strict verification)
./tools/build_production.sh --key dev_signing_key.bin
```

### Feature flags

| Flag | Purpose |
|------|---------|
| `skip-tests` | Skip boot-time hardware self-tests (dev builds) |
| `production` | Silent boot + strict firmware verification |
| `verbose-boot` | Extra boot diagnostics on UART |
| `screenshot` | Enable screenshot capture to SD card |
| `icon-browser` | Enable icon browser debug screen |
| `cam-tune` | Camera tuning overlay |

## Project Structure

```
kassigner/
├── README.md
├── SECURITY.md
├── LICENSE
├── .gitignore
│
├── docs/
│   ├── STEGANOGRAPHY.md        JPEG EXIF steganographic backup
│   ├── KEY_DERIVATION.md       BIP32/39/85 derivation architecture
│   └── EFUSE_RUNBOOK.md        eFuse secure boot procedure (irreversible!)
│
├── tools/
│   ├── gen_hash.rs             Firmware hash + Schnorr signing
│   ├── gen_keypair.rs          Developer signing key generator
│   ├── convert_logo.rs         BMP → Rust logo data converter
│   ├── dump_header.rs          ESP-IDF binary header inspector
│   ├── build_with_hash.sh      Iterative hash convergence build
│   ├── build_production.sh     Production build wrapper
│   └── Cargo.toml              Tool dependencies
│
├── bootloader/
│   ├── Cargo.toml              Main project manifest
│   ├── Cargo.lock
│   ├── build.rs                Linker configuration
│   ├── .cargo/config.toml      Xtensa target + PSRAM config
│   └── src/
│       ├── main.rs             Entry point, HW init, main loop
│       ├── firmware_hash.rs    Build-generated hash + signature
│       │
│       ├── app/                Application state machine (~94 states)
│       │   ├── data.rs         AppData — all mutable runtime state
│       │   ├── input.rs        AppState enum, handler dispatch
│       │   ├── signing.rs      Key derivation + signing pipeline
│       │   └── boot_test.rs    Boot-time hardware validation
│       │
│       ├── handlers/           Touch event handlers (one per domain)
│       │   ├── menu.rs         Main menu, seeds menu, tools menu
│       │   ├── seed.rs         Seed management, BIP85, import/export
│       │   ├── tx.rs           Transaction review, confirm, multisig
│       │   ├── export.rs       Address display, QR/kpub/xprv export
│       │   ├── stego.rs        Steganography workflow (JPEG EXIF)
│       │   ├── sd.rs           SD backup/restore flows
│       │   ├── settings.rs     Display, audio, SD settings
│       │   └── camera_loop.rs  Non-blocking DMA capture + QR decode
│       │
│       ├── hw/                 Hardware abstraction layer
│       │   ├── board.rs        Pin assignments (change this to port)
│       │   ├── display.rs      ST7789T3 SPI driver + color palette
│       │   ├── camera.rs       OV5640 DVP via LCD_CAM + GDMA
│       │   ├── touch.rs        CST816D I2C + gesture tracking
│       │   ├── sdcard.rs       SDHOST native SD (1-bit, PLL clock)
│       │   ├── sd_backup.rs    AES-256-GCM encrypted backup codec
│       │   ├── sound.rs        Audio stubs (Waveshare has no speaker)
│       │   ├── battery.rs      Battery ADC via RTC SAR
│       │   ├── pmu.rs          Backlight PWM via LEDC
│       │   └── ov5640_af_fw.rs Autofocus MCU firmware blob
│       │
│       ├── ui/                 User interface
│       │   ├── screens.rs      All screen drawing functions
│       │   ├── redraw.rs       State → screen dispatch
│       │   ├── helpers.rs      Touch hit-test, validation
│       │   ├── keyboard.rs     On-screen keyboard (3 pages)
│       │   ├── pin_ui.rs       PIN entry keypad
│       │   ├── setup_wizard.rs Dice roll + word import wizards
│       │   ├── seed_manager.rs Multi-seed slot management
│       │   ├── prop_fonts.rs   Proportional fonts (Lato, Oswald, Rubik)
│       │   └── logo_data.rs    Boot splash logo bitmap
│       │
│       ├── qr/                 QR code engine (pure Rust, no crate)
│       │   ├── encoder.rs      QR generation V1–V6, byte mode
│       │   └── decoder.rs      Detection + Reed-Solomon (5-pass)
│       │
│       ├── wallet/             Cryptographic wallet (pure Rust, no-std)
│       │   ├── bip39.rs        Mnemonic generation + validation
│       │   ├── bip32.rs        HD key derivation (Kaspa path)
│       │   ├── bip85.rs        BIP85 child mnemonic derivation
│       │   ├── schnorr.rs      Schnorr signing (secp256k1)
│       │   ├── hmac.rs         HMAC-SHA512, PBKDF2
│       │   ├── address.rs      Kaspa address encoding (Bech32)
│       │   ├── pskt.rs         PSKT parse / sign / serialize
│       │   ├── sighash.rs      Transaction sighash computation
│       │   ├── transaction.rs  Transaction structures
│       │   ├── xpub.rs         Extended key (kpub/xprv) encoding
│       │   └── storage.rs      Encrypted key storage primitives
│       │
│       ├── features/           Feature modules
│       │   ├── stego.rs        JPEG EXIF stego codec + base64
│       │   ├── krc20.rs        KRC-20 token format detection
│       │   ├── verify.rs       Firmware hash + signature verify
│       │   ├── fw_update.rs    Firmware update parsing
│       │   ├── nvs.rs          Non-volatile storage interface
│       │   └── self_test.rs    Hardware self-test framework
│       │
│       └── crypto/             Low-level security primitives
│           ├── constant_time.rs  Constant-time comparison
│           ├── secure_zeroize.rs Memory zeroization
│           ├── secret_box.rs     XOR-masked secret containers
│           └── flow.rs           Flow integrity counters
```

## Security Architecture

### Air-gap enforcement

KasSigner has **no network stack**. The ESP32-S3's WiFi and Bluetooth radios are never initialized. The only data paths are:

- **QR codes** — camera input (scan PSKT / SeedQR / pubkeys) and display output (signed TX / addresses)
- **SD card** — encrypted backup/restore and steganographic operations
- **Touchscreen** — user input

### Key lifecycle

```
Entropy (TRNG / dice)
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

1. **XOR-masked in RAM** — never stored as plaintext (`crypto/secret_box.rs`)
2. **Zeroized after use** — compiler-proof memory clearing (`crypto/secure_zeroize.rs`)
3. **Never persisted** — all seed slots live in RAM only, lost on power-off
4. **Encrypted for SD backup** — AES-256-GCM with user passphrase

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
| Seed encryption (SD) | AES-256-GCM | NIST SP 800-38D |
| Seed encryption (stego) | AES-256-GCM via PBKDF2 | NIST / RFC 8018 |
| Hashing | SHA-256, HMAC-SHA512, BLAKE2b | FIPS 180-4, RFC 2104, RFC 7693 |
| Firmware verification | SHA-256 + Schnorr | Custom |
| Constant-time ops | Fixed-time compare, XOR masking | Side-channel mitigation |

### What KasSigner does NOT protect against

- **Lab-grade physical attacks** — JTAG probes, voltage glitching, or decapping the ESP32-S3 die. This is a limitation of consumer hardware.
- **Compromised build toolchain** — if your compiler is backdoored, the binary is untrustworthy. Always verify builds from source.
- **Social engineering** — if you reveal your seed or passphrase, no device can protect you.
- **Evil maid + no 25th word** — if someone physically accesses your stego backup AND knows your ImageDescription passphrase AND you didn't use a BIP39 25th word, they have your keys.

## Documentation

- [SECURITY.md](SECURITY.md) — security model, threat analysis, responsible disclosure
- [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) — JPEG EXIF steganographic backup system
- [docs/KEY_DERIVATION.md](docs/KEY_DERIVATION.md) — BIP32/39/85 derivation tree explained
- [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) — eFuse secure boot procedure (irreversible!)

## Cryptographic Notice

This software contains cryptographic functionality. Export, import, or use may be subject to laws in your jurisdiction. All algorithms used are published, standardized, and open.

## Contributing

Contributions welcome, especially:

- **Security review** of `wallet/` and `crypto/` modules
- **QR scanning** improvements (edge cases with hand-drawn CompactSeedQR)
- **Hardware ports** to other ESP32-S3 boards
- **UI/UX** refinements and accessibility

Please read [SECURITY.md](SECURITY.md) before reporting security issues.

## License

[MIT](LICENSE)

## Disclaimer

**KasSigner is experimental software. It has not been audited by a professional security firm.** The authors are not responsible for any loss of funds. Always verify transactions on a trusted watch-only wallet before signing. Never store more cryptocurrency than you can afford to lose on unaudited hardware.
