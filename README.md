# KasSigner

**Air-gapped offline signing device for the Kaspa blockchain.**

> ⚠️ **IMPORTANT: KasSigner is an EXPERIMENTAL offline signing device. It is NOT a hardware wallet. It has NO secure element and NO persistent storage — all keys are wiped on power-off. This software has NOT been professionally audited. Do NOT use KasSigner to manage funds you cannot afford to lose.**

KasSigner is an open-source signing device built on ESP32-S3. It generates private keys offline, signs transactions via QR code exchange, and never connects to any network. All key material lives in RAM only and is destroyed when the device powers off.

> **This project is under active development.** It has not yet undergone a formal security audit. Do not store significant funds until the codebase has been independently reviewed.

## Features

- **Fully air-gapped** — no WiFi, Bluetooth, or USB data. All I/O via QR codes, touchscreen, and SD card
- **No persistent storage** — all keys live in RAM only, wiped on every power-off
- **Live display mirror** — stream the device screen to a Mac/PC for presentations (`--features mirror`)
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

See [docs/KEY_DERIVATION.md](docs/KEY_DERIVATION.md) for the full derivation architecture.

## Supported Hardware

KasSigner runs on ESP32-S3 platforms. The Waveshare board is the primary target:

| | Waveshare ESP32-S3-Touch-LCD-2 | M5Stack CoreS3 / CoreS3 Lite |
|---|---|---|
| **Status** | Primary (Secure Boot ready) | Secondary (fully functional) |
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

Run the setup checker to verify your environment:

```bash
cd tools
cargo run --bin kassigner-setup
```

### Quick start

```bash
git clone https://github.com/InKasWeRust/KasSigner.git
cd KasSigner/bootloader

# Waveshare ESP32-S3-Touch-LCD-2 (default)
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release

# M5Stack CoreS3 / CoreS3 Lite
cargo run --release --no-default-features --features m5stack

# Development build (skip hardware self-tests for faster iteration)
cargo run --release --no-default-features --features m5stack,skip-tests
```

### Feature flags

| Flag | Purpose |
|------|---------|
| `waveshare` | Waveshare ESP32-S3-Touch-LCD-2 (default) |
| `m5stack` | M5Stack CoreS3 / CoreS3 Lite |
| `skip-tests` | Skip boot-time hardware self-tests (dev builds) |
| `production` | Silent boot + strict firmware verification |
| `verbose-boot` | Extra boot diagnostics on UART |
| `mirror` | Live display mirror — streams screen to Mac/PC via serial |
| `screenshot` | Shadow framebuffer (internal, implied by `mirror`) |
| `icon-browser` | Enable icon browser debug screen |

### Live display mirror (for presentations)

Stream the device screen to a Mac/PC window in real-time. Every screen change on the device appears on the computer — plug USB, run the tool, project to audience.

```bash
# Build firmware with mirror enabled
# Waveshare:
ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features waveshare,mirror,skip-tests
# M5Stack:
cargo build --release --no-default-features --features m5stack,mirror,skip-tests

# Flash (no monitor — mirror tool needs the serial port)
espflash flash target/xtensa-esp32s3-none-elf/release/kassigner-bootloader

# Run mirror tool (separate terminal)
cd tools
cargo run --release --bin kassigner-mirror -- /dev/cu.usbmodem21201

# Press reset on device — screen appears in window
```

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
│   ├── mirror.rs               Live display mirror (Mac/PC serial viewer)
│   ├── setup_check.rs          Build environment checker (cross-platform)
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
│       │   ├── mod.rs          Platform-gated module routing
│       │   ├── board.rs        Pin assignments (Waveshare only)
│       │   ├── lockdown.rs     Radio kill + JTAG disable (Waveshare only)
│       │   ├── display_ws.rs   ST7789T3 SPI driver (Waveshare)
│       │   ├── display_m5.rs   ILI9342C SPI driver (M5Stack)
│       │   ├── camera_ov5640.rs OV5640 DVP driver (Waveshare)
│       │   ├── camera_gc0308.rs GC0308 DVP driver (M5Stack)
│       │   ├── touch_cst816d.rs CST816D I2C + gestures (Waveshare)
│       │   ├── touch_ft6336u.rs FT6336U I2C (M5Stack)
│       │   ├── sdcard_ws.rs    SDHOST native SD (Waveshare)
│       │   ├── sdcard_m5.rs    Bitbang SPI SD (M5Stack)
│       │   ├── sd_backup.rs    AES-256-GCM encrypted backup codec
│       │   ├── sound_ws.rs     Audio stubs (Waveshare, no speaker)
│       │   ├── sound_m5.rs     AW88298 I2S speaker (M5Stack)
│       │   ├── battery_ws.rs   Battery ADC via RTC SAR (Waveshare)
│       │   ├── battery_m5.rs   AXP2101 battery gauge (M5Stack)
│       │   ├── pmu_ws.rs       Backlight PWM via LEDC (Waveshare)
│       │   ├── pmu_m5.rs       AXP2101 PMU + AW9523B IO (M5Stack)
│       │   ├── ov5640_af_fw.rs Autofocus MCU firmware blob
│       │   ├── icon_data.rs    Custom icon bitmaps (RGB565)
│       │   └── screenshot.rs   Screenshot capture (optional)
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
│       │   ├── decoder_ws.rs   Waveshare decoder (5-pass voting)
│       │   └── decoder_m5.rs   M5Stack decoder (3-consecutive match)
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
│       │   └── self_test.rs    Hardware self-test framework
│       │
│       └── crypto/             Low-level security primitives
│           ├── constant_time.rs  Constant-time comparison
│           ├── secure_zeroize.rs Memory zeroization
│           ├── secret_box.rs     XOR-masked secret containers
│           └── flow.rs           Flow integrity counters
```

## What KasSigner Is

- An **offline signing device** — generates keys, signs transactions, exports via QR
- A **seed generator** — creates BIP39 mnemonics from hardware entropy or dice rolls
- A **steganographic backup tool** — hides encrypted seeds inside ordinary JPEG photos
- **Stateless** — all key material lives in RAM and is destroyed on power-off
- **Open source** — 100% Rust, every line auditable, reproducible Docker builds

## What KasSigner Is NOT

- **NOT a hardware wallet** — it has no secure element, no tamper detection, no persistent key storage. It runs on a consumer ESP32-S3 microcontroller.
- **NOT a replacement for Ledger, Trezor, or Coldcard** — those devices have dedicated security chips designed to resist physical attacks. KasSigner does not.
- **NOT audited** — the cryptographic implementation has not been reviewed by a professional security firm. The code is open for community review.
- **NOT resistant to physical attacks** — an attacker with physical access and lab equipment (JTAG probes, voltage glitching, flash readers) may be able to extract secrets from the ESP32-S3 while it is powered on.
- **NOT a place to store keys long-term** — the device wipes everything on power-off. Your backup (seed words, stego JPEG, SD card) is your permanent storage, not the device.

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
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute, code standards
- [CHANGELOG.md](CHANGELOG.md) — version history
- [docs/STEGANOGRAPHY.md](docs/STEGANOGRAPHY.md) — JPEG EXIF steganographic backup system
- [docs/KEY_DERIVATION.md](docs/KEY_DERIVATION.md) — BIP32/39/85 derivation tree explained
- [docs/EFUSE_RUNBOOK.md](docs/EFUSE_RUNBOOK.md) — eFuse secure boot procedure (irreversible!)
- [docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md) — verify builds with Docker

## Hardware References

KasSigner runs on the [Waveshare ESP32-S3-Touch-LCD-2](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2). These are the datasheets and reference manuals for the components used:

- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf) — register-level peripheral documentation
- [ESP32-S3 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf) — pinout, electrical characteristics, memory map
- [Waveshare ESP32-S3-Touch-LCD-2 Wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2) — board schematic, GPIO assignments, setup guide
- [OV5640 Datasheet](https://cdn.sparkfun.com/datasheets/Sensors/LightImaging/OV5640_datasheet.pdf) — camera sensor registers, PLL configuration, DVP interface
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
