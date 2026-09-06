<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

**Navigate:** [Documentation](docs/README.md) · [Building](docs/development/BUILDING.md) · [KasSee](docs/kassee/KASSEE.md) · [Security](SECURITY.md)

# KasSigner

**Air-gapped offline signing device for the Kaspa blockchain.**

> ⚠️ **EXPERIMENTAL SECURITY SOFTWARE.** KasSigner runs on consumer ESP32-S3 hardware with no secure element or tamper resistance. The 2.0.0 line has extensive automated assurance (mutation testing, fuzzing, branch coverage, CRAP/complexity gates, reproducible builds, and source-security checks), but those controls do not replace release-bound independent review, broad hardware validation, physical attack testing, entropy characterization, or field history. Do not use it for funds you cannot afford to lose.

> ⚠️ **VALIDATION STATUS.** **Tested:** M5Stack CoreS3 hardware, KasSee Web, the Android app, and the iOS app on macOS Sonoma with Xcode 16.2 using the iPhone 16 Pro Simulator. **Meaningful remaining hardware qualification gaps:** Waveshare boards and the other ESP32-S3 hardware variants. A signed iOS Release build plus physical-device smoke remains formal release evidence in the release checklist, but iOS is no longer treated as an unresolved application-qualification gap. Untested hardware variants may still contain build/integration defects or minor UI/UX issues. Community test reports and fixes are welcome.

> ⚠️ **SEEDS FROM 1.0.4 AND EARLIER.** Earlier releases had two seed-generation defects: dice entropy could be printed over USB serial, and automatic camera entropy could be accepted in poor light while the intended hardware-RNG register was wrong. If an affected seed may have been exposed or generated in poor conditions, create a fresh seed on current firmware and move the balance. See [CHANGELOG.md](CHANGELOG.md).

KasSigner keeps spending keys offline and exchanges transaction data by QR code. Hardware users can choose RAM-only **Always Start Fresh** operation or optional **device-bound encrypted wallet storage** protected by the ESP32-S3 HMAC eFuse service plus the user's PIN/password. Portable recovery remains the BIP39 mnemonic plus optional passphrase.

The firmware signing path is bare-metal `no_std` Rust. KasSee uses Rust/WASM with a browser UI; the mobile shells use Swift (iOS) and Kotlin (Android) around the same KasSee runtime.

**Documentation:** [Overview](docs/README.md) · [Features](docs/features/FEATURES.md) · [Building](docs/development/BUILDING.md) · [KasSee](docs/kassee/KASSEE.md) · [Security](docs/security/SECURITY_OVERVIEW.md) · [Hardware](docs/hardware/HARDWARE.md)

## Features

- **Air-gapped signer** — QR/SD transaction exchange with on-device review; no wallet-network path in firmware.
- **Seed generation** — BIP39 12/24 words from mandatory health-checked hardware RNG + camera + board IMU + timing/context mixing, with optional additive dice; BIP32, BIP85, passphrases, and Touch Seed are supported. See [Entropy Sources](docs/security/ENTROPY_SOURCES.md).
- **Optionally stateless** — **Always Start Fresh** keeps key material in RAM and destroys it on power-off; encrypted device-bound persistence is opt-in.
- **Backups** — mnemonic/SeedQR, authenticated SD backups, and a **steganographic backup tool** that hides encrypted seeds inside ordinary JPEG photos.
- **Transactions** — Schnorr signing, PSKT/PSKB, session-bound KSPT v4, multisig, stealth, and current Covenants++ workflows.
- **Companions** — KasSee Web plus Android and iOS shells around the same Rust/WASM wallet runtime.
- **Wallet integration SDK** — official network-free Rust crate/WASM SDK for third-party wallets to pair directly with KasSigner; KasSee is the reference consumer, not an intermediary.
- **Assurance** — reproducible builds, pinned toolchains, mutation/fuzz/coverage/CRAP gates, architecture checks, and explicit release evidence requirements.

See the [full feature summary](docs/features/FEATURES.md) and [CHANGELOG.md](CHANGELOG.md).

## Verify First: Reproducible Builds

Before flashing a release, rebuild it from source and compare the published hashes. The reproducible path uses the pinned Docker build rather than local compiler state.

```bash
make release
```

This builds and manifest-verifies the reproducible **normal release** artifacts. The normal release is deliberately non-destructive: it does not compile the Pop It!/owner-authority UI or boot-control provisioning path. Flash an already-built signed merged image with `make flash-release`; that target never rebuilds firmware, never invokes the secure-provisioning profile, and never falls back to an unsigned image. The two special CoreS3 provisioning builds are explicit and non-flashing: `make secure-provisioning SECURE_BOOT_KEY=... SIGNING_KEY=...` for vendor + optional owner authority, and `make secure-owner-only OWNER_KEY=...` for the restored sole-owner hardware trust model. Production publication additionally requires the external signed-evidence gate:

```bash
make release-readiness
```

See [Building](docs/development/BUILDING.md), [Reproducible Builds](docs/development/REPRODUCIBLE_BUILD.md), and [Release evidence](qa/release/README.md).

## Steganographic Backup: A beautiful way

KasSigner can hide an encrypted mnemonic in an ordinary JPEG using authenticated **Descriptor** or **Picture** carriers, with device-bound or portable protection depending on the recovery goal.

See [Features](docs/features/FEATURES.md) and [JPEG Steganographic Backup](docs/security/STEGANOGRAPHY.md).

## Covenants++

KasSee builds covenant transactions, KasSigner reviews/signs them offline, and KasSee broadcasts them. Current workflows cover savings/inheritance/limits, whitelists, channels, PayJoin, commit-reveal, Private Swap, KIP-20 vaults, Oracle, ZK Crowdfunding, ZK Price Oracle, and stealth payments.

`COVENANT SIGN` uses isolated covenant keys for exact reviewed commitments. See [Features](docs/features/FEATURES.md), [`COVENANT SIGN`](docs/protocol/COVENANT_SIGN.md), and the [Covenants & Stealth Guide](docs/guides/KasSigner_Kassee_Covenants_Stealth_Guide.pdf).

## Wallet Slot Types

KasSigner supports up to 16 active wallet slots:

- **Mnemonic (12/24 words)** — full BIP39 wallet with HD addresses, BIP85, signing, kpub/XPrv, and SeedQR.
- **Account XPrv** — account-level extended private key with preserved derivation metadata.
- **Raw private key** — a single 32-byte secp256k1 scalar imported as 64 hex characters. **Compatible with KasWare-style raw-key exports.**

See [Features](docs/features/FEATURES.md) for recovery and compatibility details.

## Supported Hardware

| Target | Code support | Validation status |
|---|---|---|
| M5Stack CoreS3 | Yes | **Hardware-tested** |
| M5Stack CoreS3 Lite | Shared M5Stack target | Not separately hardware-tested |
| Waveshare ESP32-S3-Touch-LCD-2 (OV2640/OV5640) | Yes | **Not hardware-tested** |
| Waveshare OV5640-AF variant | Yes | **Not hardware-tested** |

A community 3D-printable Waveshare case is included under [`external/hardware/`](external/hardware/), design by **Sandmann21** (GPL). See [Hardware](docs/hardware/HARDWARE.md) for target notes and references.

## Building

Fresh native development hosts:

```bash
# Linux
./install.sh
make help
make test
```

```powershell
# Windows (native PowerShell; no WSL required)
.\install.ps1
make help
make test
```

GNU Make is the stable public developer interface on Linux and Windows; platform scripts and Python checks are implementation/debug helpers behind it. Start with `make test`, `make firmware`, and `make help`. `make test` is the fast host/browser contributor suite and deliberately runs no Android, iOS/Xcode, physical-device, or HIL tests. `make qa` is the authoritative all-non-hardware suite: it starts with strict coverage/CRAP, then immediately runs the pinned stable Core CI gate (`cargo fmt --all -- --check`, workspace/all-target Clippy with `-D warnings`, strict `make test`, and `git diff --check`) while retaining the complete transcript at `target/qa/core-ci/core-ci.log`; after that it continues with static/security/regression, browser/mobile/QEMU/software integration, real-node and funded/interactive testnet E2E, benchmarks, fresh mutation certification, and fuzzing last. Firmware builds never flash; device writes are explicit through `make flash BOARD=... PORT=...`. A failed full QA run can be continued with `make qa RESUME_FROM=<stable-step-id>`; the named step is rerun before all later QA steps.

**macOS:** `./install.sh` retains the native Waveshare firmware setup/build/erase/flash workflow; it is not the Linux/Windows full-QA bootstrap. The iOS/Xcode path is validated on macOS Sonoma with Xcode 16.2 and the iPhone 16 Pro Simulator; use `scripts/mac/install.sh` for the iOS-only toolchain and `scripts/mac/run-ios.command` to build/install/launch the app in Simulator.

See [Building](docs/development/BUILDING.md), [Build, Sign & Flash](docs/development/BUILD_FLASH_GUIDE.md), and the [eFuse Runbook](docs/EFUSE_RUNBOOK.md).

## KasSee: Watch-Only Companion Wallet

KasSee is the browser-based watch-only companion wallet. It imports your kpub, derives addresses, tracks UTXOs, builds unsigned transactions/covenants, hands them to KasSigner by QR, scans signed responses, and broadcasts them without needing the wallet spending private key.
Third-party wallets do not connect through KasSee. The official Rust/WASM integration is split into [`kassigner-sdk`](crates/kassigner-sdk/) for the friendly pair/prepare/complete/finalize flow and [`kassigner-protocol`](crates/kassigner-protocol/) for advanced PSKT/KSPT/QR control; both pair directly with the hardware and leave coin selection, fees, change policy, and broadcast to the host wallet.

Visit [kassigner.org](https://kassigner.org/). KasSee connects to a public Kaspa node automatically; to use your own node, open **Settings** and enter a WebSocket URL (`wss://` or `ws://`).

Highlights include fee selection/Send Max, manual UTXO selection, receive/address history and reuse markers, animated QR, multisig, Covenants++, Private Swap, ZK Crowdfunding, Oracle, stealth, KRC-20/KRC-721/KNS views, node resolver/reconnect, storage-mass checks, camera scanning, and PWA/mobile shells.

See [KasSee](docs/kassee/KASSEE.md) for the complete feature list, source build, safety model, and mobile status.

## What KasSigner Is

- An **offline signing device**: generates/imports keys, reviews/signs transactions, and exports results by QR.
- A **seed generator**: creates BIP39 mnemonics from hardware entropy **or dice rolls**.
- A **steganographic backup tool**: hides encrypted seeds inside ordinary JPEG photos.
- **Optionally stateless**: **Always Start Fresh** keeps wallet key material in RAM and destroys it on power-off; device-bound encrypted persistence is opt-in.
- An **open-source** Rust-first project with reproducible builds and aggressive automated security/quality gates.

## What KasSigner Is NOT

- **Not a secure-element hardware wallet**: it runs on a consumer ESP32-S3 and does not provide dedicated tamper-resistant key silicon.
- **Not resistant to lab-grade physical attack**: voltage glitching, invasive probing, side channels, and fault injection remain relevant.
- **Not formally verified or certified**: mutation/fuzz/coverage gates are testing methods, not mathematical proof or a guarantee.
- **Not claiming security certification**: the project has undergone multiple independent security reviews/audits and tracked findings have been addressed in the current codebase. See [CHANGELOG.md](CHANGELOG.md) and any open repository issues.
- **Not a substitute for recovery words**: the mnemonic plus optional BIP39 passphrase remains the durable cross-device recovery path.

## Security Architecture

- **Air gap:** firmware has no wallet network stack; production policy gates development/debug data paths.
- **Key lifecycle:** active wallet material stays in RAM unless device-bound encrypted persistence is explicitly enabled; signing keys are derived only for reviewed operations.
- **Boot verification:** the normal signed production release is software-verified and contains no Pop It!/owner-authority/eFuse-provisioning UI or request-staging path. Separate opt-in CoreS3 `secure-provisioning` (vendor + optional owner) and `secure-owner-only` (owner is the sole hardware authority) builds contain that UI. Neither special profile performs an irreversible eFuse transition during boot or ordinary use: owner enrollment requires its explicit typed action, and flash encryption/Secure Boot/anti-rollback provisioning is deferred until the explicit typed Pop It! action. Development firmware keeps a non-destructive simulation of the same UI.
- **Cryptography:** BIP39/BIP32/BIP85, secp256k1 Schnorr/BIP-340-compatible signing, SHA-256/HMAC, Kaspa transaction hashing, Argon2id for KasSigner-owned password protection, standards-required BIP39 PBKDF2, AES-256-GCM, and ECDH where required.

See [Security overview](docs/security/SECURITY_OVERVIEW.md) and [SECURITY.md](SECURITY.md).

## Documentation

- [Documentation hub](docs/README.md) — guided navigation for features, building, KasSee, security, hardware, development, and integration.
- [Repository Architecture](docs/development/REPOSITORY_ARCHITECTURE.md) — current dependency graph and original→current ownership map.
- [Wallet Integration](docs/integration/WALLET_INTEGRATION.md) — third-party wallet SDK/protocol integration.
- [User guides](docs/guides/) — printable and end-user PDFs.
- [Constellation](https://kassigner.org/constellation/) — interactive key-derivation and architecture explorer.
- [CHANGELOG.md](CHANGELOG.md) — version, compatibility, feature, and security history.

## Hardware References

- [ESP32-S3 Technical Reference Manual](https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf)
- [ESP32-S3 Datasheet](https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf)
- [Waveshare ESP32-S3-Touch-LCD-2 Wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-2)
- [M5Stack CoreS3 documentation](https://docs.m5stack.com/en/core/CoreS3)
- [OV2640 Datasheet](https://www.uctronics.com/download/cam_module/OV2640DS.pdf)
- [ST7789 Datasheet](https://www.newhavendisplay.com/appnotes/datasheets/LCDs/ST7789V.pdf)

More target notes are in [Hardware](docs/hardware/HARDWARE.md).

## Cryptographic Notice

This software contains cryptographic functionality. Export, import, or use may be subject to laws in your jurisdiction. Algorithms and protocol choices are open for review; this notice is not a certification of security.

## Contributing

Contributions are especially welcome for security review, signed iOS physical-device validation, Waveshare hardware validation, QR/camera reliability, hardware ports, transaction/covenant review UX, and documentation. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) first.

## License

[GNU General Public License v3.0](LICENSE)

## Disclaimer

**KasSigner remains experimental security software on consumer hardware.** Automated assurance is extensive but incomplete, and not every supported hardware variant has completed physical qualification. Verify transactions on the device, verify builds where practical, keep tested recovery backups, start with small amounts, and never risk more than you can afford to lose.
