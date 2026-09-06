[KasSigner](../README.md) › Documentation

# Documentation

Use this page as the navigation hub for project documentation. Component READMEs stay beside the code or artifact they explain; cross-cutting reference material lives under `docs/`.

## Start here

- [Features](features/FEATURES.md) — complete product capability summary and compatibility notes.
- [Building](development/BUILDING.md) — contributor setup, Make targets, firmware builds, and release entry points.
- [KasSee](kassee/KASSEE.md) — browser/mobile watch-only wallet behavior and safety model.
- [Security overview](security/SECURITY_OVERVIEW.md) — key lifecycle, trust boundaries, limitations, and assurance model.
- [Hardware](hardware/HARDWARE.md) — supported boards, qualification, and hardware references.

## Develop and integrate

- [Repository Architecture](development/REPOSITORY_ARCHITECTURE.md) — dependency direction, responsibility boundaries, and original→current ownership map.
- [Firmware Architecture](development/FIRMWARE_ARCHITECTURE.md) — signer firmware layers and hardware/runtime boundaries.
- [Wallet Integration](integration/WALLET_INTEGRATION.md) — integrate KasSigner into third-party wallets through the Rust/WASM SDK.
- [`COVENANT SIGN`](protocol/COVENANT_SIGN.md) — covenant-signing protocol contract.

## Build, qualify, and recover

- [Build, Sign & Flash](development/BUILD_FLASH_GUIDE.md) and [Reproducible Builds](development/REPRODUCIBLE_BUILD.md).
- [eFuse Runbook](EFUSE_RUNBOOK.md), [Entropy Sources](security/ENTROPY_SOURCES.md), [Pop It! and owner-authorized firmware](security/POP_IT_SECURE_BOOT.md), and [Steganographic Backup](security/STEGANOGRAPHY.md).
- Printable/user-facing PDFs remain under [`docs/guides/`](guides/).

For vulnerability reporting and repository security policy, use the top-level [SECURITY.md](../SECURITY.md). For release and compatibility history, use [CHANGELOG.md](../CHANGELOG.md).
