<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# Contributing to KasSigner

Thank you for your interest in contributing to KasSigner!

## Security Vulnerabilities

**DO NOT open a public issue for security vulnerabilities.** Instead, email
kassigner@proton.me with subject `[SECURITY]`. See [SECURITY.md](SECURITY.md) for our
full security policy.

## How to Contribute

1. Fork the repository
2. Run the setup checker: `cd tools && cargo run --bin kassigner-setup`
3. Create a feature branch (`git checkout -b feature/my-feature`)
4. Make your changes
5. Ensure the firmware compiles for both targets:
   - Waveshare: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features waveshare,skip-tests`
   - M5Stack: `cd bootloader && cargo build --release --no-default-features --features m5stack,skip-tests`
6. Run clippy: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo clippy --features waveshare,skip-tests`
7. Run the hardware self-tests (they execute at boot — flash and verify on device)
8. If modifying KasSee Web (`kassee/`), verify the WASM build: `cd kassee && RUSTUP_TOOLCHAIN=stable ./build.sh`
9. Commit with clear messages
10. Open a Pull Request

## Code Standards

- All code must be `no_std` compatible (no heap allocation in hot paths)
- All comments and strings in English
- GPL v3 copyright header on every source file
- No `unsafe` blocks unless absolutely necessary for hardware register access
- Key material must be explicitly cleared after use
- No network-capable dependencies in the firmware
- Zero compiler warnings on both platforms (clippy clean)

## What We Need Help With

- Security review of `wallet/` and `crypto/` modules
- QR decoder accuracy improvements
- New hardware board ports (via feature flags)
- Transaction review UX improvements
- KasSee Web features and testing
- Documentation and guides

## License

By contributing, you agree that your contributions will be licensed under
the GNU General Public License v3.0.
