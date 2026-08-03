<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

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
   - Waveshare: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features waveshare`
   - M5Stack: `cd bootloader && cargo build --release --no-default-features --features m5stack`
6. Run clippy for both targets, and make sure it is clean:
   - Waveshare: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo clippy --release --features ov5640-af`
   - M5Stack: `cd bootloader && cargo clippy --release --no-default-features --features m5stack`
7. Flash and check the boot output: the hardware self-tests and the crypto known-answer tests run at boot and must all pass. Do not build with `skip-tests` for this step, since that is what removes them
8. If modifying KasSee Web (`kassee/`), verify the WASM build: `cd kassee && RUSTUP_TOOLCHAIN=stable ./build.sh`
9. Commit with clear messages
10. Open a Pull Request

## Code Standards

- All code must be `no_std` compatible. Prefer stack buffers with compile-time bounds; the heap is for large structures that would otherwise overflow the stack
- All comments and strings in English
- GPL v3 copyright header on every source file
- Keep `unsafe` to the roles that need it: MMIO register access, `write_volatile` for zeroization (a safe write can be optimised away), and heap construction of oversized structures. Anything else needs justification in a comment
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
