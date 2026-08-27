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
5. If you touched anything under `core/`, run the host tests first; they need no hardware and no Xtensa toolchain: `cd core && cargo test`
6. Ensure the firmware compiles for both targets:
   - Waveshare: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features waveshare`
   - M5Stack: `cd bootloader && cargo build --release --no-default-features --features m5stack`
7. Run clippy in the three project configurations, all with `-D warnings`, and make sure every one is clean:
   - M5Stack: `cd bootloader && cargo clippy --release --no-default-features --features m5stack -- -D warnings`
   - Waveshare: `cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo clippy --release --features ov5640-af -- -D warnings`
   - M5Stack with the measurement features: `cd bootloader && cargo clippy --release --no-default-features --features m5stack,e12-capture,rng-probe -- -D warnings`
8. Flash and check the boot output: the hardware self-tests and the crypto known-answer tests run at boot and must all pass. Do not build with `skip-tests` for this step, since that is what removes them
9. If modifying KasSee Web (`kassee/`), verify the WASM build: `cd kassee && RUSTUP_TOOLCHAIN=stable ./build.sh`
10. Commit with clear messages
11. Open a Pull Request

## Code Standards

- All code must be `no_std` compatible. Prefer stack buffers with compile-time bounds; the heap is for large structures that would otherwise overflow the stack
- All comments and strings in English
- GPL v3 copyright header on every source file
- Keep `unsafe` to the roles that need it: MMIO register access, `write_volatile` for zeroization (a safe write can be optimised away), heap construction of oversized structures, and the function-pointer seams where the firmware registers a logger and an entropy source with `core/`. Anything else needs justification in a comment
- Key material must be explicitly cleared after use
- No network-capable dependencies in the firmware
- Zero compiler warnings on both platforms (clippy clean)

## What We Need Help With

- Security review of `core/src/wallet/` and `core/src/crypto/`
- QR decoder accuracy improvements
- New hardware board ports (via feature flags)
- Transaction review UX improvements
- KasSee Web features and testing
- Documentation and guides

## License

By contributing, you agree that your contributions will be licensed under
the GNU General Public License v3.0.
