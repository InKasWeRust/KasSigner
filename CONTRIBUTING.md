# Contributing to KasSigner

Thank you for your interest in contributing to KasSigner!

## Security Vulnerabilities

**DO NOT open a public issue for security vulnerabilities.** Instead, email
kassigner@proton.me with details. See [SECURITY.md](SECURITY.md) for our
full security policy.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure the firmware compiles: `cd bootloader && cargo build`
5. Run the QR self-tests (they execute at boot)
6. Commit with clear messages
7. Open a Pull Request

## Code Standards

- All code must be `no_std` compatible (no heap allocation in hot paths)
- All comments in English
- GPL v3 copyright header on every `.rs` file
- No `unsafe` blocks unless absolutely necessary for hardware access
- Secrets must be zeroized via `write_volatile` after use
- No network-capable dependencies

## What We Need Help With

- Security audits and code review
- QR decoder accuracy improvements
- New hardware board ports (feature flags)
- Transaction review UX improvements
- Documentation and guides

## License

By contributing, you agree that your contributions will be licensed under
the GNU General Public License v3.0.
