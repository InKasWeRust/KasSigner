<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Contributing to KasSigner

Thanks for helping improve KasSigner.

## Security vulnerabilities

**Do not open a public issue for a suspected vulnerability.** Email
`kassigner@proton.me` with subject `[SECURITY]`; see [SECURITY.md](SECURITY.md).

## Development setup

Use the native bootstrap for the host you are actually testing:

```bash
# Linux
./install.sh
make help
make test
```

```powershell
# Windows PowerShell (native; no WSL)
.\install.ps1
make help
make test
```

On macOS, `./install.sh` preserves the original interactive **Waveshare firmware
build/erase/flash** workflow. It is not the Linux/Windows full-QA bootstrap.
The documented contributor interface is GNU Make. Platform scripts under `scripts/` and `qa/` plus direct Python checks remain available for CI/debugging, but they are implementation helpers rather than competing public entry points. Do not use `scripts/linux/` as a claimed macOS compatibility layer. iOS work
requires macOS/Xcode plus the Rust, Python, and KasSee WASM prerequisites.

## Before opening a pull request

1. Make the smallest coherent change; do not weaken QA thresholds to make it pass.
2. Run `make test` while developing. It is intentionally host/browser-only: no Android, iOS/Xcode, physical-device, or HIL tests run there.
3. Run `make qa` before release-oriented changes. It is the authoritative all-non-hardware suite and includes eligible Android/iOS software tests, QEMU, real-node and funded/interactive E2E, coverage/CRAP, benchmarks, fresh mutation certification, and fuzzing. Keep first-party versions pinned at `2.0.0` unless a release explicitly changes them.
4. Firmware changes should pass `make qa` before release-oriented review.
5. KasSee changes should build with `make kassee`.
6. `make android-qa` and `make ios-qa` remain useful focused mobile commands; the corresponding non-hardware mobile checks are also cataloged under `make qa`, with explicit SKIP results on ineligible hosts.
7. Hardware-sensitive changes should be exercised on the affected board. If you do not have that hardware, say so plainly in the PR; a skipped HIL check is not a pass.
8. Update the smallest relevant user guide or changelog entry when behavior changes.

## Code and security rules

- Firmware remains `no_std` and must not gain a wallet-network path.
- No secret-bearing production logs; zeroize owned transient key material.
- Avoid `unsafe` except where hardware access requires it, and keep its scope documented.
- Monetary/DAA values crossing JavaScript boundaries must use exact integer handling, not lossy `Number` arithmetic.
- Keep wallet-spending keys separate from covenant-only signing domains.
- Do not reintroduce retired password-only secret containers or obsolete transaction/session wire formats as current encoders.
- Keep compiler/lint/CRAP/mutation/coverage/fuzz/architecture gates intact.

## Useful contribution areas

Security review, QR/camera reliability, Waveshare and other hardware validation,
macOS/iOS validation, transaction/covenant review UX, KasSee/mobile testing, and
clear reproducible documentation are especially useful.

## License

KasSigner uses path-specific contribution licensing so the public wallet SDK
remains permissive without relicensing the GPL application/device code:

- Contributions to `crates/shared-signer`, `crates/kassigner-protocol`, and
  `crates/kassigner-sdk` are accepted under **MIT OR Apache-2.0**, matching
  those crates' `Cargo.toml` declarations and bundled license files.
- Contributions to the remaining first-party application/device crates and
  repository code are accepted under **GPL-3.0-only**, unless a file or
  directory carries an explicit different license.
- A change spanning both groups is licensed per destination file/path; moving
  code across the GPL/permissive boundary requires explicit provenance and
  relicensing authority rather than an implicit copy.

By contributing, you agree that your contribution may be distributed under the
license terms applicable to each destination path above.
