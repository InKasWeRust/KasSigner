<!-- Delete any section that does not apply. A short PR with three honest
     sections beats a long one with every heading filled in for form. -->

## What changed

<!-- Bullet list. One line per behavioural change, not per file. -->

-

## Why

<!-- What was wrong, or what this makes possible. If it fixes a defect, say
     what the defect actually did, not just that it existed. -->

## User impact

<!-- What someone holding the device sees or does differently. Write "none"
     if nothing changes for them. Call out anything that invalidates an
     existing backup, address, fingerprint or exported file. -->

## Verification

Builds, both targets (see CONTRIBUTING.md steps 5-6):

- [ ] Waveshare: `ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features waveshare`
- [ ] M5Stack: `cargo build --release --no-default-features --features m5stack`
- [ ] Clippy clean, Waveshare: `ESP_HAL_CONFIG_PSRAM_MODE=octal cargo clippy --release --features ov5640-af`
- [ ] Clippy clean, M5Stack: `cargo clippy --release --no-default-features --features m5stack`

Host tests, if the change touches `core/`. Clippy on the firmware does NOT
cover that crate: it is a path dependency, and cargo does not lint
dependencies, so `core.yml` is the only lint coverage the wallet, crypto and
QR code gets.

- [ ] `cd core && cargo test`
- [ ] `cd core && cargo clippy --all-targets -- -D warnings -A unknown_lints`

Boot tests. These are removed by `skip-tests`, so build WITHOUT it for this
step:

- [ ] Hardware self-tests pass at boot
- [ ] Crypto known-answer tests pass at boot
- [ ] Flashed and exercised on hardware: <!-- which board, which flow -->

<!-- If the change touches kassee/, also: RUSTUP_TOOLCHAIN=stable ./build.sh -->

## Not verified

<!-- Say plainly what you did NOT test. "Compiles but not flashed" and
     "only checked on M5Stack" are useful and welcome; a reviewer can act on
     them. Silence here is read as "fully tested". -->

## Security checklist

- [ ] `unsafe` limited to MMIO, volatile accesses the optimiser must not elide (the `write_volatile` zeroization, the `read_volatile` that keeps unsigned builds whole), heap construction of oversized structures, or the seams where the firmware registers a logger and an entropy source with `core/`; anything else justified in a comment
- [ ] Key material explicitly cleared after use
- [ ] No network-capable dependencies added
- [ ] GPL v3 header on new files
- [ ] No secret, key, seed or passphrase value added to a `log!` line

<!-- Reminder: production implies silent, which compiles out every log! and
     gates USB serial. In a shipped build the screen is the only channel, so
     an on-screen message has to stand on its own. -->

<!-- Security vulnerabilities: do NOT open a public PR or issue.
     Email kassigner@proton.me with subject [SECURITY]. See SECURITY.md. -->
