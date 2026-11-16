<!--
Security vulnerabilities: do NOT open a public pull request or issue.
Email kassigner@proton.me with the subject [SECURITY]. See SECURITY.md.
-->

## What changed

<!-- One change per pull request. -->

## Why

<!-- The problem, and how you found it. Link the issue if there is one. -->

## User impact

<!-- What someone holding a unit, or building on the SDK, will notice.
     "None" is a fine answer. -->

## Verification

<!-- Tick only what you ran. The commands are CONTRIBUTING.md's. -->

From the repository root:

- [ ] `cargo fmt --all -- --check && cargo +esp195 test-all && cargo +esp195 clippy-all && cargo deny check`

If you touched them:

- [ ] The SDK packages, or a dependency: `sh crates/kassigner-sdk-wasm/build.sh`, `sh crates/kassigner-sdk-wasm/build.sh watch`, `sh crates/kassigner-sdk-ffi/build.sh` and `sh release/notices.sh --check`
- [ ] A shell script, or a workflow: `shellcheck` on the scripts, and `actionlint`
- [ ] `vendor/rqrr`: `cargo test` and `cargo clippy --all-targets -- -D warnings`, from that folder

On a unit:

- [ ] Flashed, and every self-test passed at boot: <!-- which boards: m5, ws, p4 -->
- [ ] Exercised on hardware: <!-- which flow: seed, restore, sign, multisig, backup, stego... -->

## Not verified

<!-- Say plainly what you did NOT test. "Compiles but not flashed" and
     "only checked on the M5Stack" are useful and welcome; a reviewer can act
     on them. Silence here is read as "fully tested". -->

## Security checklist

- [ ] No `unsafe` outside `kassigner-hal-esp32s3` and `kassigner-hal-esp32p4`, and each block there has a `// SAFETY:` comment
- [ ] Every secret wipes itself when dropped, and none leaves the unit in the clear to a file, a card or the console
- [ ] No network-capable dependency added to the firmware
- [ ] The crate's licence header on every new file
- [ ] Generated files made again with their command, not edited by hand
