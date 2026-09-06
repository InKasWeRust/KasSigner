# Firmware Workflow E2E Tests

KasSigner keeps the firmware workflow harness separate from production code paths while reusing the production navigation policy.

## Scope

The `workflow-tests` firmware feature is developer/QA-only and is compile-time incompatible with `production`/`silent`. It exposes the on-device E2E menu/hooks but does **not** auto-run tests at boot and does **not** enable `verbose-boot`. The separate `workflow-test-auto` feature implies `workflow-tests` and is used only by the host-supervised auto-run image. Keeping verbose software KATs independent prevents the production-KDF backup compatibility batch from delaying normal development boot or consuming the connected-device E2E timeout. Its catalog is the canonical inventory of user-visible firmware workflows. QA fails if a new `AppState` is added without being assigned to at least one workflow.

The harness has two deliberately separate responsibilities:

1. **Workflow-contract E2E** — runs headlessly against a shadow navigation state and verifies that every screen has an input route, every workflow edge is accepted by the production navigation policy, and onboarding terminal states are valid. It never mutates the live wallet/session.
2. **Fixture declaration** — each workflow declares external requirements such as a seed, camera QR, SD card, saved wallet, RTC, audio, or camera tuning. A workflow that needs a fixture is not represented as proof that the external side effect occurred merely because its navigation contract passed.

This separation prevents a destructive test such as seed deletion, duress, or storage migration from running against the user's real wallet while still making every user workflow discoverable and testable.

## On-device runner

Normal Make development firmware is built with `workflow-tests`: the application boots normally and Tools gains **E2E Tests**. No workflow suite runs automatically in this profile.

`Tools → E2E Tests` provides:

- **Run All** — all cataloged workflow contracts.
- a workflow category — Wallet Setup, Seeds, Signing, Export / Backup, Storage / SD, Steganography, Multisig, or Settings / Security.
- **Run Category** — every contract in that category.
- an individual workflow — one named contract.

The on-device menu calls the shared `runtime::workflow_tests::execute()` facade for Run All/Category/One. The automated connected-device image does not duplicate or re-run those shadow-only contracts: `make workflow-e2e` validates the canonical catalog and production reachability on the host before flashing, then reserves the board run for hardware-backed navigation evidence.

## Headless connected-device gate

`make workflow-e2e` has two ordered gates. First, the host runs the canonical workflow-catalog and production-navigation regression contracts and fails before flashing if they are not green. Second, it builds and flashes `workflow-runtime-auto` on M5Stack CoreS3 (or `workflow-test-auto` on Waveshare).

The auto image emits a constant-time pre-board marker, completes real board initialization, initializes the static internal-RAM application state, probes the live touch controller, and then drives the production Home/root/settings navigation paths on the connected board. On M5Stack, the final non-destructive runtime tranche uses the real LCD/audio/entropy/camera path, the production Core1 derivation worker, and the real 30-second TIMG0 watchdog. It must complete View Words, Firmware Update camera entry, Pop It! warning rendering, Receive -> Change derivation, multisig-kpub derivation, and a fixed-public-input PersistentWallet Argon2id KAT; the host independently imposes a 25-second deadline on each named runtime action. It deliberately does **not** run the shadow-only catalog a second time on the ESP32-S3; that duplicate run adds no hardware evidence and previously stalled the device before live navigation began. The manual `Tools → E2E Tests` menu remains available in normal developer firmware for on-device Run All/Category/One catalog execution.

A successful connected run terminates with:

```text
KASSIGNER_WORKFLOW_TESTS: PASS ALL
```

A connected navigation or touch failure emits a stable `KASSIGNER_WORKFLOW_TESTS: FAIL ...` marker instead.

Run it through the Make facade:

```bash
make workflow-e2e BOARD=m5stack PORT=/dev/ttyACM0
```

For Waveshare:

```bash
make workflow-e2e BOARD=waveshare PORT=/dev/ttyACM0
```

The Python device runner reuses the existing hardware-test flash/serial-monitor supervision; it does not introduce another serial ownership implementation in firmware. The developer-only workflow image deliberately retains the USB/JTAG log transport long enough for the supervised result marker. The repository pins espflash 3.3.0, whose monitor initializes an input reader. On POSIX hosts the supervisor therefore gives espflash a **private pseudo-terminal** rather than `/dev/null` or the developer's keyboard. The monitor kills its whole process group on completion/timeout and restores the caller terminal settings before returning, so the developer shell is never placed into espflash's raw/no-echo input mode.

The connected runner also owns transport recovery. For CoreS3 it passes an explicit `--chip esp32s3 --before usb-reset` connection profile so espflash uses the ESP32-S3 USB Serial/JTAG reset sequence instead of depending on host USB-device classification. Connection/open failures are retried up to three times **only before** espflash reports `Flashing has completed!`; an explicitly selected Linux device node is allowed a bounded re-enumeration window between attempts. The workflow timeout starts at that flash-complete boundary, not while reset/connection/flashing is still in progress. If the serial monitor drops after flashing, recovery is monitor-only with `--before no-reset-no-sync`: the runner does not reset or reflash the device, so destructive SD/HIL work cannot be restarted by host transport recovery.

When `PORT` is omitted on POSIX, unattended execution auto-selects only an unambiguous serial device (or the unique Espressif USB serial device); multiple unresolved candidates fail with the visible port list rather than opening a hidden prompt on the private pseudo-terminal. If CoreS3 still cannot enter its ROM download mode after the bounded automatic attempts, close competing serial monitors, hold the bottom RESET button for about three seconds until the internal green indicator turns on, release it, and rerun the same Make command.

The command leaves the test image on the device. Restore the normal M5Stack development image with `make flash BOARD=m5stack PORT=/dev/ttyACM0` when finished.

## Fixture-backed functional tests

The catalog's fixture mask is the boundary for functional HIL automation. Host/device fixture drivers should consume the existing workflow ID and fixture declaration rather than create a second workflow list. Functional automation must use dedicated disposable test state and must never satisfy a fixture requirement by directly forcing the next screen.

Examples:

- transaction signing: funded/test transaction fixture + camera QR + seed;
- SD backup/restore: disposable SD + disposable encrypted wallet fixture;
- RTC policies: controlled RTC fixture + disposable wallet;
- audio/camera tuning: physical board capability fixture.

Navigation-contract PASS and functional-HIL PASS are intentionally distinct evidence.

## If Make says `getcwd: No such file or directory`

That error occurs before Make reads the repository Makefile. It means the shell is still attached to a directory inode that was deleted or replaced (for example after re-extracting the repository in another process), even if the prompt still prints the old path. Recover with:

```bash
cd ~
cd ~/Downloads/kassigner
pwd -P
test -f Makefile
make help
```

Then rerun the desired Make target.
