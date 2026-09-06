# KasSigner CoreS3 Production End-to-End Requirements

> QA implementation specification. This file is machine-consumed release-assurance input, not project/developer documentation. It is the single canonical source for production E2E requirement groups and stable item IDs.

**Package:** 2.0.0  
**Board:** M5Stack CoreS3  
**Scope:** production end-user behavior. Developer-only menus, diagnostics, workflow-test UI, and other QA-only facilities are excluded from production coverage.

This checklist is the canonical production E2E requirements document. Requirement text tracks the current production UI while stable item IDs preserve coverage continuity. The independent production-surface baseline remains the continuous-integration backlog ratchet. Section IDs (`E2E-001`..`E2E-100`) are grouping labels; every checkbox has its own stable item ID (for example `E2E-045-03`) and item IDs are the authoritative completion unit consumed by `qa/checks/firmware/production_e2e_coverage.py`. Definition-of-Done/release qualification is item-level and cannot be satisfied while any required item or production surface remains uncovered.

Coverage levels used by the generated manifest:

- `catalog`: declarative state/transition catalog coverage only.
- `connected`: production controller/state/redraw logic exercised on a connected CoreS3 test image.
- `hil`: a real peripheral or physical interaction is exercised.
- `manual-hil`: requires an external/manual physical action that the device cannot self-generate.

## E2E-001 — Boot and Startup
- [ ] **E2E-001-01** — Cold boot with no stored wallet.
- [ ] **E2E-001-02** — Cold boot with a stored PIN-protected wallet.
- [ ] **E2E-001-03** — Cold boot with a stored password-protected wallet.
- [ ] **E2E-001-04** — Cold boot with device-bound SD storage enabled.
- [ ] **E2E-001-05** — Cold boot when the required device-bound SD card is present.
- [ ] **E2E-001-06** — Cold boot when the required device-bound SD card is absent.
- [ ] **E2E-001-07** — Cold boot when device-bound SD data is corrupt or unreadable.
- [ ] **E2E-001-08** — Startup self-tests succeed.
- [ ] **E2E-001-09** — Startup self-test failure is surfaced and fails closed.
- [ ] **E2E-001-10** — Internal SRAM test path.
- [ ] **E2E-001-11** — PSRAM detection/test path when enabled.
- [ ] **E2E-001-12** — Flash mapped-segment validation.
- [ ] **E2E-001-13** — SHA-256 self-test.
- [ ] **E2E-001-14** — Display initialization succeeds.
- [ ] **E2E-001-15** — Display initialization failure fails closed.
- [ ] **E2E-001-16** — PMU initialization succeeds.
- [ ] **E2E-001-17** — PMU initialization failure behavior.
- [ ] **E2E-001-18** — Touch-controller/IO-expander initialization succeeds.
- [ ] **E2E-001-19** — Touch-controller failure behavior.
- [ ] **E2E-001-20** — SD initialization present/absent/failure paths.
- [ ] **E2E-001-21** — Audio initialization succeeds.
- [ ] **E2E-001-22** — Audio initialization failure behavior.
- [ ] **E2E-001-23** — Camera initialization succeeds.
- [ ] **E2E-001-24** — Camera initialization failure behavior.
- [ ] **E2E-001-25** — IMU initialization succeeds.
- [ ] **E2E-001-26** — IMU initialization failure behavior.
- [ ] **E2E-001-27** — Hardware RNG/entropy health succeeds.
- [ ] **E2E-001-28** — Hardware RNG/entropy health failure behavior.
- [ ] **E2E-001-29** — RTC initialization/read succeeds.
- [ ] **E2E-001-30** — RTC initialization/read failure behavior.
- [ ] **E2E-001-31** — Wireless-lockdown security invariant is active at boot.
## E2E-002 — First-Boot Welcome
- [ ] **E2E-002-01** — Render Welcome.
- [ ] **E2E-002-02** — Create Wallet.
- [ ] **E2E-002-03** — Restore Wallet.
- [ ] **E2E-002-04** — Back where permitted and outside-touch no-op.

## E2E-003 — Create Wallet Word Count
- [ ] **E2E-003-01** — Select 12 words.
- [ ] **E2E-003-02** — Select 24 words.
- [ ] **E2E-003-03** — Back to Welcome and outside-touch no-op.

## E2E-004 — Mandatory Entropy
- [ ] **E2E-004-01** — Collect mandatory hardware RNG entropy.
- [ ] **E2E-004-02** — Collect mandatory camera entropy.
- [ ] **E2E-004-03** — Collect IMU entropy.
- [ ] **E2E-004-04** — Successful entropy health validation.
- [ ] **E2E-004-05** — Camera unavailable.
- [ ] **E2E-004-06** — Camera returns no usable frames.
- [ ] **E2E-004-07** — Camera entropy retry.
- [ ] **E2E-004-08** — Camera entropy cancel.
- [ ] **E2E-004-09** — IMU unavailable.
- [ ] **E2E-004-10** — IMU entropy-health failure.
- [ ] **E2E-004-11** — IMU retry.
- [ ] **E2E-004-12** — Hardware RNG health failure.
- [ ] **E2E-004-13** — Entropy collection cannot silently continue with a missing mandatory source.
- [ ] **E2E-004-14** — 12-word generation completes.
- [ ] **E2E-004-15** — 24-word generation completes.
## E2E-005 — Optional Dice Entropy
- [ ] **E2E-005-01** — No Dice and Add Dice Rolls.
- [ ] **E2E-005-02** — 25/50/100/200 roll choices.
- [ ] **E2E-005-03** — Die values 1 through 6; reject outside 1–6.
- [ ] **E2E-005-04** — Undo including zero boundary.
- [ ] **E2E-005-05** — Correct progress/count, cancel, and exact completion.

## E2E-006 — Optional Touch Entropy
- [ ] **E2E-006-01** — No Touch Entropy and Add Touch Entropy.
- [ ] **E2E-006-02** — Collect samples at different positions/timings.
- [ ] **E2E-006-03** — Cancel and complete.

## E2E-007 — BIP39 Passphrase During Creation
- [ ] **E2E-007-01** — No passphrase and enter passphrase.
- [ ] **E2E-007-02** — Simple/long valid passphrases, keyboard pages, edit/backspace, submit, cancel.
- [ ] **E2E-007-03** — Empty optional passphrase follows specification.

## E2E-008 — Recovery-Word Presentation
- [ ] **E2E-008-01** — First/next/previous/last word boundaries.
- [ ] **E2E-008-02** — All 12 or 24 words reachable.
- [ ] **E2E-008-03** — Backup acknowledgement cannot be skipped.
- [ ] **E2E-008-04** — I BACKED UP MY WORDS.

## E2E-009 — Storage Choice After Creation
- [ ] **E2E-009-01** — Save Securely on Device.
- [ ] **E2E-009-02** — Use for This Session Only.
- [ ] **E2E-009-03** — Back behavior.
- [ ] **E2E-009-04** — Session-only reaches wallet UI and leaves no persistent secret after reset.

## E2E-010 — Credential Type
- [ ] **E2E-010-01** — PIN.
- [ ] **E2E-010-02** — Password.
- [ ] **E2E-010-03** — Back where permitted.

## E2E-011 — PIN Setup
- [ ] **E2E-011-01** — Minimum/maximum valid length.
- [ ] **E2E-011-02** — Too short/too long rejection.
- [ ] **E2E-011-03** — Digits 0–9, delete, confirmation, mismatch/retry, back/cancel.
- [ ] **E2E-011-04** — Persistence failure fails closed.

## E2E-012 — Password Setup
- [ ] **E2E-012-01** — Minimum/maximum and required character classes.
- [ ] **E2E-012-02** — Too short/invalid class rejection.
- [ ] **E2E-012-03** — Keyboard pages, backspace, confirmation, mismatch/retry, back/cancel.
- [ ] **E2E-012-04** — Persistence failure fails closed.

## E2E-013 — Unlock Existing Wallet
- [ ] **E2E-013-01** — Correct PIN unlocks.
- [ ] **E2E-013-02** — Incorrect PIN is rejected.
- [ ] **E2E-013-03** — Correct password unlocks.
- [ ] **E2E-013-04** — Incorrect password is rejected.
- [ ] **E2E-013-05** — Repeated failures invoke intended backoff.
- [ ] **E2E-013-06** — Unlock cannot be bypassed using Back.
- [ ] **E2E-013-07** — Unlock cannot be bypassed using Home.
- [ ] **E2E-013-08** — Malformed stored state fails closed.
- [ ] **E2E-013-09** — Duress credential produces intended duress behavior.
- [ ] **E2E-013-10** — Duress visible handling matches the specified indistinguishable failure path.
## E2E-014 — Restore Wallet Main Choices
- [ ] **E2E-014-01** — Enter Words.
- [ ] **E2E-014-02** — Scan SeedQR.
- [ ] **E2E-014-03** — Restore from SD.
- [ ] **E2E-014-04** — Advanced Restore.
- [ ] **E2E-014-05** — Back.

## E2E-015 — Restore Recovery Words
- [ ] **E2E-015-01** — Valid 12 and 24 words.
- [ ] **E2E-015-02** — 12-word checksum detection: restore or continue to 24.
- [ ] **E2E-015-03** — Invalid checksums rejected.
- [ ] **E2E-015-04** — Suggestions/no-match/edit/back navigation.
- [ ] **E2E-015-05** — Restore with and without BIP39 passphrase.

## E2E-016 — Restore SeedQR
- [ ] **E2E-016-01** — Compact and standard SeedQR.
- [ ] **E2E-016-02** — Supported plain-text seed representation where permitted.
- [ ] **E2E-016-03** — Invalid checksum/count/malformed QR.
- [ ] **E2E-016-04** — Cancel/back.
- [ ] **E2E-016-05** — Multi-frame missing/duplicate/out-of-order/mixed-session rejection.

## E2E-017 — Advanced Restore
- [ ] **E2E-017-01** — Compact SeedQR.
- [ ] **E2E-017-02** — Raw Private Key.
- [ ] **E2E-017-03** — Steganographic restore.
- [ ] **E2E-017-04** — Back.

## E2E-018 — Raw Private-Key Import
- [ ] **E2E-018-01** — Valid lowercase/uppercase 64-hex input.
- [ ] **E2E-018-02** — Short/long/non-hex/zero/out-of-range rejection.
- [ ] **E2E-018-03** — Edit/backspace/cancel.
- [ ] **E2E-018-04** — Successful import and slot-full failure.
- [ ] **E2E-018-05** — Raw-key wallet single-address restrictions.

## E2E-019 — Home Screen
- [ ] **E2E-019-01** — Receive, Scan QR, Wallet, Settings render and route.
- [ ] **E2E-019-02** — Every route returns correctly.
- [ ] **E2E-019-03** — Touch between tiles is a no-op.
- [ ] **E2E-019-04** — Header/global controls behave correctly.

## E2E-020 — Receive
- [ ] **E2E-020-01** — Current address renders and encodes correctly.
- [ ] **E2E-020-02** — Open/close full-screen QR.
- [ ] **E2E-020-03** — Receive/change chain toggle.
- [ ] **E2E-020-04** — Previous index including zero boundary; next index.
- [ ] **E2E-020-05** — Custom index entry: digits, clear, submit, malformed/length limits, back.
- [ ] **E2E-020-06** — Raw-key restrictions.
- [ ] **E2E-020-07** — Missing key/public cache fails closed.
- [ ] **E2E-020-08** — Back/Home behavior.

## E2E-021 — Main Scan QR
- [ ] **E2E-021-01** — Kaspa address, Compact KSPT, Standard PSKT, SeedQR, supported raw entropy, stealth, firmware update, covenant variants, private swap variants, anti-klepto, multisig descriptor fallback, kpub fallback.
- [ ] **E2E-021-02** — Unknown/empty/oversized/malformed recognized payload.
- [ ] **E2E-021-03** — Cancel/back and no-QR responsiveness.

## E2E-022 — Multi-Frame QR Assembly
- [ ] **E2E-022-01** — Correct/out-of-order/duplicate/missing/repeated frame.
- [ ] **E2E-022-02** — Invalid total/index/length/corrupt frame.
- [ ] **E2E-022-03** — Mixed-session/splice rejection.
- [ ] **E2E-022-04** — Restart/cancel clears state.
- [ ] **E2E-022-05** — Maximum and above-maximum frame counts.

## E2E-023 — Wallet Menu
- [ ] **E2E-023-01** — Receive.
- [ ] **E2E-023-02** — Connect KasSee.
- [ ] **E2E-023-03** — Backup.
- [ ] **E2E-023-09** — Recovery.
- [ ] **E2E-023-04** — Wallet Details.
- [ ] **E2E-023-05** — Switch / Add Wallet.
- [ ] **E2E-023-06** — Multisig.
- [ ] **E2E-023-07** — Advanced.
- [ ] **E2E-023-08** — Back.

## E2E-024 — Connect KasSee
- [ ] **E2E-024-01** — Loading state and watch-only derivation.
- [ ] **E2E-024-02** — kpub QR/open/save/return.
- [ ] **E2E-024-03** — Derivation/missing-key/SD failures.
- [ ] **E2E-024-04** — Back/Home.

## E2E-025 — Wallet Details
- [ ] **E2E-025-01** — Source/type/fingerprint and non-secret metadata.
- [ ] **E2E-025-02** — Delete flow: cancel, early release, move-away cancel, full hold.
- [ ] **E2E-025-03** — Actual delete, active-wallet fallback, final-wallet onboarding.
- [ ] **E2E-025-04** — Storage failure safe.

## E2E-026 — Switch / Add Wallet
- [ ] **E2E-026-01** — List/activate wallets and active indicator.
- [ ] **E2E-026-02** — Pagination boundaries and maximum slots.
- [ ] **E2E-026-03** — Add Wallet.
- [ ] **E2E-026-04** — Activation failure and back.

## E2E-027 — Add Wallet
- [ ] **E2E-027-01** — Create new 12/24 word wallet.
- [ ] **E2E-027-02** — Restore another wallet.
- [ ] **E2E-027-03** — Distinct slot, slot-full failure, cancel preserves existing wallets.

## E2E-028 — Wallet Backup
- [ ] **E2E-028-01** — View Words.
- [ ] **E2E-028-02** — SeedQR Backup.
- [ ] **E2E-028-03** — Encrypted SD Card.
- [ ] **E2E-028-04** — Advanced.
- [ ] **E2E-028-05** — Back.

## E2E-029 — View Recovery Words
- [ ] **E2E-029-01** — Authenticate where required.
- [ ] **E2E-029-02** — Navigate all words and boundaries.
- [ ] **E2E-029-03** — Return without mutation.
- [ ] **E2E-029-04** — Raw-key mnemonic-only rejection.

## E2E-030 — SeedQR Backup
- [ ] **E2E-030-01** — Compact, standard, and permitted plain-text QR.
- [ ] **E2E-030-02** — QR/grid rendering and pan boundaries.
- [ ] **E2E-030-03** — Close/back.
- [ ] **E2E-030-04** — Raw-key rejection for seed-only backup.

## E2E-031 — Encrypted SD Backup
- [ ] **E2E-031-01** — SD present/absent.
- [ ] **E2E-031-02** — Default/custom filename, password and confirmation.
- [ ] **E2E-031-03** — Mismatch and overwrite cancel/confirm.
- [ ] **E2E-031-04** — Write success/failure/full/read-only.
- [ ] **E2E-031-05** — Generated backup restores successfully.

## E2E-032 — Advanced Backup
- [ ] **E2E-032-01** — Compact SeedQR.
- [ ] **E2E-032-02** — Plain-text SeedQR.
- [ ] **E2E-032-03** — Steganographic backup.
- [ ] **E2E-032-04** — XPrv Backup.
- [ ] **E2E-032-05** — Export Key.
- [ ] **E2E-032-06** — Back.

## E2E-033 — Seed Tools
- [ ] **E2E-033-01** — New Seed, Dice Seed, Touch Seed, Import Words, Address, BIP85 Child, Calculate BIP39 Last Word, Back.

## E2E-034 — BIP85 Child Wallet
- [ ] **E2E-034-01** — Mnemonic-required/raw-key rejection.
- [ ] **E2E-034-02** — 12/24 child, index edit/boundaries, generation and word navigation.
- [ ] **E2E-034-03** — Determinism for same index and divergence across indices.
- [ ] **E2E-034-04** — Back/cancel.

## E2E-035 — BIP39 Last-Word Calculator
- [ ] **E2E-035-01** — 12/24 modes.
- [ ] **E2E-035-02** — Prefix words, valid results, invalid input, edit/back/cancel, result navigation.

## E2E-036 — Wallet Advanced Menu
- [ ] **E2E-036-01** — BIP85 Child Wallet, BIP39 Last Word, Sign Message, Commit Secret, Decrypt Secret, Back.

## E2E-037 — XPrv Backup
- [ ] **E2E-037-01** — Compatible/incompatible wallet sources.
- [ ] **E2E-037-02** — Show as QR and close/back.
- [ ] **E2E-037-03** — Encrypt to SD: filename/password/overwrite/success/no-SD/failure.

## E2E-038 — Export Private Key
- [ ] **E2E-038-01** — Address/index/chain selection and raw-key behavior.
- [ ] **E2E-038-02** — Display only after intended action, QR, close/back.
- [ ] **E2E-038-03** — Invalid index/derivation failure.

## E2E-039 — Single-Signature Menu
- [ ] **E2E-039-01** — Sign TX, Sign Message, Covenant Sign, Commit Secret, Decrypt Secret, Back.
- [ ] **E2E-039-02** — Seed-required actions fail closed without signing key.

## E2E-040 — Transaction Signing Entry
- [ ] **E2E-040-01** — Guide/back/account export/scan.
- [ ] **E2E-040-02** — Compact KSPT and Standard PSKT accepted.
- [ ] **E2E-040-03** — Invalid/unsupported network/version/oversized/truncated/malformed/overflow rejected.

## E2E-041 — Transaction Review
- [ ] **E2E-041-01** — Amount, fee, recipient/output, change.
- [ ] **E2E-041-02** — Every review page forward/back.
- [ ] **E2E-041-03** — UTXO inspection round trip.
- [ ] **E2E-041-04** — Reject/back.
- [ ] **E2E-041-05** — Large/zero/edge values render correctly.

## E2E-042 — UTXO Inspection
- [ ] **E2E-042-01** — Summary and every input outpoint/amount/source address.
- [ ] **E2E-042-02** — Multi-input navigation and final boundary.
- [ ] **E2E-042-03** — Return to review.
- [ ] **E2E-042-04** — Malformed source/address safe failure.

## E2E-043 — Transaction Confirmation
- [ ] **E2E-043-01** — Confirm/cancel/back.
- [ ] **E2E-043-02** — Forged/non-wallet change, body mismatch, arithmetic overflow, policy violation rejection.
- [ ] **E2E-043-03** — No-sign-before/weekly policy deny and allow boundaries.

## E2E-044 — Transaction Signing
- [ ] **E2E-044-01** — Single/multi-input, owned/non-owned handling.
- [ ] **E2E-044-02** — Key derivation/signature failures.
- [ ] **E2E-044-03** — Final signed payload parses and preserves reviewed body.

## E2E-045 — Anti-Klepto Signing
- [ ] **E2E-045-01** — Valid commitment/session/reveal/signature.
- [ ] **E2E-045-02** — Wrong session/secret/reveal/malformed/replay/body mismatch rejection.
- [ ] **E2E-045-03** — Cancel/back and result QR.

## E2E-046 — Signed Result QR
- [ ] **E2E-046-01** — Phone/KasSigner frame size, all density choices.
- [ ] **E2E-046-02** — Auto/manual cycling, all frames, wrap/back/close.
- [ ] **E2E-046-03** — Save to SD success/failure.
- [ ] **E2E-046-04** — Reassembly exact.

## E2E-047 — Sign Message
- [ ] **E2E-047-01** — Type, Scan QR, SD .TXT file, Back.
- [ ] **E2E-047-02** — Typed edit/empty/max/oversized/preview/sign.
- [ ] **E2E-047-03** — QR valid/empty/binary/control/oversized/cancel.
- [ ] **E2E-047-04** — SD list/select/read/too-large/read-failure/no-SD.
- [ ] **E2E-047-05** — Result QR/save/overwrite/failure/back.

## E2E-048 — Commit Secret
- [ ] **E2E-048-01** — Valid/empty/max/over-33 input, edit/back/preview.
- [ ] **E2E-048-02** — Recipient derivation, RNG, ECIES failures.
- [ ] **E2E-048-03** — Success/result QR/close.

## E2E-049 — Decrypt Secret
- [ ] **E2E-049-01** — Scan/cancel/back.
- [ ] **E2E-049-02** — Malformed/wrong-recipient/authentication failure.
- [ ] **E2E-049-03** — Successful plaintext/preimage QR and close/return.

## E2E-050 — Covenant Restore
- [ ] **E2E-050-01** — Raw COVB covenant backup payload is accepted.
- [ ] **E2E-050-02** — Raw COVI covenant backup payload is accepted.
- [ ] **E2E-050-03** — Hex COVB covenant backup payload is accepted.
- [ ] **E2E-050-04** — Hex COVI covenant backup payload is accepted.
- [ ] **E2E-050-05** — Invalid covenant-backup hex is rejected.
- [ ] **E2E-050-06** — Invalid covenant-backup prefix is rejected.
- [ ] **E2E-050-07** — Truncated covenant backup is rejected.
- [ ] **E2E-050-08** — Invalid serialized covenant fields are rejected.
- [ ] **E2E-050-09** — Restored covenant backup can be named.
- [ ] **E2E-050-10** — Restored covenant backup can be saved to SD.
- [ ] **E2E-050-11** — Existing covenant backup overwrite and cancel are safe.
- [ ] **E2E-050-12** — Covenant restore encryption/password flow works where applicable.
- [ ] **E2E-050-13** — No-SD and SD-write failures are surfaced safely.
## E2E-051 — Covenant Signing
- [ ] **E2E-051-01** — KeyInfo covenant-sign request is accepted.
- [ ] **E2E-051-02** — Known covenant-sign mode is accepted.
- [ ] **E2E-051-03** — BindKnown covenant-sign mode is accepted.
- [ ] **E2E-051-04** — Opaque covenant-sign mode is accepted.
- [ ] **E2E-051-05** — BindOpaque covenant-sign mode is accepted.
- [ ] **E2E-051-06** — Mnemonic-backed covenant signing key is accepted.
- [ ] **E2E-051-07** — Raw-key wallet is rejected for covenant signing.
- [ ] **E2E-051-08** — Key-info result is produced.
- [ ] **E2E-051-09** — Key-info result QR is presented.
- [ ] **E2E-051-10** — Every known-context review page is reachable.
- [ ] **E2E-051-11** — Opaque warning is presented.
- [ ] **E2E-051-12** — Opaque warning can be cancelled.
- [ ] **E2E-051-13** — Opaque warning can be continued.
- [ ] **E2E-051-14** — Final confirmation is presented.
- [ ] **E2E-051-15** — Back from final confirmation is safe.
- [ ] **E2E-051-16** — Known request signs.
- [ ] **E2E-051-17** — Known binding request completes.
- [ ] **E2E-051-18** — Opaque request signs.
- [ ] **E2E-051-19** — Opaque binding request completes.
- [ ] **E2E-051-20** — Nonce commitment result is produced.
- [ ] **E2E-051-21** — Nonce QR is presented.
- [ ] **E2E-051-22** — Valid reveal completes signing.
- [ ] **E2E-051-23** — Invalid reveal is rejected.
- [ ] **E2E-051-24** — Wrong session is rejected.
- [ ] **E2E-051-25** — Context/body mismatch is rejected.
- [ ] **E2E-051-26** — Final result QR is presented.
- [ ] **E2E-051-27** — Malformed covenant request is rejected.
## E2E-052 — Private Swap
- [ ] **E2E-052-01** — Private Swap KeyInfo request is accepted.
- [ ] **E2E-052-02** — Private Swap Bind request is accepted.
- [ ] **E2E-052-03** — Private Swap PreSign request is accepted.
- [ ] **E2E-052-04** — Private Swap Complete request is accepted.
- [ ] **E2E-052-05** — Each Private Swap request is reviewed.
- [ ] **E2E-052-06** — Private Swap review can be cancelled/backed out safely.
- [ ] **E2E-052-07** — Private Swap key result QR is presented.
- [ ] **E2E-052-08** — Private Swap nonce commitment QR is presented.
- [ ] **E2E-052-09** — Private Swap reveal scanner is entered.
- [ ] **E2E-052-10** — Valid Private Swap reveal completes.
- [ ] **E2E-052-11** — Invalid Private Swap reveal is rejected.
- [ ] **E2E-052-12** — Private Swap session mismatch is rejected.
- [ ] **E2E-052-13** — Malformed Private Swap request is rejected.
- [ ] **E2E-052-14** — Private Swap final signed/result QR is presented.
- [ ] **E2E-052-15** — Private Swap rejected screen returns safely.
## E2E-053 — Stealth Request
- [ ] **E2E-053-01** — Valid/min/max/invalid candidate counts and invalid length.
- [ ] **E2E-053-02** — No seed/derivation failure/no match/one/multiple match.
- [ ] **E2E-053-03** — Response QR/close/back.

## E2E-054 — Export Menu
- [ ] **E2E-054-01** — Export Menu Seed Backup route is reachable.
- [ ] **E2E-054-02** — Export Menu Watch-Only route is reachable.
- [ ] **E2E-054-03** — Export Menu Signing Keys route is reachable.
- [ ] **E2E-054-04** — Export Menu Steganography route is reachable.
- [ ] **E2E-054-05** — Export Menu Back returns to its documented parent.
## E2E-055 — Watch-Only Export
- [ ] **E2E-055-01** — kpub QR/SD/multisig QR, popup save/back.
- [ ] **E2E-055-02** — Derivation/no-SD/write failures.
- [ ] **E2E-055-03** — Output parses as expected kpub.

## E2E-056 — Multisig Create
- [ ] **E2E-056-01** — M/N increment/decrement/min/max/clamp and start/back.
- [ ] **E2E-056-02** — Cosigner scan/local seed/back/all positions/invalid/duplicate/version metadata.
- [ ] **E2E-056-03** — Local seed picker pagination/raw-key/account incompatibilities and failures.
- [ ] **E2E-056-04** — Address/QR/index/chain/custom-index/save/descriptor/descriptor QR/SD/back.

## E2E-057 — Multisig Import
- [ ] **E2E-057-01** — QR descriptor valid/invalid.
- [ ] **E2E-057-02** — SD address/descriptor valid/invalid.
- [ ] **E2E-057-03** — kpub Multisig QR.
- [ ] **E2E-057-04** — No-SD/read failure.

## E2E-058 — SD Import Menu
- [ ] **E2E-058-01** — Seed/XPrv Backup, Transaction, kpub Watch-Only, Multisig Address, Multisig Descriptor, Covenant Restore, Raw Private Key, Back.

## E2E-059 — Generic SD File Browser
- [ ] **E2E-059-01** — Card present/absent/empty/one file/multi-page.
- [ ] **E2E-059-02** — Page boundaries/select/back/list/read failure/unsupported file.
- [ ] **E2E-059-03** — Delete cancel/hold/commit/failure.

## E2E-060 — Restore Encrypted SD Seed/XPrv
- [ ] **E2E-060-01** — Valid backup/correct password.
- [ ] **E2E-060-02** — Wrong/empty password, corrupt ciphertext/metadata, unsupported version.
- [ ] **E2E-060-03** — Mnemonic/xprv restore, slot-full and activation failures.

## E2E-061 — Transaction Import From SD
- [ ] **E2E-061-01** — Plain/encrypted KSPT, correct/wrong password.
- [ ] **E2E-061-02** — Invalid/oversized/read failure.
- [ ] **E2E-061-03** — Successful import enters identical review/signing flow.

## E2E-062 — SD kpub Import
- [ ] **E2E-062-01** — Valid/invalid/corrupt/unsupported network-version/read failure.

## E2E-063 — Storage Settings
- [ ] **E2E-063-01** — Card present/absent, test success/failure.
- [ ] **E2E-063-02** — Format start/cancel/early release/move-away/full hold/success/failure/no-card.
- [ ] **E2E-063-03** — Back.

## E2E-064 — Device-Bound SD Storage
- [ ] **E2E-064-01** — Open device-bound SD storage setup.
- [ ] **E2E-064-02** — Backup requirement is explained and acknowledged.
- [ ] **E2E-064-03** — Device-bound SD setup can be cancelled.
- [ ] **E2E-064-04** — Enable device-bound storage with a valid SD card.
- [ ] **E2E-064-05** — Successful card binding completes.
- [ ] **E2E-064-06** — Device-bound persistence succeeds.
- [ ] **E2E-064-07** — Device-bound persistence failure fails closed.
- [ ] **E2E-064-08** — Device-bound SD write failure fails closed.
- [ ] **E2E-064-09** — Failure after a partial transition wipes volatile sensitive state safely.
- [ ] **E2E-064-10** — Already-enabled state is read-only or appropriately represented.
- [ ] **E2E-064-11** — Boot succeeds with the bound card.
- [ ] **E2E-064-12** — Boot fails closed without the bound card.
- [ ] **E2E-064-13** — Wrong or replaced card fails closed.
## E2E-065 — Steganographic Backup Entry
- [ ] **E2E-065-01** — Supported carriers, device-bound/portable security.
- [ ] **E2E-065-02** — No mnemonic/raw-key/no-SD failures.
- [ ] **E2E-065-03** — Back/cancel.

## E2E-066 — Steganographic JPEG Selection
- [ ] **E2E-066-01** — List/page/select valid JPEG.
- [ ] **E2E-066-02** — Invalid JPEG/dimensions/read failure/no files/back.

## E2E-067 — Steganographic Description
- [ ] **E2E-067-01** — Type/edit/backspace or load TXT.
- [ ] **E2E-067-02** — Valid/empty/oversized/read-failure TXT.
- [ ] **E2E-067-03** — Preview/back/continue.

## E2E-068 — Steganographic Recovery Hint
- [ ] **E2E-068-01** — No hint/add hint/explanation/custom hint/edit/confirm/back.

## E2E-069 — Portable Steganographic Password
- [ ] **E2E-069-01** — Valid/invalid/too-short password, confirm/mismatch/retry/back.

## E2E-070 — Steganographic Backup Finalization
- [ ] **E2E-070-01** — Review/cancel/back/confirm.
- [ ] **E2E-070-02** — RNG/payload/capacity/JPEG/dimensions/EXIF/SD failures.
- [ ] **E2E-070-03** — Successful valid JPEG and actual recovery round-trip.

## E2E-071 — Steganographic Restore
- [ ] **E2E-071-01** — Valid/invalid stego JPEG.
- [ ] **E2E-071-02** — Descriptor typed/from SD valid/wrong.
- [ ] **E2E-071-03** — Device-bound and portable password paths.
- [ ] **E2E-071-04** — Damaged authentication failure, hint, passphrase, slot/activation failures.
- [ ] **E2E-071-05** — Back/cancel at each pre-commit stage.

## E2E-072 — Settings Main Menu
- [ ] **E2E-072-01** — Display, Audio, Security, Storage, Advanced, About.
- [ ] **E2E-072-02** — Developer entry absent in production.
- [ ] **E2E-072-03** — Pagination and Back to Home.

## E2E-073 — Display Settings
- [ ] **E2E-073-01** — Current value, increment/decrement, min/max/no-op boundaries, intermediate slider.
- [ ] **E2E-073-02** — Real CoreS3 backlight changes and persistence where specified.
- [ ] **E2E-073-03** — Back.

## E2E-074 — Audio Settings
- [ ] **E2E-074-01** — Current value, increment/decrement, min/max/no-op boundaries.
- [ ] **E2E-074-02** — Mute/unmute and real CoreS3 speaker path where promised.
- [ ] **E2E-074-03** — Persistence where specified and Back.

## E2E-075 — Global Audio Control
- [ ] **E2E-075-01** — Mute/unmute header control, icon/state consistency, nearby no-op.

## E2E-076 — Security Settings
- [ ] **E2E-076-01** — Duress credential, No-sign-before UTC, Weekly windows, Device-bound storage, Hardware RTC UTC.
- [ ] **E2E-076-02** — Saved-wallet prerequisites and policy-integrity failure.
- [ ] **E2E-076-03** — Back.

## E2E-077 — Duress Credential
- [ ] **E2E-077-01** — Warning/cancel/continue/credential/invalid/confirmation/mismatch/persistence failure/success.
- [ ] **E2E-077-02** — Already-enabled behavior and reboot normal/duress unlock.

## E2E-078 — Hardware RTC
- [ ] **E2E-078-01** — Display/set/read valid UTC.
- [ ] **E2E-078-02** — Invalid syntax/date, I/O failure, low-voltage/untrusted state, policy read-only behavior, Back.

## E2E-079 — No-Sign-Before Policy
- [ ] **E2E-079-01** — Warning/cancel/continue/RTC unavailable-untrusted.
- [ ] **E2E-079-02** — Valid future timestamp; invalid syntax/date/not-future.
- [ ] **E2E-079-03** — Confirmation/cancel/persistence/success/read-only.
- [ ] **E2E-079-04** — Reject before threshold; allow exactly at/after threshold.

## E2E-080 — Weekly Signing Windows
- [ ] **E2E-080-01** — Warning/cancel/continue/RTC unavailable-untrusted.
- [ ] **E2E-080-02** — One/multiple/max windows; invalid syntax/day/time/overlap/too many.
- [ ] **E2E-080-03** — Confirmation/persistence/success/read-only.
- [ ] **E2E-080-04** — Allow inside, reject outside, exact start/end boundaries.

## E2E-081 — Advanced Settings
- [ ] **E2E-081-01** — Firmware Update.
- [ ] **E2E-081-02** — Pop It! only when Secure Boot v2 is not enabled; hidden otherwise.
- [ ] **E2E-081-03** — Back.
- [ ] **E2E-081-04** — Owner Firmware opens a dedicated submenu with Enroll Owner Key and Install from SD.
- [ ] **E2E-081-05** — Owner Firmware warning/confirmation screens cancel and return without mutating security state.

## E2E-082 — Pop It! and Owner-Authority Secure-Boot Flow
- [ ] **E2E-082-01** — No/Explain/return/Yes.
- [ ] **E2E-082-02** — Confirmation accepts pop it / POP IT / pop-it and optional !; rejects unrelated text.
- [ ] **E2E-082-03** — Back/cancel.
- [ ] **E2E-082-04** — Compatibility/key/digest/preparation/persistence failures.
- [ ] **E2E-082-05** — Simulated success/restart.
- [ ] **E2E-082-06** — Automated QA can never burn a real eFuse.
- [ ] **E2E-082-07** — Pop It! warns that owner-key enrollment must happen first and that enabling Secure Boot permanently closes later enrollment.
- [ ] **E2E-082-08** — OWNERKEY.KAS validation, typed ENROLL OWNER confirmation, and development simulation perform no eFuse mutation.
- [ ] **E2E-082-09** — Production owner enrollment preflights the official boot chain, consumes the one-shot request, enrolls official digest slot 0 and owner digest slot 1, closes slot 2, and protects the trusted-key revoke controls.
- [ ] **E2E-082-10** — OWNERFW.BIN installation requires enabled Secure Boot and enrolled owner authority, exact owner-key Secure Boot v2 signature verification, valid ESP image verification, and hardware anti-rollback acceptance before OTA selection changes.
- [ ] **E2E-082-11** — Failed owner-firmware installation leaves the previously selected OTA intact; successful installation selects only the fully verified inactive OTA.
- [ ] **E2E-082-12** — OWNERKEY.KAS carries only the owner public-key digest and checksum; the owner RSA private key is never required on the device or enrollment media.

## E2E-083 — Firmware Update
- [ ] **E2E-083-01** — Settings → Firmware Update opens USB-host guidance, not a firmware scanner.
- [ ] **E2E-083-02** — Guidance identifies the supported USB-host update path and returns safely with Back.
- [ ] **E2E-083-03** — Firmware-update QR payloads are rejected with explicit USB guidance.
- [ ] **E2E-083-04** — Runtime QR/SD firmware parsing, hashing, verification, and flash-install modules remain absent.
- [ ] **E2E-083-05** — Signed release manifest binds product, board, channel, package version, update sequence, and hardware anti-rollback epoch.
- [ ] **E2E-083-06** — Firmware signature verification uses the shared BIP340 release public key and rejects invalid signatures.
- [ ] **E2E-083-07** — Release-sequence downgrade policy is enforced.
- [ ] **E2E-083-08** — Hardware anti-rollback policy is enforced by the boot chain.
- [ ] **E2E-083-09** — Verified image hash must match the signed release identity.
- [ ] **E2E-083-10** — Partition-layout hash is bound to the signed release manifest.
- [ ] **E2E-083-11** — Verified firmware image/code-segment size remains bounded before acceptance.
- [ ] **E2E-083-12** — Production host release tooling refuses unsigned/missing-key release construction.
- [ ] **E2E-083-13** — Production release tooling preserves secure-boot signing/provisioning policy.
- [ ] **E2E-083-14** — Boot-time verifier and release generator share compatible BIP340 signing vectors.
- [ ] **E2E-083-15** — Back/cancel from device guidance performs no firmware mutation.
- [ ] **E2E-083-16** — Supported update success path is host-assisted USB flashing of a verified signed release.
- [ ] **E2E-083-17** — Safe HIL can reboot into a verified signed test image flashed through the supported USB path.
## E2E-084 — About
- [ ] **E2E-084-01** — Package version, board, and hardware-security state.
- [ ] **E2E-084-02** — No secret data.
- [ ] **E2E-084-03** — Back.

## E2E-085 — QR Presentation Controls
- [ ] **E2E-085-01** — Single/multi-frame, phone/KasSigner framing, all densities.
- [ ] **E2E-085-02** — Auto/manual cycling, first/last/wrap, back/close.
- [ ] **E2E-085-03** — Corresponding parser round-trip and no stale previous frames.

## E2E-086 — SeedQR Grid/Panning
- [ ] **E2E-086-01** — Initial position, all four directions, every edge boundary, repeated boundary no-op, close.

## E2E-087 — All Keyboard Types
- [ ] **E2E-087-01** — Alpha/full: pages/case/backspace/clear/submit/back/max/empty.
- [ ] **E2E-087-02** — Numeric: 0–9/delete/clear/submit/length/overflow.
- [ ] **E2E-087-03** — Hex: 0–9/a–f/uppercase/backspace/exact length/invalid rejection.
- [ ] **E2E-087-04** — PIN: 0–9/DEL/OK/min/max.

## E2E-088 — Generic Menu Behavior
- [ ] **E2E-088-01** — Every visible item selectable and routes correctly.
- [ ] **E2E-088-02** — Back/Home, first/last page, page up/down, outside-touch no-op.
- [ ] **E2E-088-03** — One touch causes one action and no stale touch replay.

## E2E-089 — Generic Scalar Controls
- [ ] **E2E-089-01** — Increment/decrement/min/max/no underflow/overflow/intermediate.
- [ ] **E2E-089-02** — State and rendered value remain synchronized.

## E2E-090 — Destructive Hold Controls
- [ ] **E2E-090-01** — Start/progress/early release/move-away/re-entry/full hold exactly once.
- [ ] **E2E-090-02** — Back/cancel prevents mutation.

## E2E-091 — Universal Navigation Integrity
- [ ] **E2E-091-01** — Every production state renders without panic.
- [ ] **E2E-091-02** — Every control reachable and dispatches exactly once.
- [ ] **E2E-091-03** — Back/Home/redraw/state model/transient reset/no-input-leak.
- [ ] **E2E-091-04** — No route reaches developer-only state.

## E2E-092 — Universal Missing-Key/Wallet Errors
- [ ] **E2E-092-01** — No active wallet fails closed.
- [ ] **E2E-092-02** — No mnemonic when mnemonic is required fails closed.
- [ ] **E2E-092-03** — Raw key supplied where an HD mnemonic is required fails closed.
- [ ] **E2E-092-04** — Missing cached public key fails closed.
- [ ] **E2E-092-05** — Key derivation failure fails closed.
- [ ] **E2E-092-06** — Wallet slots full fails closed.
- [ ] **E2E-092-07** — Inactive/deleted wallet reference fails closed.
- [ ] **E2E-092-08** — Every missing-key/wallet failure offers a sane return route.
## E2E-093 — Universal SD Failure Matrix
- [ ] **E2E-093-01** — No/unmountable/empty/corrupt/read-only/full card.
- [ ] **E2E-093-02** — File not found/read/write/rename/overwrite/malformed/oversized/interruption.
- [ ] **E2E-093-03** — No sensitive plaintext artifact remains incomplete.

## E2E-094 — Universal Camera/QR Failure Matrix
- [ ] **E2E-094-01** — Camera unavailable/init failure/no QR/unrecognized/damaged/oversized/truncated/wrong context.
- [ ] **E2E-094-02** — Cancel/back and clean re-entry.

## E2E-095 — Universal Cryptographic Failure Matrix
- [ ] **E2E-095-01** — Invalid private/public key/signature/checksum/path/index/ciphertext/password/nonce/reveal/session/body/descriptor/change/randomness/arithmetic/version.
- [ ] **E2E-095-02** — Failure occurs before sensitive/signing output is released.

## E2E-096 — Persistence and Reboot Verification
- [ ] **E2E-096-01** — Persist promised settings/state across reboot; nonpersistent secrets disappear.
- [ ] **E2E-096-02** — Corrupt persisted representation fails closed.
- [ ] **E2E-096-03** — Safe pre-commit power interruption leaves consistent state.
- [ ] **E2E-096-04** — Wallet selection, display/audio, security policies, duress, and device-bound storage as specified.

## E2E-097 — Production Security Surface
- [ ] **E2E-097-01** — Developer Menu, Workflow Tests, diagnostics, entropy shortcuts unreachable.
- [ ] **E2E-097-02** — Test public fixture and any test seed/private key absent in production.
- [ ] **E2E-097-03** — Automated eFuse simulator absent from production behavior.
- [ ] **E2E-097-04** — Watch-only companion cannot authorize spending.
- [ ] **E2E-097-05** — Security policies fail closed and wireless remains locked down.

## E2E-098 — Physical CoreS3 Hardware Interaction
- [ ] **E2E-098-01** — LCD representative screens; real brightness.
- [ ] **E2E-098-02** — Capacitive touchscreen coordinates including corners/center/edge controls.
- [ ] **E2E-098-03** — Speaker init/volume/mute.
- [ ] **E2E-098-04** — Camera single/multi-frame QR.
- [ ] **E2E-098-05** — IMU entropy, SD I/O/removal, RTC, PMU/battery.
- [ ] **E2E-098-06** — One peripheral failure does not deadlock unrelated UI.

## E2E-099 — Production-State Exhaustiveness Gate
- [ ] **E2E-099-01** — Enumerate every production M5Stack AppState and require scenario ownership.
- [ ] **E2E-099-02** — Enumerate every production transition and visible control.
- [ ] **E2E-099-03** — Enumerate every explicit error/result state.
- [ ] **E2E-099-04** — CI fails on new production state/menu/action without E2E coverage.
- [ ] **E2E-099-05** — CI fails on new QR type/destructive action/security policy without required tests.

## E2E-100 — Complete User Journeys
- [ ] **E2E-100-01** — Fresh device → create 12-word wallet → save with PIN → Receive.
- [ ] **E2E-100-02** — Fresh device → create 24-word wallet → password → backup → Receive.
- [ ] **E2E-100-03** — Fresh device → restore 12 words → unlock → sign transaction.
- [ ] **E2E-100-04** — Fresh device → restore 24 words + BIP39 passphrase → sign.
- [ ] **E2E-100-05** — Restore SeedQR → verify address.
- [ ] **E2E-100-06** — Restore encrypted SD backup → verify address.
- [ ] **E2E-100-07** — Import raw private key → Receive → sign supported operation.
- [ ] **E2E-100-08** — Create second wallet → switch between wallets → verify different addresses.
- [ ] **E2E-100-09** — Create wallet → Connect KasSee → export kpub.
- [ ] **E2E-100-10** — Create wallet → backup SeedQR → restore that backup → verify identical address.
- [ ] **E2E-100-11** — Create wallet → encrypted SD backup → delete wallet → restore backup → verify identical address.
- [ ] **E2E-100-12** — Create stego backup → delete wallet → stego restore → verify identical address.
- [ ] **E2E-100-13** — Receive → custom address index → QR.
- [ ] **E2E-100-14** — Scan valid transaction → inspect every UTXO → confirm → sign → result QR.
- [ ] **E2E-100-15** — Scan transaction → reject.
- [ ] **E2E-100-16** — Scan transaction with forged change → fail closed.
- [ ] **E2E-100-17** — Anti-klepto transaction → commitment → reveal → signed result.
- [ ] **E2E-100-18** — Sign typed message → result QR.
- [ ] **E2E-100-19** — Sign scanned message → result QR.
- [ ] **E2E-100-20** — Sign message loaded from SD → save signature to SD.
- [ ] **E2E-100-21** — Commit secret → export → decrypt secret → verify round trip.
- [ ] **E2E-100-22** — Create multisig → mix local and scanned cosigners → address → descriptor → save.
- [ ] **E2E-100-23** — Restore/import multisig descriptor → reproduce same address.
- [ ] **E2E-100-24** — Configure no-sign-before → attempt too early → advance verified time → sign successfully.
- [ ] **E2E-100-25** — Configure weekly window → reject outside window → succeed inside window.
- [ ] **E2E-100-26** — Enable device-bound SD storage → reboot with card → unlock.
- [ ] **E2E-100-27** — Enable device-bound SD storage → reboot without card → fail closed.
- [ ] **E2E-100-28** — Configure duress credential → reboot → exercise normal and duress credentials.
- [ ] **E2E-100-29** — Perform safe simulated Pop It! sequence.
- [ ] **E2E-100-30** — Perform verified firmware-update test using dedicated safe test image.
- [ ] **E2E-100-31** — Reboot after all persistent changes and verify final expected device state.
- [ ] **E2E-100-32** — Enroll an owner key before Pop It!, enable Secure Boot, install an owner-signed application, and verify that official vendor-signed application firmware remains bootable.
## Definition of Done
- [ ] **DOD-01** — Every production AppState is covered.
- [ ] **DOD-02** — Every production user-triggerable transition and visible control is exercised.
- [ ] **DOD-03** — Every meaningful boundary and security-relevant rejection path is covered.
- [ ] **DOD-04** — Every deterministically inducible user-visible error is covered.
- [ ] **DOD-05** — Every QR/export format round-trips through its corresponding parser/importer.
- [ ] **DOD-06** — Every destructive action tests cancel and commit.
- [ ] **DOD-07** — Every persistent setting is verified across reboot.
- [ ] **DOD-08** — Every hardware-backed feature has actual hardware evidence, not only injected controller state.
- [ ] **DOD-09** — Production and QA/developer surfaces remain separated.
- [ ] **DOD-10** — CI detects future uncovered production states/actions.
- [ ] **DOD-11** — Final physical CoreS3 suite completes without panic, deadlock, timeout, state mismatch, or unexpected user-visible error.
