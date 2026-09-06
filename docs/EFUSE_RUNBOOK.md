<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner — ESP32-S3 eFuse / Secure Boot Runbook

> **IRREVERSIBLE OPERATIONS.** ESP32-S3 eFuses are one-time programmable. A wrong key purpose, digest, revocation bit, protection bit, encryption setting, or download-mode setting can permanently remove recovery/update options. Rehearse every destructive policy on a sacrificial CoreS3 first.

KasSigner pins **ESP-IDF v6.0.2** in `qa/config/toolchains.env` and **esptool/espsecure/espefuse 5.3.1** in `apps/signer-firmware/release-policy.env`. For an actual burn, those pinned ESP32-S3 tool semantics and the captured pre-burn eFuse state are the source of truth. Never copy a key-block number or burn sequence from another ESP32 family.

This document describes **four distinct firmware/profile classes**. They must not be conflated:

| Firmware | Pop It!/Owner UI | Automatic eFuse provisioning at ordinary boot | Secure Boot authority after provisioning |
|---|---|---|---|
| `make release` / normal `m5stack,production` | **Not compiled** | **None** | None added by the firmware |
| Development (`make flash`) | Present as simulation | **None** | None; simulation never burns eFuses |
| `m5stack,secure-provisioning` | Present | **None until explicit Owner/Pop It action** | Vendor digest 0, optionally owner digest 1 |
| `m5stack,secure-owner-only` | Present | **None until explicit Owner/Pop It action** | **Owner digest 0 only; vendor is not trusted** |

The `secure-owner-only` profile restores the original KasSigner ownership model: the purchaser/operator supplies the RSA-3072 key and, after explicit enrollment and Pop It, that key is the **sole hardware Secure Boot authority**. The newer `secure-provisioning` profile is an addition that supports vendor authority plus an optional independent owner authority.

The automated `secure-provisioning` and `secure-owner-only` profiles are **CoreS3-only** and the firmware feature policy rejects them on other board profiles. The external/manual reference later in this runbook explains ESP32-S3 eFuse semantics; it is not a claim that an unqualified board has passed KasSigner's production HIL process.

## 1. Security layers and what they mean

ESP32-S3 Secure Boot v2 uses RSA-PSS/RSA-3072 signatures. The ROM authenticates the second-stage bootloader from public-key digest(s) in eFuse, and the Secure-Boot-enabled second-stage bootloader authenticates applications. ESP32-S3 supports three Secure Boot digest indices, numbered 0 through 2.

Flash Encryption is separate. It protects selected flash contents from straightforward plaintext extraction. Hardware anti-rollback (`SECURE_VERSION`) is separate again. KasSigner's ordinary release additionally uses an application-level Schnorr signature, but that software signature is **not** a substitute for an immutable ROM trust root.

The owner-only provisioning image intentionally does **not** depend on the vendor Schnorr private key. Before Pop It there is no immutable vendor root to claim: the image still performs its generated code-hash/flow checks, while the special signed bootloader verifies the exact bootloader and application RSA signatures against the owner's selected RSA key before any owner-only Secure Boot transition is committed. After Pop It, hardware Secure Boot is authoritative.

## 2. Key policies

### Dual-authority profile: `secure-provisioning`

If the owner enrolls an owner key before Pop It, the intended final Secure Boot digest policy is:

| Digest index | State | Authority |
|---|---|---|
| 0 | live and protected | vendor RSA-3072 Secure Boot key |
| 1 | live and protected | enrolled owner RSA-3072 key |
| 2 | revoked | none |

The profile also permits Pop It without owner enrollment. In that case Secure Boot is vendor-only and owner enrollment is permanently closed afterward.

### Owner-only profile: `secure-owner-only`

The intended final Secure Boot digest policy is:

| Digest index | State | Authority |
|---|---|---|
| 0 | live; revoke control protected | **owner RSA-3072 key** |
| 1 | **revoked** | none |
| 2 | **revoked** | none |

There is **no vendor Secure Boot digest** in this policy. Pop It is blocked until the owner key has been explicitly enrolled. Enrollment verifies that `OWNERKEY.KAS` matches the RSA key that signed the special owner-only bootloader/application, burns that digest as `SECURE_BOOT_DIGEST0`, revokes digest indices 1 and 2, and protects the digest-0 revoke control. This is irreversible and is the restored original owner-only behavior.

A Secure Boot digest index is not the same thing as a fixed physical `BLOCK_KEYn`. ESP-IDF may place a digest into a free eligible key block and assign that block the corresponding `SECURE_BOOT_DIGESTn` purpose. Record the actual block allocation from the device rather than assuming `DIGEST0 == BLOCK_KEY0`.

## 3. Nothing destructive happens merely because the special firmware boots

Both special provisioning profiles are designed so they can be flashed and used normally for as long as desired before provisioning. Ordinary boot, reset, wallet use, and navigation must not automatically initialize Flash Encryption, enable Secure Boot, switch ROM Download mode, or advance hardware anti-rollback eFuses.

The only application actions allowed to request irreversible transitions are explicit, typed user actions:

- **Owner Firmware → Enroll Owner Key** — may burn the profile's Secure Boot digest/revocation policy while Secure Boot is still disabled.
- **Pop It!** — after typed `POP IT`, may initialize/enable release-mode Flash Encryption, switch to Secure Download mode, enable Secure Boot v2, and permit later hardware anti-rollback advancement.

The Rust application does not directly write these eFuses. It records a checksummed one-shot command and software-resets. The specially built ESP-IDF second-stage bootloader performs final image/key/state checks and owns the irreversible operation. The command is consumed so old consent cannot be replayed on later ordinary boots.

The special bootloader is compiled with Secure Boot v2 support (`CONFIG_SECURE_BOOT=y` and `CONFIG_SECURE_BOOT_V2_ENABLED=y`), but KasSigner patches the ESP-IDF startup path so those build-time settings do **not** authorize an ordinary pre-Pop boot to burn provisioning eFuses. Application images are secure-padded by `tools/build/firmware/secure_pad_v2.py` before RSA-PSS signing and verification.

## 4. Build the special provisioning artifacts — no hardware is touched

These commands build/sign files only. They do not flash a board and do not burn eFuses. The public `make` targets dispatch to native Windows PowerShell or POSIX tooling; they are intentionally separate from `make release` and `make flash-release`.

### Dual authority

Keep the vendor RSA Secure Boot key and the 32-byte vendor Schnorr release key offline/outside the repository:

```bash
make secure-provisioning \
  SECURE_BOOT_KEY=/secure/vendor-secure-boot-rsa3072.pem \
  SIGNING_KEY=/secure/vendor-schnorr-release.key \
  SECURE_DIR=target/secure-provisioning
```

The produced special application uses the `m5stack,secure-provisioning` feature profile. The bootloader/application RSA signatures are bound to the selected vendor Secure Boot key. Optional owner enrollment later adds the independent owner digest as slot 1.

### Owner only — restored original ownership model

Generate/hold the owner's RSA-3072 key outside the repository. For example, using the pinned Espressif tooling:

```bash
espsecure generate-signing-key --version 2 --scheme rsa3072 owner-secure-boot.pem
```

Then prepare the owner-only chain:

```bash
make secure-owner-only \
  OWNER_KEY=/secure/owner-secure-boot.pem \
  SECURE_DIR=target/secure-owner-only
```

This path:

1. builds `m5stack,secure-owner-only` without a vendor Schnorr signing key;
2. signs the special second-stage bootloader and special application with the **owner RSA key**;
3. derives the exact owner Secure Boot v2 public-key digest;
4. writes `OWNERKEY.KAS` containing that digest plus integrity metadata; and
5. records `TRUST-POLICY=owner-only` / `AUTHORITY-MODE=owner-only` in the artifact set.

Use a dedicated output directory for each trust policy. The preparation wrapper refuses to reuse an output directory whose `TRUST-POLICY` names the other mode, and owner-only preparation refuses a directory containing a stale vendor-authorized KSFU manifest.

It intentionally does **not** emit a vendor-Schnorr KSFU manifest. After owner-only provisioning, application updates are owner-authorized and can be produced through `make owner-firmware OWNER_KEY=/secure/owner-secure-boot.pem` for the SD `OWNERFW.BIN` path.

The private RSA key is never copied into `OWNERKEY.KAS`, firmware, or the device.

## 5. Preflight before any irreversible action

Before owner enrollment or Pop It:

- Verify the exact target is the intended ESP32-S3 CoreS3 and record its identity.
- Boot the exact special provisioning bootloader/application repeatedly and verify normal use does not alter eFuse state.
- Capture `espefuse --chip esp32s3 --port PORT summary` before the first burn.
- Stop if any security eFuse/key purpose differs from the policy you intended.
- Back up every private key needed by the selected policy and verify the backups can be restored.
- Decide all required key-block consumers first, including Flash Encryption and Device-bound-storage `HMAC_UP` keys.
- Provision any key that must become read-protected **before** the final Secure Boot/`RD_DIS` protection sequence can prevent later read protection.
- Never mix the in-device Pop It workflow with a partially completed external-manual Secure Boot workflow unless a sacrificial-board procedure explicitly validates that mixed state.

Host-side eFuse commands in repository procedures must pass through `qa/checks/release/irreversible_action_ack.py`, which requires interactive acknowledgement and exact target re-entry. Read-only inspection does not need that wrapper.

## 6. On-device dual-authority sequence

1. Flash the prepared dual-authority special boot chain by the tested HIL/manufacturing process.
2. Use it normally and verify eFuses remain unchanged.
3. If independent owner firmware is desired, create `OWNERKEY.KAS`/`OWNERFW.BIN` from the owner's RSA key and choose **Settings → Advanced → Owner Firmware → Enroll Owner Key**.
4. Read the irreversible warning and type `ENROLL OWNER`.
5. After reboot, verify the device reports owner authority enrolled. The bootloader should have established vendor digest 0, owner digest 1, revoked digest 2, and protected the trusted revoke controls.
6. When ready, choose **Settings → Advanced → Pop It!**, read the warning, and type `POP IT`.
7. The bootloader re-validates its configured RSA authority and current selected application before performing the request-gated irreversible security transition.

If step 3 is skipped, dual-authority Pop It explicitly allows vendor-only provisioning and permanently closes later owner enrollment.

## 7. On-device owner-only sequence

1. Flash the special bootloader/application generated with `--owner-only` and the intended owner RSA private key.
2. Use the device normally for as long as desired. Verify no provisioning eFuse changes occur merely from boot/use.
3. Put the generated `OWNERKEY.KAS` on SD.
4. Choose **Settings → Advanced → Owner Firmware → Enroll Owner Key**.
5. Read the warning that this owner key will be the **sole** Secure Boot authority and type `ENROLL OWNER`.
6. The bootloader verifies the running bootloader/application against the same expected owner RSA key and verifies that the enrollment record matches it. It also refuses owner-only conversion if digest slot 1 or 2 already contains a live alternate Secure Boot authority; it will not silently revoke a previously trusted key. Only then may it burn owner digest 0, revoke empty digest indices 1 and 2, and protect digest 0's revoke control.
7. Reboot and verify the owner-only digest/revocation state before proceeding.
8. Choose **Settings → Advanced → Pop It!** and type `POP IT` only when ready for the remaining irreversible hardware transition. **Owner-only Pop It refuses to continue unless owner enrollment is already present.** There is no “Continue Without It” path.
9. The bootloader again verifies the boot chain against the owner key, then performs the request-gated Flash Encryption / Secure Download / Secure Boot transition.
10. After Secure Boot is active, prove an owner-signed `OWNERFW.BIN` is accepted and an image signed only by the vendor or an unrelated RSA key is rejected.

After this sequence, the vendor does not possess a hardware-authorized signing key unless the owner independently chose to give the vendor their private key. Normal vendor release firmware cannot satisfy the owner-only Secure Boot root by itself.

## 8. What Pop It commits

For either special profile, Pop It is the final security transition and is separate from owner enrollment. The patched bootloader keeps ESP-IDF's irreversible startup paths deferred until the one-shot request is present.

During a valid Pop It request it:

1. verifies the installed second-stage bootloader and selected application against the profile's exact expected RSA authority;
2. in owner-only mode, verifies the sole-owner digest policy is already enrolled;
3. initializes/enables Flash Encryption in the configured Release Mode if it is not already enabled;
4. consumes the one-shot Pop It request;
5. switches ROM UART into Secure Download mode where supported/configured;
6. permanently enables Secure Boot v2; and
7. allows hardware anti-rollback advancement only after Secure Boot is hardware-enabled.

Any failure aborts the sequence; however, eFuse operations are intrinsically non-transactional, so power loss during an irreversible transition is why sacrificial-board testing and stable power are mandatory.

## 9. Owner firmware after Pop It

`make owner-firmware OWNER_KEY=/secure/owner.pem` creates the owner-authorized update without inheriting or embedding any `KASSIGNER_SIGNING_KEY` from the caller's environment:

- `OWNERKEY.KAS` — public Secure Boot digest + integrity metadata;
- `OWNERFW.BIN` — Secure-Boot-v2-padded application signed by that RSA key; and
- hashes for transfer verification.

For dual-authority devices, the bootloader requires `OWNERFW.BIN` to match **owner digest 1**. For owner-only devices, it requires **owner digest 0**. The staged image must also satisfy image-format, hash, OTA, and anti-rollback policy before it is selected.

Owner firmware is application firmware. This SD workflow does not replace the second-stage bootloader.

## 10. External/manual owner-only Secure Boot reference

The original repository documented an external process where the user generated the Secure Boot key, burned it as digest 0, revoked unused digest slots, signed the bootloader/application, then enabled Secure Boot. That ownership property is preserved by `secure-owner-only`; the on-device workflow adds guarded consent and exact-image checks.

For a deliberately external/manual policy, current Espressif tooling provides the `burn-key-digest` command family. A representative guarded command is:

```bash
python3 qa/checks/release/irreversible_action_ack.py \
  --action "Burn owner Secure Boot digest 0" \
  --device PORT -- \
  espefuse --chip esp32s3 --port {device} \
    burn-key-digest BLOCK_KEYn owner-secure-boot.pem SECURE_BOOT_DIGEST0
```

Choose `BLOCK_KEYn` from the actual free-block allocation; do not assume a fixed physical block. `burn-key-digest` programs the public-key digest with the Secure Boot digest purpose and protects the key material/purpose according to the tool's policy. The digest itself must remain readable to Secure Boot hardware.

The original manual runbook also allowed an **optional second owner-held backup RSA key** in digest 1. That remains an external/manual owner-only variant (both live authorities are controlled by the owner), but the automated `secure-owner-only` profile deliberately implements the stricter one-key final policy used by the original runbook's recommended locked-down configuration: owner digest 0 is live and digest indices 1 and 2 are revoked. Do not expect the automated profile to leave a backup slot open.

With exactly one intended owner key, the unused Secure Boot digest indices must be closed:

```bash
python3 qa/checks/release/irreversible_action_ack.py \
  --action "Revoke unused Secure Boot digest 1" --device PORT -- \
  espefuse --chip esp32s3 --port {device} burn-efuse SECURE_BOOT_KEY_REVOKE1

python3 qa/checks/release/irreversible_action_ack.py \
  --action "Revoke unused Secure Boot digest 2" --device PORT -- \
  espefuse --chip esp32s3 --port {device} burn-efuse SECURE_BOOT_KEY_REVOKE2
```

Only after the exact signed bootloader/application and all other required key provisioning have been verified should an external procedure enable Secure Boot:

```bash
python3 qa/checks/release/irreversible_action_ack.py \
  --action "Permanently enable Secure Boot v2" --device PORT -- \
  espefuse --chip esp32s3 --port {device} burn-efuse SECURE_BOOT_EN
```

Do not use these manual commands on a board already being provisioned by the in-device owner/Pop It workflow unless the HIL procedure specifically calls for it.

## 11. Flash Encryption, HMAC storage, debug and download eFuses

Device-bound wallet storage may require one independently generated 256-bit key in a free eligible block with purpose `HMAC_UP`, read-protected. Flash Encryption consumes its own eligible key block(s), depending on the configured XTS mode. Settle the complete key-block allocation before burning anything.

When using an external combined Secure Boot + Flash Encryption workflow, follow the pinned ESP-IDF v6.0.2 ESP32-S3 ordering rather than manually inventing `SPI_BOOT_CRYPT_CNT` values. Keys needing read protection must be provisioned before Secure Boot's final protection of relevant read-disable controls.

Debug/download lockdown is product-policy-specific. Relevant ESP32-S3 controls include pad JTAG disable, USB-JTAG disable, direct-boot disable, and Secure Download mode. Do not burn `DIS_DOWNLOAD_MODE` as a generic hardening shortcut: it can remove the ROM recovery path entirely. The special Pop It flow uses Secure Download mode rather than automatically disabling ROM download mode.

Once Secure Download mode is active, arbitrary host `espefuse` access is intentionally restricted. Capture complete pre-lock evidence first.

## 12. Required sacrificial-board evidence

For **each** special profile that will be shipped/provisioned, prove at minimum:

- repeated ordinary pre-Pop boots do not change provisioning eFuses;
- malformed/substituted enrollment records fail;
- wrong RSA bootloader/application authority fails the irreversible preflight;
- owner enrollment occurs only after explicit typed confirmation;
- the exact digest/revocation policy matches the selected profile;
- Pop It occurs only after explicit typed confirmation;
- Secure Boot and Flash Encryption are active afterward;
- a one-byte-modified/unsigned/wrong-key application is rejected;
- lower-security-version application images are rejected by the boot chain;
- a valid owner application is accepted at the correct owner digest index; and
- the previously selected OTA application remains bootable after a rejected staged owner image.

For **owner-only**, additionally prove:

- digest 0 equals the expected owner key;
- digest indices 1 and 2 are revoked;
- no vendor digest is trusted;
- Pop It cannot bypass owner enrollment; and
- a vendor-only signed application is rejected after hardware enforcement.

For **dual authority**, separately prove the vendor+owner case and the deliberate vendor-only Pop It case.

See `qa/release/M5STACK_SECURITY_HIL.md` for the release-evidence checklist.

## 13. Verification record and recovery consequences

Before lockdown, retain a full eFuse summary plus hashes of the exact bootloader, partition table, application, trust-policy marker, and enrollment record used. The record must identify actual physical key-block allocation, key purposes, Secure Boot digest index/revocation states, Flash Encryption state, `SECURE_VERSION`, and the approved debug/download posture.

There is no general recovery from an incorrect eFuse configuration:

- If every private key corresponding to a live Secure Boot digest is lost, existing valid firmware can continue to boot but new authorized firmware cannot be produced for that trust root.
- In **owner-only** mode, loss of the sole owner key removes future owner-authorized updates; the vendor cannot rescue the device with a separate vendor signing key because no vendor digest is trusted.
- In **owner-only** mode, compromise of the sole owner key is likewise serious: the configured sole authority is permanent under this policy because digest 0's revoke control is protected and unused authority slots are closed.
- In **dual-authority** mode, loss of the owner key still leaves vendor-authorized applications available; loss of the vendor key may still leave owner-authorized applications available. The configured protected trusted authorities cannot be silently removed by later application firmware.
- Loss of required Flash Encryption/HMAC/recovery keys can make procedures depending on those keys impossible.
- Permanently disabling download mode can eliminate physical recovery even when a signing key still exists.

Treat the owner-only private key as a long-term device ownership credential and maintain verified offline backups before enrollment.
