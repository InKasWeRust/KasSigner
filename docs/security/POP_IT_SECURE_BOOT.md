<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# Pop It! and owner-authorized firmware

`Pop It!` is compiled only into development firmware (non-destructive simulation) and the two opt-in M5Stack CoreS3 provisioning profiles. The normal `make release` / `make flash-release` production image does not compile the Pop It!/owner-authority UI, request staging, or irreversible provisioning path.

The production provisioning profiles are deliberately different:

- **`secure-provisioning`** — vendor RSA Secure Boot authority, plus an optional independently held owner RSA authority.
- **`secure-owner-only`** — restored original ownership model. The owner's RSA key is the **sole** Secure Boot authority; no vendor Secure Boot digest remains trusted.

Neither profile performs irreversible provisioning merely because it boots. Owner enrollment and Pop It are explicit user actions.

## Trust states

KasSigner displays the boot-trust state in the navigation badge:

- **Software verified** — applicable signed release software checks passed, but ROM Secure Boot is not yet enabled.
- **Hardware enforced** — `SECURE_BOOT_EN` is active and the ESP32-S3 ROM enforces the fused Secure Boot policy.
- **Not verified** — the firmware does not claim either of those states.

The owner-only special image intentionally does not claim a vendor software-signing authority before Pop It. Until a hardware trust root is fused, physical flash replacement can replace both application and second-stage bootloader. The owner-only bootloader therefore performs exact RSA authority checks immediately before irreversible enrollment/Pop It transitions.

## Dual-authority enrollment

With `secure-provisioning`, owner enrollment is optional. Before Pop It the owner may generate an RSA-3072 key, produce `OWNERKEY.KAS`, and choose **Settings → Advanced → Owner Firmware → Enroll Owner Key**. The typed `ENROLL OWNER` confirmation arms a one-shot bootloader request.

Successful enrollment establishes:

- digest 0 — vendor RSA Secure Boot authority;
- digest 1 — owner RSA Secure Boot authority;
- digest 2 — revoked/closed.

The trusted revoke controls for the live authorities are protected. If Pop It is completed without owner enrollment, the device deliberately becomes vendor-only and later owner enrollment is closed.

## Owner-only enrollment

With `secure-owner-only`, the build itself is signed with the owner's RSA-3072 key and emits a matching `OWNERKEY.KAS`. There is no vendor RSA authority and no vendor Schnorr release key requirement for this special image.

Before Pop It the user must choose **Owner Firmware → Enroll Owner Key** and type `ENROLL OWNER`. The bootloader checks that:

1. the installed second-stage bootloader is signed by the exact expected owner key;
2. the selected application is signed by that same owner key; and
3. `OWNERKEY.KAS` contains that same public-key digest.

Only then may it establish the sole-owner eFuse policy:

- digest 0 — owner RSA Secure Boot authority;
- digest 1 — revoked;
- digest 2 — revoked;
- digest-0 revoke control — write-protected.

The owner-only Pop It screen does **not** provide `Continue Without It`. Pop It is refused until this owner authority is enrolled.

## Pop It is Settings-only

Neither production provisioning profile prompts automatically at first boot. The owner deliberately opens **Settings → Advanced → Pop It!**.

Before the final transition the user must type `POP IT`. The application checks that Secure Boot is not already enabled, the firmware security version is valid, and the production build identity is available. Owner-only additionally requires the enrolled owner-only authority state.

The Rust application never performs raw eFuse writes. It writes a checksummed one-shot request and software-resets. The specially signed ESP-IDF bootloader then performs the final cryptographic and eFuse-state checks.

During a valid Pop It request, the bootloader:

1. verifies the installed bootloader and selected application against the profile's exact expected RSA signing authority;
2. for owner-only, verifies the sole-owner digest policy is already present;
3. initializes/enables configured release-mode Flash Encryption only while the request is armed;
4. consumes the one-shot request;
5. enables Secure Download mode where supported/configured;
6. permanently enables Secure Boot v2; and
7. allows hardware anti-rollback advancement only after hardware Secure Boot is active.

Ordinary pre-Pop boots leave those transitions deferred.

## Building the owner-only provisioning chain

Create and back up the owner RSA-3072 private key on a trusted offline system, then run:

```bash
make secure-owner-only \
  OWNER_KEY=/secure/offline/owner.pem \
  SECURE_DIR=target/secure-owner-only
```

This signs both the special bootloader and application with `owner.pem` and generates a matching `OWNERKEY.KAS`. The private key is never placed in the enrollment record, firmware, or signer.

For a dual-authority special chain, use `make secure-provisioning SECURE_BOOT_KEY=/secure/vendor-rsa.pem SIGNING_KEY=/secure/vendor-schnorr.key`.

See [EFUSE_RUNBOOK.md](../EFUSE_RUNBOOK.md) for the exact trust-policy/eFuse consequences and destructive validation requirements.

## Owner-authorized application updates

After owner enrollment and Pop It, build an owner application with:

```bash
make owner-firmware OWNER_KEY=/secure/offline/owner.pem
```

The output includes `OWNERFW.BIN` and `OWNERKEY.KAS`. For a dual-authority device, staged owner firmware must match owner digest **1**. For an owner-only device, it must match owner digest **0**. The bootloader also enforces image formatting, staged-image hash, anti-rollback, inactive-slot verification, and only changes OTA selection after all checks succeed.

A corrupt, truncated, wrong-key, or rollback image is rejected without selecting it. The owner-firmware SD flow updates the application; it is not a general second-stage bootloader replacement mechanism.

## Key-loss implications

Back up the owner RSA private key before enrollment. It cannot be recovered from `OWNERKEY.KAS`, an eFuse digest, the signer, or `OWNERFW.BIN`.

- **Dual authority:** losing the owner key removes future owner-signed updates, but vendor-authorized updates remain possible while the vendor key is available.
- **Owner only:** losing the owner key removes the ability to produce new firmware accepted by that sole hardware trust root. The vendor has no alternate hardware signing authority.

That distinction is intentional: owner-only mode reproduces the original model where the purchaser controls the only Secure Boot signing key.
