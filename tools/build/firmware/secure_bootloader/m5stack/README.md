[KasSigner](../../../../../README.md) › [Documentation](../../../../../docs/README.md) › [Security](../../../../../docs/security/SECURITY_OVERVIEW.md) › M5Stack secure bootloader

# CoreS3 production bootloader profiles

This pinned ESP-IDF project builds KasSigner's signed second-stage bootloader for the opt-in M5Stack CoreS3 provisioning profiles. Normal `make release` does not use this provisioning bootloader.

## Authority modes

`build.sh` accepts the authority policy through `KASSIGNER_SECURE_BOOT_AUTHORITY_MODE`:

- `dual` (default) — the bootloader/application are signed by the vendor Secure Boot RSA key. Owner enrollment establishes vendor digest 0 + owner digest 1 and closes digest 2. Pop It may also proceed vendor-only when the user explicitly declines owner enrollment.
- `owner-only` — the bootloader/application are signed by the owner's RSA key. Owner enrollment requires `OWNERKEY.KAS` to match that same key, burns it as digest 0, revokes digest 1 and digest 2, and protects digest-0 revocation. Pop It is refused until this sole-owner policy is present. No vendor Secure Boot digest is trusted.

The expected 32-byte Secure Boot v2 public-key digest is derived from `KASSIGNER_SECURE_BOOT_SIGNING_KEY` and embedded only for exact-key preflight. Private signing keys are never embedded.

## One-shot boot control

Irreversible/security-sensitive transitions use the dedicated checksummed `kassigner_bootctl` partition and are accepted only on the expected software-reset path. Ordinary boots read state but do not provision eFuses.

Supported operations are:

- **Owner-key enrollment** — only after explicit typed owner confirmation and only before hardware Secure Boot is enabled. The exact eFuse digest policy depends on `dual` versus `owner-only`.
- **Pop It!** — after exact bootloader/application authority preflight, gate release-mode Flash Encryption, consume the request, enter Secure Download mode, then enable Secure Boot v2. Hardware anti-rollback advancement remains deferred until Secure Boot is already hardware-enabled.
- **Owner-firmware install** — after Pop It, verify/stage an owner-signed application into the inactive OTA slot and select it only after image, hash, key and anti-rollback checks succeed. Dual mode verifies owner digest 1; owner-only mode verifies owner digest 0.

Development firmware may validate/simulate the application UI but cannot issue these production boot-control operations.

## Why Pop It is deferred

The ESP-IDF security configuration enables Secure Boot v2 and Flash Encryption capabilities in the special bootloader build, but KasSigner's source patch gates the normally irreversible first-boot paths behind explicit Pop It consent. The ROM-download eFuse auto-enable option is left off and Secure Download mode is entered only inside the explicit Pop It commit.

Before a Pop It request is accepted, the bootloader validates both the installed second-stage bootloader and selected application and requires a valid Secure Boot signature from the authority key used to build that profile. Owner-only additionally requires the already-enrolled sole-owner digest policy.

## Building

For dual authority, set `KASSIGNER_SECURE_BOOT_SIGNING_KEY` to the vendor RSA-3072 key and leave `KASSIGNER_SECURE_BOOT_AUTHORITY_MODE=dual` (or unset it).

For owner only, set the signing key to the owner's RSA-3072 key and set:

```bash
export KASSIGNER_SECURE_BOOT_AUTHORITY_MODE=owner-only
```

The higher-level `prepare_m5stack_secure_release.sh --owner-only` wrapper performs those selections and emits matching `OWNERKEY.KAS`/policy evidence automatically.

Application images are secure-padded to the ESP32-S3 64 KiB MMU boundary before RSA signing. Repository tooling performs the padding explicitly and verifies the resulting signature.

See [`docs/security/POP_IT_SECURE_BOOT.md`](../../../../../docs/security/POP_IT_SECURE_BOOT.md), [`docs/security/EFUSE_RUNBOOK.md`](../../../../../docs/EFUSE_RUNBOOK.md), and [`qa/release/M5STACK_SECURITY_HIL.md`](../../../../../qa/release/M5STACK_SECURITY_HIL.md).
