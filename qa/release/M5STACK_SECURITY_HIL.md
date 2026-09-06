# M5Stack CoreS3 production security HIL

This runbook defines the CoreS3 hardware-in-loop evidence required for a production release. It separates **read-only verification**, **destructive validation fixtures**, and **production provisioning**. Never perform irreversible eFuse operations on a device that contains funds or the only copy of wallet material.

## Release inputs

Hash and retain the exact inputs used for HIL:

- the release source archive;
- the normal `m5stack,production` application image signed by the KasSigner application-release key (used to prove the non-destructive normal-release profile);
- the dedicated `m5stack,secure-provisioning` dual-authority image/boot chain and the `m5stack,secure-owner-only` sole-owner image/boot chain for whichever destructive provisioning policies are release-qualified;
- the checked-in M5Stack partition CSV and generated partition-table binary;
- the RSA-signed ESP-IDF second-stage bootloader produced by the selected `make secure-provisioning` or `make secure-owner-only` build;
- for dual-authority testing, the vendor-authorized KSFU update manifest for that exact application/board/security-version/layout; owner-only preparation intentionally emits no vendor KSFU manifest;
- when testing owner authority, the owner RSA-3072 public-key enrollment record (`OWNERKEY.KAS`) and an owner-signed application (`OWNERFW.BIN`) produced from a test-only owner key.

In dual-authority testing, the vendor Secure Boot RSA key, KasSigner application-release Schnorr key, and owner RSA key are distinct authorities. In owner-only testing, the owner RSA key signs the special bootloader/application and becomes the sole Secure Boot root; a vendor hardware signing authority is intentionally absent. Private keys do not belong in the source tree or HIL evidence bundle.

## Mandatory irreversible-action acknowledgement

Developer-side eFuse burns, key burns, write protection, and other irreversible security-state changes must be launched through the repository acknowledgement wrapper. It refuses piped/unattended input, requires the operator to type `I UNDERSTAND THIS IS IRREVERSIBLE`, requires the exact target device identifier a second time, and substitutes that confirmed device through the literal `{device}` token:

```text
python3 qa/checks/release/irreversible_action_ack.py \
  --action "describe the exact irreversible operation" \
  --device /dev/ttyACM0 -- vendor-tool --port {device} <irreversible-arguments>
```

The placeholder is intentionally generic. Review Espressif's current ESP32-S3 provisioning procedure and the exact tool version before executing an irreversible command. Repository automation must not contain an unguarded destructive eFuse command.

This host-side acknowledgement is independent of the signed firmware's on-device **Pop It!** consent. Pop It! requires the user to read the permanent warning and type `POP IT`. **Owner Key enrollment** likewise requires its own explicit irreversible confirmation. Development firmware may exercise the UI and validation path but must not arm the production boot-control operation or write eFuses.

## Provisioning order

ESP32-S3 read/write protection is irreversible. Both secure provisioning firmware/bootloader profiles must leave Flash Encryption, Secure Boot, Secure ROM Download mode, and hardware anti-rollback eFuses unchanged during ordinary boot and use. Owner-key enrollment is allowed only after its own explicit typed confirmation; the Pop It path performs the Flash Encryption/Secure-Download/Secure-Boot transition only after its explicit typed confirmation. Any separately required per-device HMAC provisioning remains an operator-controlled irreversible manufacturing action and must never be triggered implicitly by normal firmware boot. Follow Espressif's current ESP32-S3 guidance for the exact approved operation.

The digest policy depends on the selected profile:

- **Dual `secure-provisioning`:** optional owner enrollment establishes vendor digest 0 + owner digest 1, closes digest 2, and protects the live trusted-key revoke controls. Pop It may deliberately proceed without owner enrollment, producing vendor-only hardware trust and permanently closing later owner enrollment.
- **`secure-owner-only`:** owner enrollment is mandatory before Pop It. It establishes the owner key as digest 0, revokes digest 1 and digest 2, protects digest-0 revocation, and leaves no vendor Secure Boot authority. Pop It must refuse to continue until this sole-owner state is present.

Pop It subsequently enables the remaining hardware security transition according to the selected policy.

Required final security state includes:

1. unique per-device eFuse HMAC key present and read-protected;
2. Flash Encryption enabled in **Release Mode**;
3. `SPI_BOOT_CRYPT_CNT` write-protected and download-mode manual encryption disabled;
4. Secure Boot v2 enabled with exactly the selected profile's authority set: dual mode keeps vendor digest 0 and, when enrolled, owner digest 1; owner-only keeps owner digest 0 and no vendor digest; all unused digest slots are closed according to policy;
5. live trusted-key revoke controls protected according to the selected profile;
6. hardware `SECURE_VERSION` at or above the application security version required by the release;
7. production debug/JTAG/download restrictions in their approved final state.

## Security-state evidence across lockdown

Immediately before final Secure Download lockdown, capture and hash a complete `espefuse summary` as provisioning evidence. After lockdown, arbitrary eFuse and memory access is intentionally unavailable; use only the ROM's restricted security-info command through the read-only collector:

```bash
qa/linux/run-m5stack-security-hil.sh /dev/ttyACM0 \
  target/qa/security/m5stack-final-security
```

Archive the pre-lock eFuse summary separately. The post-lock collector bootstraps the version-pinned esptool declared in `apps/signer-firmware/release-policy.env`; the operator does not install or activate esptool manually. Archive `get-security-info.txt`, `security-info-raw.json`, `security-state.json`, and `collection.json`. Release evidence must verify the actual values and file hashes, not merely the presence of field names.

## Owner-authority destructive fixture

Use a dedicated sacrificial CoreS3 with test-only vendor/owner keys. Bind the complete serial/UI transcript, eFuse reports, image hashes, key fingerprints, and partition/OTA state into the report referenced by `m5stack_owner_authority.json`.

The fixture must prove all of the following:

1. **Development safety:** development firmware can parse/validate `OWNERKEY.KAS` and `OWNERFW.BIN` only in simulation; it cannot request enrollment/install eFuse transitions.
2. **Enrollment ordering:** an owner key can be enrolled before Pop It!, and enrollment is rejected after Secure Boot has been permanently enabled.
3. **Digest policy:** official vendor digest is slot 0, owner digest is slot 1, slot 2 is closed, and the trusted-key revoke controls are write-protected.
4. **Official authority survives:** a correctly vendor-signed application still verifies and boots after owner enrollment and Pop It!.
5. **Owner authority works:** an application signed by the enrolled owner RSA key installs through the owner-firmware SD flow and boots.
6. **Wrong key fails:** an otherwise valid image signed by an unrelated RSA key is rejected and never selected.
7. **Anti-rollback survives:** an owner-signed image whose application `secure_version` is below fused `SECURE_VERSION` is rejected before application execution.
8. **Selection atomicity:** a corrupt, truncated, wrong-hash, wrong-key, or otherwise rejected owner image leaves the previously selected OTA application selected and bootable; the inactive OTA slot may have been overwritten during verification.
9. **Permanent opt-out:** Pop It! performed without prior owner enrollment permanently closes the owner-enrollment path while preserving official vendor updates.

`m5stack_owner_authority.json` is an externally stored, signed release-evidence record. Raw HIL logs and private test keys are not committed to the repository.

### Owner-only parity fixture

Use a separate sacrificial CoreS3 and test-only owner RSA key for the restored original sole-owner policy. The fixture must additionally prove:

1. the special bootloader and application are signed by the owner key selected for that build;
2. no eFuse provisioning happens during repeated ordinary pre-enrollment/pre-Pop boots;
3. typed `ENROLL OWNER` burns that exact owner digest as Secure Boot digest 0;
4. digest slots 1 and 2 are revoked and digest-0 revocation is protected;
5. no vendor Secure Boot digest is live;
6. the Pop It UI/bootloader refuses a continue-without-owner path;
7. typed Pop It subsequently enables the configured Flash Encryption/Secure Download/Secure Boot transition;
8. owner-signed `OWNERFW.BIN` is accepted through digest 0; and
9. a vendor-only or unrelated-key RSA-signed application is rejected after hardware Secure Boot is active.

Bind this evidence to the owner-only trust-policy marker and the exact `OWNERKEY.KAS` digest.

## Secret-memory map check

Build the exact normal `m5stack,production` ELF with map/symbol output and verify the `APP_DATA` static and its inline outgoing QR buffer resolve to internal DRAM, not external PSRAM. Also verify camera/bulk buffers that intentionally use PSRAM contain no persistent seed/passphrase/private-key root state. Bind the map and ELF hashes into `m5stack_secret_memory_map.json`.

## Anti-rollback destructive fixture

Use a dedicated sacrificial validation unit, never a funded production signer. The test must use the same second-stage bootloader policy and Secure Boot identity as production.

1. Establish eFuse `SECURE_VERSION=1` and successfully boot an approved application with application `secure_version=1`.
2. Prepare an older **correctly Secure-Boot-signed** test application whose app descriptor has `secure_version=0`, signed with the same dedicated test Secure Boot identity.
3. Place/select that older image through the validation fixture's allowed flash/OTA mechanism.
4. Reboot and capture second-stage bootloader output proving the lower-security image is rejected and never entered.
5. Reinstall/select the approved application and prove normal boot remains possible.

The result is `m5stack_anti_rollback.json`; a source-level runtime rejection is not sufficient evidence. Rejection must happen in the second-stage bootloader before application execution.

## Signed update-manifest negative matrix

Against the provisioned test device, prove that a valid signed update manifest succeeds, then mutate one dimension at a time without re-signing and prove rejection:

- schema/reserved bytes;
- board;
- release channel;
- semantic version;
- update sequence;
- security version;
- image size;
- partition-layout SHA-256;
- image SHA-256;
- signature;
- appended/trailing bytes;
- truncated bytes.

Also produce correctly signed but policy-invalid manifests for wrong board, wrong layout, non-increasing update sequence, and lower hardware anti-rollback epoch. Bind the raw transcript and manifest hashes into `m5stack_update_manifest_negative.json`.

## Final fused smoke

After destructive validation, use a separate production-fused unit for the normal signer HIL matrix: boot KATs, wallet create/restore, lock/unlock, receive/address QR, Scan QR, transaction review/signing, SD persistence/recovery, camera error recovery, screen dim/wake, watchdog reset recovery, reboot persistence, and power-loss/fault cases. No debug/provisioning private key material may remain on the device or in the release bundle.
