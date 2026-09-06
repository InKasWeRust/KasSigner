#!/usr/bin/env python3
"""Fail-closed source contracts for the CoreS3 production security boundary."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> int:
    errors: list[str] = []
    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    main_rs = text("apps/signer-firmware/src/main.rs")
    secret_state = text("apps/signer-firmware/src/runtime/secret_state.rs")
    qr_rs = text("apps/signer-firmware/src/runtime/data/qr.rs")
    anti = text("apps/signer-firmware/src/services/verify/anti_rollback.rs")
    attest = text("apps/signer-firmware/src/services/verify/attestation/mod.rs")
    partition = text("apps/signer-firmware/partitions/m5stack-cores3.csv")
    manifest = text("crates/signer-firmware-core/src/update/manifest/mod.rs")
    fw_update = text("apps/signer-firmware/src/services/fw_update/mod.rs")
    manifest_generator = text("tools/firmware/gen_update_manifest.rs")
    boot_cfg = text("tools/build/firmware/secure_bootloader/m5stack/sdkconfig.defaults")
    boot_build = text("tools/build/firmware/secure_bootloader/m5stack/build.sh")
    release_policy = text("apps/signer-firmware/release-policy.env")
    production_sh = text("tools/build/firmware/build_production.sh")
    secure_prepare = text("tools/build/firmware/prepare_m5stack_secure_release.sh")
    secure_prepare_ps1 = text("tools/build/firmware/prepare_m5stack_secure_release.ps1")
    secure_boot_build_ps1 = text("tools/build/firmware/secure_bootloader/m5stack/build.ps1")
    makefile = text("Makefile")
    make_tasks = text("scripts/common/lib/make_tasks.py")
    owner_build_sh = text("tools/build/firmware/build_owner_firmware.sh")
    owner_build_ps1 = text("tools/build/firmware/build_owner_firmware.ps1")
    cargo_features = text("apps/signer-firmware/Cargo.toml")
    feature_policy = text("apps/signer-firmware/src/feature_policy.rs")
    owner_boot = text("tools/build/firmware/secure_bootloader/m5stack/owner_bootloader_patch.py")
    dockerfile = text("Dockerfile")

    require("static APP_DATA: StaticCell<AppData>" in secret_state and "runtime::secret_state::initialize()" in main_rs,
            "CoreS3 production security: AppData must be static internal-SRAM state")
    require("Box::new(AppData::new())" not in main_rs,
            "CoreS3 production security: AppData must never move onto the PSRAM heap")
    require("OUTGOING_QR_BUFFER_SIZE" in qr_rs and "Vec<u8>" not in qr_rs,
            "CoreS3 production security: outgoing secret QR state must use the fixed internal buffer")

    require("SECURE_VERSION" in anti and "count_ones()" in anti,
            "CoreS3 production security: anti-rollback must read the monotonic SECURE_VERSION eFuse")
    require("write_u32(&mut output, SECURE_VERSION_OFFSET, APP_SECURITY_VERSION)" in anti,
            "CoreS3 production security: application descriptor must bind APP_SECURITY_VERSION")
    require("min_version" not in anti,
            "CoreS3 production security: legacy semantic-version rollback floor must stay retired")
    require("FlashEncryptionDisabled" in attest and "FlashEncryptionNotRelease" in attest
            and "DIS_DOWNLOAD_MANUAL_ENCRYPT" in attest
            and "if hardware_secure_boot" in attest
            and "require_release_flash_encryption()?" in attest,
            "CoreS3 production security: hardware-enforced attestation must require Flash Encryption Release Mode")

    partition_rows = [
        [cell.strip() for cell in line.split(",")]
        for line in partition.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    row_keys = {(row[0], row[1], row[2]) for row in partition_rows if len(row) >= 3}
    for row_key in (("ota_0", "app", "ota_0"), ("ota_1", "app", "ota_1"), ("otadata", "data", "ota")):
        require(row_key in row_keys,
                f"CoreS3 production security: partition layout missing {row_key}")
    require(not any(len(row) >= 3 and row[1] == "app" and row[2] in {"factory", "test"} for row in partition_rows),
            "CoreS3 production security: anti-rollback layout must not contain a factory/test app")

    required_boot = (
        "CONFIG_SECURE_BOOT=y",
        "CONFIG_SECURE_BOOT_V2_ENABLED=y",
        "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y",
        "CONFIG_SECURE_FLASH_ENC_ENABLED=y",
        "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y",
        "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y",
        "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y",
        "CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16",
        "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y",
    )
    for fragment in required_boot:
        require(fragment in boot_cfg,
                f"CoreS3 production security: secure bootloader profile missing {fragment}")
    security_version = next(
        (line.split("=", 1)[1].strip() for line in release_policy.splitlines()
         if line.startswith("KASSIGNER_SECURITY_VERSION=")),
        None,
    )
    require(security_version is not None and security_version.isdigit(),
            "CoreS3 production security: release policy must define numeric KASSIGNER_SECURITY_VERSION")
    require('source "$ROOT/tools/build/firmware/lib/release_policy.sh"' in boot_build
            and 'CONFIG_BOOTLOADER_APP_SECURE_VERSION=%s' in boot_build
            and '"$KASSIGNER_SECURITY_VERSION"' in boot_build,
            "CoreS3 production security: bootloader secure_version must be injected from release-policy.env")
    require("CONFIG_BOOTLOADER_APP_SECURE_VERSION=" not in boot_cfg,
            "CoreS3 production security: sdkconfig.defaults must not duplicate the release security version")
    require("CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE=y" not in boot_cfg,
            "CoreS3 production security: production bootloader must never emulate SECURE_VERSION")
    require("CONFIG_SECURE_BOOT_ALLOW_JTAG=y" not in boot_cfg,
            "CoreS3 production security: production bootloader must not allow JTAG")
    require("CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y" not in boot_cfg
            and "CONFIG_SECURE_DISABLE_ROM_DL_MODE=y" not in boot_cfg,
            "CoreS3 secure-provisioning profile must not auto-burn ROM download-mode eFuses before Pop It")
    secure_patch = text("tools/build/firmware/secure_bootloader/m5stack/owner_secure_boot_patch.py")
    pop_it_commit = secure_patch.split("POP_IT_COMMIT_BLOCK =", 1)[-1]
    require("POP_IT_COMMIT_BLOCK =" in secure_patch
            and "esp_efuse_enable_rom_secure_download_mode()" in pop_it_commit
            and pop_it_commit.index("kassigner_bootctl_take(KASSIGNER_BOOTCTL_OP_POP_IT")
            < pop_it_commit.index("esp_efuse_enable_rom_secure_download_mode()")
            < pop_it_commit.index("esp_secure_boot_v2_permanently_enable(image_data)"),
            "CoreS3 secure-provisioning profile must restrict ROM download only inside the explicit Pop It commit")

    require('secure-owner-only = ["secure-provisioning-core"]' in cargo_features
            and 'secure-provisioning = ["secure-provisioning-core"]' in cargo_features,
            "CoreS3 production security: both dual-authority and owner-only provisioning profiles must exist")
    require("secure-provisioning and secure-owner-only are mutually exclusive" in feature_policy,
            "CoreS3 production security: authority profiles must be compile-time mutually exclusive")
    require("--secure-owner-only" in production_sh
            and "FEATURES=m5stack,secure-owner-only" in production_sh
            and "unset KASSIGNER_SIGNING_KEY" in production_sh,
            "CoreS3 owner-only build must be explicit and independent of the vendor Schnorr key")
    require("--owner-only" in secure_prepare
            and "KASSIGNER_OWNER_SECURE_BOOT_KEY" in secure_prepare
            and "OWNERKEY.KAS" in secure_prepare,
            "CoreS3 owner-only artifact preparation must bind the supplied owner RSA key and enrollment record")
    require("[switch]$OwnerOnly" in secure_prepare_ps1
            and "KASSIGNER_OWNER_SECURE_BOOT_KEY" in secure_prepare_ps1
            and "OWNERKEY.KAS" in secure_prepare_ps1
            and "owner-only" in secure_boot_build_ps1,
            "CoreS3 owner-only artifact preparation must have native Windows parity")
    require("secure-provisioning:" in makefile
            and "secure-owner-only:" in makefile
            and 'secure-release dual' in makefile
            and 'secure-release owner-only' in makefile
            and 'def secure_release(' in make_tasks,
            "CoreS3 special production profiles must be explicit public make targets")
    require("KASSIGNER_OWNER_ONLY_AUTHORITY" in owner_boot
            and "ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0" in owner_boot
            and "esp_efuse_set_digest_revoke(1)" in owner_boot
            and "esp_efuse_set_digest_revoke(2)" in owner_boot,
            "CoreS3 owner-only bootloader policy must use owner digest0 and close unused authority slots")
    require("owner-only enrollment refuses an existing alternate Secure Boot authority" in owner_boot
            and "ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, &alternate_block" in owner_boot
            and "ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2, &alternate_block" in owner_boot,
            "CoreS3 owner-only enrollment must refuse pre-existing alternate Secure Boot authorities")
    require("refusing to mix secure trust policies" in secure_prepare
            and "refusing to mix secure authority modes" in secure_prepare
            and "stale dual-authority artifact" in secure_prepare
            and "stale owner-only artifact" in secure_prepare
            and "refusing to mix secure authority modes" in secure_prepare_ps1
            and "stale opposite-policy artifact" in secure_prepare_ps1,
            "CoreS3 secure artifact preparation must fail closed against mixed/stale trust-policy output")
    require("unset KASSIGNER_SIGNING_KEY" in owner_build_sh
            and "Remove-Item Env:KASSIGNER_SIGNING_KEY" in owner_build_ps1,
            "owner firmware builds must not inherit a vendor/development Schnorr signing identity")

    for field in (
        "schema", "board", "channel", "version", "release_sequence", "security_version", "image_size",
        "partition_layout_hash", "image_hash", "signature",
    ):
        require(field in manifest, f"firmware update manifest is missing signed field {field}")
    require("input.len() != MANIFEST_LEN" in manifest,
            "firmware update manifest must reject trailing or truncated bytes")
    require("KasSigner/FirmwareManifest/v3" in manifest,
            "firmware update manifest must remain domain separated")
    require("verify_image" not in fw_update and "hash_firmware_file" not in fw_update,
            "runtime firmware-update verification must stay retired in the USB-only model")
    require(not (ROOT / "apps/signer-firmware/src/services/fw_update/verification.rs").exists()
            and not (ROOT / "apps/signer-firmware/src/services/fw_update/layout.rs").exists(),
            "retired runtime SD/QR firmware verifier/layout must not return")
    for policy in (
        "update_manifest::BOARD_M5STACK_CORES3",
        "update_manifest::CHANNEL_PRODUCTION",
        "release_sequence,",
        "security_version,",
        "partition_hash(board, &args[7])",
        "sign_release_digest",
    ):
        require(policy in manifest_generator,
                f"host firmware manifest generator is missing policy binding {policy}")
    require("if descriptor_security_version() < floor" in anti
            and "AntiRollbackError::ImageBelowDeviceFloor" in anti,
            "boot verification must reject application security versions below the device eFuse floor")
    require('$ROOT/apps/signer-firmware/partitions/m5stack-cores3.csv' in secure_prepare,
            "secure release tooling must hash the repository-owned CoreS3 partition table")
    require("KASSIGNER_SIGNING_KEY" in production_sh and "m5stack,production" in production_sh,
            "production helper must require a firmware signing key and explicit m5stack,production features")
    require("kassigner-m5stack-app-secureboot-signed.bin" in secure_prepare
            and '"$SIGNED_APP" "$KASSIGNER_SIGNING_KEY" m5stack' in secure_prepare
            and "--bin gen-update-manifest" in secure_prepare,
            "CoreS3 KSFU manifest must be generated only after Secure Boot signing of the exact app bytes")
    require("/build/kassigner-m5stack-update.ksfu" not in dockerfile,
            "reproducible Docker stage must not emit a pre-Secure-Boot M5 update manifest")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("PASS: CoreS3 production secret-memory, boot-chain, anti-rollback, and signed-update contracts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
