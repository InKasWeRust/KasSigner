"""Firmware removable-backup and password-KDF architecture contracts."""

from __future__ import annotations

from pathlib import Path


def _require(errors: list[str], source: str, token: str, message: str) -> None:
    if token not in source:
        errors.append(f"{message}: {token}")


def check(root: Path) -> list[str]:
    errors: list[str] = []
    backup_root = root / "apps/signer-firmware/src/services/backup"
    required = {
        "mod.rs", "container.rs", "device.rs", "error.rs",
        "randomness.rs", "seed.rs", "xprv.rs",
    }
    actual = {path.name for path in backup_root.glob("*.rs")} if backup_root.exists() else set()
    if actual != required:
        errors.append(
            f"firmware backup service inventory changed: expected {sorted(required)}, got {sorted(actual)}"
        )

    limits = {
        "mod.rs": 70,
        "container.rs": 220,
        "device.rs": 100,
        "error.rs": 60,
        "randomness.rs": 70,
        "seed.rs": 80,
        "xprv.rs": 70,
    }
    for name, limit in limits.items():
        path = backup_root / name
        if not path.exists():
            continue
        lines = len(path.read_text(errors="ignore").splitlines())
        if lines > limit:
            errors.append(
                f"firmware backup module exceeds SRP limit: {path.relative_to(root)} ({lines} > {limit})"
            )

    facade = (backup_root / "mod.rs").read_text(errors="ignore")
    for token in (
        "Device-bound removable wallet backups",
        "decrypt_backup_progress", "encrypt_backup_progress",
        "decrypt_xprv_backup_progress", "encrypt_xprv_backup",
        "backup_kind", "BackupDevice", "BackupError",
    ):
        _require(errors, facade, token, "wallet-backup facade missing contract")
    for forbidden in ("pbkdf2_key_for_kspt", "legacy.rs", "raw.rs"):
        if forbidden in facade:
            errors.append(f"retired backup facade concern returned: {forbidden}")

    container = (backup_root / "container.rs").read_text(errors="ignore")
    framing = (root / "crates/offline-signer/src/crypto/container_framing.rs").read_text(errors="ignore")
    container_contract = container + "\n" + framing
    for token in (
        'BACKUP_CURRENT_MAGIC: [u8; 8] = *b"KASDB005"',
        'BACKUP_LEGACY_MAGIC: [u8; 8] = *b"KASDB004"',
        "PasswordKdfPurpose::DeviceBoundBackup",
        "password_kdf::encode_metadata",
        "password_kdf::parse_metadata",
        "BackupReaderKdf::Argon2id",
        "BackupReaderKdf::LegacyPbkdf2",
        "legacy_pbkdf2::derive_legacy_32",
        "StoragePurpose::SdSeedBackup",
        "StoragePurpose::SdXprvBackup",
        "zeroize_bytes(&mut key)",
    ):
        _require(errors, container_contract, token, "device-bound backup container missing contract")
    if "seal_with_material" not in container or "CURRENT_HEADER_SIZE" not in container:
        errors.append("current device-bound backup writer is not versioned through KASDB005")
    if "container_framing::parse_backup_header" not in container:
        errors.append("device-bound backup reader must delegate framing to the shared pure parser")

    kspt = (root / "apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/crypto.rs").read_text(errors="ignore")
    kspt_contract = kspt + "\n" + framing
    for token in (
        'TRANSPORT_CURRENT_MAGIC: [u8; 4] = *b"KAS\\x04"',
        'TRANSPORT_LEGACY_MAGIC: [u8; 4] = *b"KAS\\x03"',
        "PasswordKdfPurpose::EncryptedTransport",
        "password_kdf::encode_metadata",
        "password_kdf::parse_metadata",
        "open_current",
        "open_legacy",
        "legacy_pbkdf2::derive_legacy_32",
    ):
        _require(errors, kspt_contract, token, "encrypted KSPT KDF contract missing")
    if "container_framing::parse_transport_header" not in kspt:
        errors.append("encrypted KSPT reader must delegate framing to the shared pure parser")
    if "CURRENT_MAGIC" not in kspt.split("fn seal_envelope", 1)[1].split("fn open_envelope", 1)[0]:
        errors.append("new encrypted KSPT writer must emit only the current Argon2 envelope")

    device = (backup_root / "device.rs").read_text(errors="ignore")
    persistent = (root / "apps/signer-firmware/src/services/persistent_wallet/mod.rs").read_text(errors="ignore")
    for token in ("BackupDevice", "PersistentWallet", "seal_backup_key", "open_backup_key"):
        if token not in device + persistent:
            errors.append(f"device-bound removable-backup boundary missing: {token}")

    for name in ("seed.rs", "xprv.rs"):
        source = (backup_root / name).read_text(errors="ignore")
        if "BackupDevice" not in source or "container::" not in source:
            errors.append(f"current device-bound backup path is not wired: {name}")
        if "CURRENT_HEADER_SIZE" not in source:
            errors.append(f"current backup size must be based on the current v5 header: {name}")
        if "zeroize" not in source and ".fill(0)" not in source:
            errors.append(f"wallet-secret backup output is not cleared: {name}")
        for forbidden in ("Aes256Gcm", "legacy_pbkdf2", "derive_legacy_32"):
            if forbidden in source:
                errors.append(f"backup facade bypasses centralized container/KDF ownership: {name}: {forbidden}")

    tests = (root / "apps/signer-firmware/src/services/unit_tests/backup_tests.rs").read_text(errors="ignore")
    for token in (
        "current_device_bound_backup_uses_argon2_metadata",
        "portable_jpeg_is_password_only_cross_device",
        "wrong_password",
        "bad_kdf",
        "AuthenticationFailed",
    ):
        _require(errors, tests, token, "wallet-backup security regression missing")

    policy = (root / "SECURITY.md").read_text(errors="ignore")
    for token in (
        "JPEG + password",
        "Argon2id v=19",
        "PBKDF2 only for BIP39 and explicitly versioned deployed-legacy readers",
    ):
        _require(errors, policy, token, "recovery/password-KDF policy missing")
    if "separately recorded Portable recovery key" in policy:
        errors.append("security policy still documents the obsolete two-secret Portable workflow")

    return errors
