"""Typed wallet recovery and session-bound QR source contracts."""

from __future__ import annotations

from pathlib import Path
import re


def check_wallet_recovery_contract(root: Path, errors: list[str]) -> None:
    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    source = read("apps/signer-firmware/src/wallet/seed_manager/source.rs")
    for variant in (
        "Mnemonic12",
        "Mnemonic24",
        "RawPrivateKey",
        "AccountXprv",
    ):
        require(variant in source, f"wallet recovery: missing typed source {variant}")

    firmware = root / "apps/signer-firmware/src"
    firmware_source = "\n".join(
        path.read_text(encoding="utf-8") for path in firmware.rglob("*.rs")
    )
    for sentinel_value in (1, 2):
        require(
            re.search(rf"\bword_count\s*==\s*{sentinel_value}\b", firmware_source)
            is None,
            "wallet recovery: source typing regressed to mnemonic sentinel "
            f"word_count == {sentinel_value}",
        )

    derivation = read("apps/signer-firmware/src/runtime/signing/derivation.rs")
    wallet_keys = read("apps/signer-firmware/src/services/wallet_keys.rs")
    for required in (
        "derive_slot_account_key",
        "serialize_active_xprv",
    ):
        require(required in derivation, f"wallet recovery: missing {required}")
    require(
        'Err("Wallet source is not a mnemonic")' in wallet_keys
        and "pub(crate) use crate::services::wallet_keys" in derivation,
        "wallet recovery: mnemonic source rejection must remain owned by the wallet-key service",
    )

    checkpoint_derivation = read(
        "apps/signer-firmware/src/runtime/signing/derivation/checkpoint.rs"
    )
    require(
        "begin_active_kpub_derivation" in checkpoint_derivation
        and "finish_active_kpub_derivation" in checkpoint_derivation
        and "SeedDerivation" in checkpoint_derivation
        and "serialize_account_kpub" in checkpoint_derivation,
        "wallet recovery: cooperative canonical kpub derivation is missing",
    )

    strategy = read("apps/signer-firmware/src/runtime/signing/strategy.rs")
    require(
        "AccountKey" in strategy and "slot.is_account_key()" in strategy,
        "wallet recovery: imported account XPrv lacks its own signing strategy",
    )

    kspt = read("apps/signer-firmware/src/runtime/signing/kspt.rs")
    pskt = read("apps/signer-firmware/src/runtime/signing/pskt.rs")
    workflow = read("apps/signer-firmware/src/runtime/signing/workflow.rs")
    require(
        "sign_account_input_with_entropy" in kspt
        and "SigningStrategy::AccountKey | super::strategy::SigningStrategy::Mnemonic" in kspt,
        "wallet recovery: mnemonic/account XPrv signing is absent from the shared per-input signer",
    )
    require(
        "sign_matching_input_in_place_with_entropy" in kspt,
        "wallet recovery: raw keys must sign only the matching P2PK input",
    )
    require(
        "kspt::sign_input(ad, signing_strategy, input_idx, &signing_entropy, liveness)" in workflow
        and "serialize_pskt_vec" in pskt,
        "wallet recovery: PSKT and KSPT must share the authoritative per-input signing path",
    )

    fingerprint = read("crates/offline-signer/src/derivation/xpub/fingerprint.rs")
    require(
        "Ripemd160" in fingerprint
        and "Sha256" in fingerprint
        and "parent_fingerprint" in fingerprint,
        "wallet recovery: original v1.0.5 exports require standard BIP32 HASH160 fingerprints",
    )
    require(
        "test_original_v105_export_vectors" in read(
            "crates/offline-signer/src/derivation/unit_tests/xpub_tests.rs"
        ),
        "wallet recovery: fixed original-v1.0.5 kpub/XPrv vectors are missing",
    )

    xprv = read("crates/offline-signer/src/derivation/xpub/xprv.rs")
    require(
        "ImportedAccountXprv" in xprv
        and "parent_fingerprint" in xprv
        and "serialize_imported_xprv" in xprv,
        "wallet recovery: imported account XPrv metadata is not preserved",
    )


    backup_mod = read("apps/signer-firmware/src/services/backup/mod.rs")
    backup_container = read("apps/signer-firmware/src/services/backup/container.rs")
    backup_framing = read("crates/offline-signer/src/crypto/container_framing.rs")
    backup_contract = backup_container + "\n" + backup_framing
    backup_seed = read("apps/signer-firmware/src/services/backup/seed.rs")
    backup_xprv = read("apps/signer-firmware/src/services/backup/xprv.rs")
    backup_tests = read("apps/signer-firmware/src/services/unit_tests/backup_tests.rs")
    require(
        (root / "apps/signer-firmware/src/services/backup/container.rs").exists()
        and not (root / "apps/signer-firmware/src/services/backup/legacy.rs").exists(),
        "wallet recovery: current device-bound container must exist without a generic legacy facade",
    )
    for required in (
        'KASDB005', 'KASDB004', "KDF_ID_DEVICE_HMAC_SHA256",
        "PasswordKdfPurpose::DeviceBoundBackup", "BackupReaderKdf::Argon2id",
        "BackupReaderKdf::LegacyPbkdf2", "StoragePurpose::SdSeedBackup",
        "StoragePurpose::SdXprvBackup",
    ):
        require(required in backup_contract, f"wallet recovery: backup container missing {required}")
    for name, contents in (("seed", backup_seed), ("xprv", backup_xprv)):
        require(
            "BackupDevice" in contents
            and "container::" in contents
            and "BackupError::DeviceBoundStorageRequired" not in contents,
            f"wallet recovery: current device-bound {name} backup is not active",
        )
    require(
        not (root / "apps/signer-firmware/src/services/backup/raw.rs").exists(),
        "wallet recovery: retired raw recovery-hint backup facade must stay removed",
    )
    require(
        "current_device_bound_backup_uses_argon2_metadata" in backup_tests
        and "historical_deployed_legacy_device_bound_reader_is_magic_selected_only" in backup_tests,
        "wallet recovery: current/legacy backup security regressions are missing",
    )

    device_bound = read("crates/offline-signer/src/crypto/device_bound_storage.rs")
    for required in (
        "HardwareHmac",
        "KDF_ID_DEVICE_HMAC_SHA256",
        "InternalWallet = 1",
        "SdWallet = 2",
        "SdSeedBackup = 3",
        "SdXprvBackup = 4",
        "StegoWallet = 5",
        "AuthenticationFailed",
    ):
        require(required in device_bound, f"wallet recovery: device-bound storage missing {required}")
    require(
        "fn hmac_sha256(" in device_bound
        and "raw_key" not in device_bound
        and "export_key" not in device_bound,
        "wallet recovery: hardware HMAC boundary must not expose a raw device key",
    )

    stego_payload = read("apps/signer-firmware/src/services/stego/payload.rs")
    stego_controller = read("apps/signer-firmware/src/runtime/interactions/stego/export_confirm/mod.rs")
    stego_import = read("apps/signer-firmware/src/runtime/interactions/stego/import_decrypt.rs")
    for required in (
        "StoragePurpose::StegoWallet", "PAYLOAD_SIZE", "PORTABLE_FORMAT_VERSION",
        "password_kdf::parse_metadata", "build_aad", "descriptor_credential", "zeroize_bytes",
    ):
        require(required in stego_payload, f"wallet recovery: current stego payload missing {required}")
    require(
        re.search(r"input\.len\(\)\s*!=\s*PAYLOAD_SIZE", stego_payload) is not None,
        "wallet recovery: current stego payload missing bounded PAYLOAD_SIZE input validation",
    )
    require(
        "pack_payload" in stego_controller and "BackupDevice" in stego_controller,
        "wallet recovery: JPEG stego export is not wired to device-bound sealing",
    )
    require(
        "unpack_device_bound_payload" in stego_import
        and "unpack_portable_payload" in stego_import
        and "BackupDevice" in stego_import,
        "wallet recovery: JPEG stego import is not wired to both current security modes",
    )
    require(
        "PayloadError::Retired" not in stego_payload and "is_legacy_base64" not in stego_payload,
        "wallet recovery: current JPEG stego payload must not route through the retired facade",
    )

    legacy = read("crates/shared-signer/src/legacy_account_key.rs")
    require(
        "decode_legacy_kpub" in legacy
        and "validate_account_key_payload" in legacy
        and "base58check_encode" not in legacy
        and "pub fn encode_legacy" not in legacy,
        "wallet recovery: legacy Base58 adapter must remain decode-only and canonicalizing",
    )
    for path in (
        "crates/offline-signer/src/derivation/xpub/kpub.rs",
        "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/kpub.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/exports/kpub.rs",
        "apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/content.rs",
    ):
        contents = read(path)
        require(
            "decode_legacy_kpub" in contents
            or "decode_kpub_compatible" in contents
            or "normalize_kpub_text" in contents,
            f"wallet recovery: legacy kpub migration is missing from {path}",
        )

    protocol_bip32 = read("crates/kassigner-protocol/src/account/bip32.rs")
    watcher_bip32 = read("crates/online-watcher/src/account/bip32.rs")
    require(
        "decode_legacy_kpub" in protocol_bip32
        and "decode_bip32_xpub" in protocol_bip32
        and "canonical_kpub_text" in protocol_bip32,
        "wallet recovery: protocol-owned watcher migration must accept legacy kpub/BIP32 xpub and canonicalize output",
    )
    for delegated in (
        "kassigner_protocol::compat::decode_kpub_text",
        "kassigner_protocol::compat::import_kpub",
        "kassigner_protocol::compat::import_kpub_raw",
    ):
        require(
            delegated in watcher_bip32,
            f"wallet recovery: watcher facade must delegate legacy-compatible account import through protocol owner ({delegated})",
        )


    production_menu_graph = read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
    require(
        '"Backup to SD"' in production_menu_graph
        and '"Encrypt to SD"' in production_menu_graph
        and '"Seed / XPrv Backup"' in production_menu_graph
        and '"Touch Seed"' in production_menu_graph
        and '"Steganography"' in production_menu_graph
        and '"Stego Import"' in production_menu_graph,
        "wallet recovery: current device-bound backup and Touch Seed menu parity is missing",
    )

    wallet_session = read("apps/signer-firmware/src/services/wallet_session.rs")
    require(
        "fingerprint_hasher.update(raw)" in wallet_session
        and "fingerprint_hasher.update(imported.parent_fingerprint)" in wallet_session,
        "wallet recovery: account fingerprints must cover the complete XPrv and BIP32 metadata",
    )

    loaded_accounts = read("apps/signer-firmware/src/runtime/signing/loaded_accounts.rs")
    require(
        "loaded.push_slot(&seed_manager.slots[active_manager_slot], checkpoint)" in loaded_accounts
        and "loaded.active_index = Some(0)" in loaded_accounts
        and "&self.entries[..self.count]" in loaded_accounts,
        "wallet recovery: the active account must remain signable when more than eight wallets are loaded",
    )

    frame = read("crates/shared-signer/src/qr_frame.rs")
    require(
        "SESSION_ID_LEN" in frame
        and "session_id(payload)" in frame
        and "verify_session" in frame,
        "multi-frame QR: payload-bound session protocol is missing",
    )
    require(
        "MAX_FRAMES" in frame,
        "multi-frame QR: shared frame-count bound is missing",
    )


    camera_state = read("apps/signer-firmware/src/runtime/interactions/camera_loop/state.rs")
    require(
        "MF_SLOT_SIZE: usize = u8::MAX as usize" in camera_state
        and "zeroize_bytes(&mut self.buffer)" in camera_state,
        "multi-frame QR: abandoned session payloads must be bounded and wiped",
    )
    require(
        "SessionMismatch" not in frame,
        "multi-frame QR: unused session-error variants must not remain",
    )

    entropy_collection = read("apps/signer-firmware/src/services/entropy/collection.rs")
    require(
        re.search(r"pub fn fill\(output: &mut \[u8\]\).*?output\.fill\(0\);", entropy_collection, re.S)
        is not None,
        "entropy: failed randomness requests must leave the caller buffer zeroed",
    )

    firmware_decoder = read(
        "apps/signer-firmware/src/runtime/interactions/camera_loop/multiframe.rs"
    )
    web_adapter = read("crates/online-watcher/src/protocol/qr.rs")
    protocol_decoder = read("crates/kassigner-protocol/src/qr/mod.rs")

    require(
        "Mixed multi-frame QR session rejected" in firmware_decoder
        and "verify_session" in firmware_decoder,
        "multi-frame QR: firmware decoder lacks session locking and digest verification",
    )
    require(
        "frame_index != 0" not in firmware_decoder,
        "multi-frame QR: firmware decoder permits foreign frame zero to replace an active session",
    )
    require(
        "Conflicting duplicate" in firmware_decoder
        or "conflicting duplicate" in firmware_decoder,
        "multi-frame QR: firmware decoder accepts conflicting duplicate frames",
    )

    require(
        "use kassigner_protocol::qr::{encode_frames, QrDecoder};" in web_adapter
        and "cell.borrow_mut()" in web_adapter
        and ".accept(&payload)" in web_adapter,
        "multi-frame QR: watcher must remain a thin adapter over kassigner-protocol::QrDecoder",
    )
    require(
        "authorize_frame_session(" in protocol_decoder
        and "verify_session(&complete, &expected)" in protocol_decoder
        and "mixed multi-frame QR session rejected" in protocol_decoder,
        "multi-frame QR: canonical protocol decoder lacks session locking and digest verification",
    )
    require(
        "conflicting duplicate QR frame rejected" in protocol_decoder,
        "multi-frame QR: canonical protocol decoder accepts conflicting duplicate frames",
    )

    # Restore-source compile contracts: keep parent/submodule visibility and
    # offline-signer BIP39 Result handling aligned with their actual APIs.
    restore_passphrase = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
    restore_installed = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase/installed.rs")
    restore_qr = read("apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/seed.rs")
    require(
        "installed::apply_pending_wallet_name(ad, slot);" in restore_passphrase
        and "pub(super) fn apply_pending_wallet_name" in restore_installed,
        "wallet recovery: pending restored-wallet naming helper must be parent-visible and called through the installed submodule",
    )
    require(
        "let Ok(index) = offline_signer::derivation::bip39::word_to_index(word) else" in restore_qr
        and "let Some(index) = offline_signer::derivation::bip39::word_to_index(word) else" not in restore_qr,
        "wallet recovery: plain-text SeedQR must handle word_to_index as Result<u16, Bip39Error>",
    )

    require(
        "data[0] as usize" not in firmware_decoder
        and "data[1] as usize" not in firmware_decoder,
        "multi-frame QR: sessionless firmware framing must not return",
    )
