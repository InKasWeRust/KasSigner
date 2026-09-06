from __future__ import annotations

from pathlib import Path
import re

from architecture.protocols.compact_protocols import check_kspt, check_pskt

def _check_bip32_and_transaction_models(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    offline_root = ROOT / "crates/offline-signer/src"
    offline_lib_source = (offline_root / "lib.rs").read_text(errors="ignore")
    # Offline BIP32 and transaction data models live under canonical domain
    # namespaces rather than crate-root compatibility aliases.
    derivation_facade = (offline_root / "derivation/mod.rs").read_text(errors="ignore")
    transaction_facade = (offline_root / "transaction/mod.rs").read_text(errors="ignore")
    for required in ("pub mod derivation;", "pub mod crypto;", "pub mod transaction;"):
        if required not in offline_lib_source:
            errors.append(f"offline signer domain wiring is missing: {required}")
    if "#[path" in offline_lib_source:
        errors.append("offline signer crate root must use canonical domain modules, not path aliases")
    for retired_root in (
        "bip32", "bip39", "bip39_wordlist", "bip85", "ecies", "hmac",
        "kspt", "pbkdf2", "schnorr", "sighash", "std_pskt", "xpub",
    ):
        if f"pub mod {retired_root};" in offline_lib_source:
            errors.append(f"offline signer crate-root compatibility module must not return: {retired_root}")
    if "pub mod bip32;" not in derivation_facade:
        errors.append("offline signer derivation facade must expose bip32")
    if "pub mod model;" not in transaction_facade:
        errors.append("offline signer transaction facade must expose model")
    bip32_legacy = offline_root / "derivation/bip32.rs"
    bip32_root = offline_root / "derivation/bip32"
    if bip32_legacy.exists():
        errors.append("legacy monolithic offline-signer derivation/bip32.rs must not exist")
    for required in (
        bip32_root / "mod.rs",
        bip32_root / "constants.rs",
        bip32_root / "error.rs",
        bip32_root / "extended_private.rs",
        bip32_root / "extended_public.rs",
        bip32_root / "child.rs",
        bip32_root / "paths.rs",
        bip32_root / "address_lookup.rs",
        bip32_root / "scalar.rs",
    ):
        if not required.exists():
            errors.append(f"required offline BIP32 module is missing: {required.relative_to(ROOT)}")
    for path in bip32_root.glob("*.rs"):
        line_count = len(path.read_text().splitlines())
        if line_count > 350:
            errors.append(
                f"offline BIP32 module exceeds 350-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    if (bip32_root / "mod.rs").exists() and len((bip32_root / "mod.rs").read_text().splitlines()) > 120:
        errors.append("offline BIP32 mod.rs must remain declarations and exports only")

    model_legacy = offline_root / "transaction/model.rs"
    model_root = offline_root / "transaction/model"
    if model_legacy.exists():
        errors.append("legacy monolithic offline-signer transaction/model.rs must not exist")
    for required in (
        model_root / "mod.rs",
        model_root / "constants.rs",
        model_root / "sighash_type.rs",
        model_root / "script.rs",
        model_root / "signatures.rs",
        model_root / "input.rs",
        model_root / "output.rs",
        model_root / "transaction.rs",
        model_root / "multisig.rs",
    ):
        if not required.exists():
            errors.append(f"required transaction model module is missing: {required.relative_to(ROOT)}")
    for path in model_root.glob("*.rs"):
        line_count = len(path.read_text().splitlines())
        if line_count > 300:
            errors.append(
                f"transaction model module exceeds 300-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
    if (model_root / "mod.rs").exists() and len((model_root / "mod.rs").read_text().splitlines()) > 120:
        errors.append("transaction model mod.rs must remain declarations and exports only")

    retired_path = re.compile(
        r"\boffline_signer::(?:bip32|bip39|bip39_wordlist|bip85|ecies|hmac|kspt|"
        r"pbkdf2|schnorr|sighash|std_pskt|xpub)\b|"
        r"\boffline_signer::transaction::(?:Transaction|TransactionInput|TransactionOutput|"
        r"ScriptPublicKey|ScriptType|SigHashType|MultisigConfig|MultisigStore)\b"
    )
    for source_root in (ROOT / "apps", ROOT / "crates", ROOT / "tools", ROOT / "qa"):
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.rs"):
            match = retired_path.search(path.read_text(errors="ignore"))
            if match:
                errors.append(
                    f"retired offline-signer crate-root path remains in {path.relative_to(ROOT)}: "
                    f"{match.group(0)}"
                )

    return errors
def _check_xpub_and_sighash(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    offline_root = ROOT / "crates/offline-signer/src"
    derivation_facade = (offline_root / "derivation/mod.rs").read_text(errors="ignore")
    transaction_facade = (offline_root / "transaction/mod.rs").read_text(errors="ignore")
    if "pub mod xpub;" not in derivation_facade:
        errors.append("offline signer derivation facade must expose xpub")
    if "pub mod sighash;" not in transaction_facade:
        errors.append("offline signer transaction facade must expose sighash")

    xpub_legacy = offline_root / "derivation/xpub.rs"
    xpub_root = offline_root / "derivation/xpub"
    xpub_limits = {
        "mod.rs": 80,
        "base58.rs": 240,
        "constants.rs": 60,
        "fingerprint.rs": 40,
        "kpub.rs": 320,
        "xprv.rs": 140,
    }
    if xpub_legacy.exists():
        errors.append("legacy monolithic offline-signer derivation/xpub.rs must not exist")
    actual_xpub = {path.name for path in xpub_root.glob("*.rs")}
    if actual_xpub != set(xpub_limits):
        errors.append(
            f"offline xpub module inventory changed: expected {sorted(xpub_limits)}, "
            f"got {sorted(actual_xpub)}"
        )
    xpub_source = ""
    for name, limit in xpub_limits.items():
        path = xpub_root / name
        if not path.exists():
            errors.append(f"required offline xpub module is missing: {path.relative_to(ROOT)}")
            continue
        source = path.read_text(errors="ignore")
        xpub_source += "\n" + source
        if len(source.splitlines()) > limit:
            errors.append(
                f"offline xpub module exceeds SRP limit: {path.relative_to(ROOT)} "
                f"({len(source.splitlines())} > {limit})"
            )
    xpub_facade = (xpub_root / "mod.rs").read_text(errors="ignore") if xpub_root.exists() else ""
    for symbol in (
        "KPUB_MAX_LEN", "XPUB_PAYLOAD_LEN", "XPRV_MAX_LEN", "serialize_kpub",
        "derive_and_serialize_kpub", "derive_account_raw_kpub_payload", "kpub_text_to_raw",
        "derive_and_serialize_xprv", "import_xprv", "import_kpub", "import_kpub_raw", "import_kpub_qr",
    ):
        if symbol not in xpub_facade:
            errors.append(f"offline xpub façade is missing required export: {symbol}")
    if len(re.findall(r"\bfn\s+base58check_encode\b", xpub_source)) != 1:
        errors.append("offline xpub subsystem must contain exactly one Base58Check encoder")
    if len(re.findall(r"\bfn\s+base58check_decode\b", xpub_source)) != 1:
        errors.append("offline xpub subsystem must contain exactly one Base58Check decoder")

    sighash_legacy = offline_root / "transaction/sighash.rs"
    sighash_root = offline_root / "transaction/sighash"
    sighash_limits = {
        "mod.rs": 80,
        "blake2b.rs": 280,
        "components.rs": 220,
        "digest.rs": 220,
        "signing.rs": 80,
    }
    if sighash_legacy.exists():
        errors.append("legacy monolithic offline-signer transaction/sighash.rs must not exist")
    actual_sighash = {path.name for path in sighash_root.glob("*.rs")}
    if actual_sighash != set(sighash_limits):
        errors.append(
            f"offline sighash module inventory changed: expected {sorted(sighash_limits)}, "
            f"got {sorted(actual_sighash)}"
        )
    sighash_source = ""
    for name, limit in sighash_limits.items():
        path = sighash_root / name
        if not path.exists():
            errors.append(f"required offline sighash module is missing: {path.relative_to(ROOT)}")
            continue
        source = path.read_text(errors="ignore")
        sighash_source += "\n" + source
        if len(source.splitlines()) > limit:
            errors.append(
                f"offline sighash module exceeds SRP limit: {path.relative_to(ROOT)} "
                f"({len(source.splitlines())} > {limit})"
            )
    sighash_facade = (sighash_root / "mod.rs").read_text(errors="ignore") if sighash_root.exists() else ""
    for symbol in ("KaspaBlake2b", "blake2b_hash", "calculate_sighash", "sign_input"):
        if symbol not in sighash_facade:
            errors.append(f"offline sighash façade is missing required export: {symbol}")
    if len(re.findall(r"\bpub\s+struct\s+KaspaBlake2b\b", sighash_source)) != 1:
        errors.append("offline sighash subsystem must contain exactly one keyed Blake2b implementation")
    if len(re.findall(r"\bpub\s+fn\s+calculate_sighash\b", sighash_source)) != 1:
        errors.append("offline sighash subsystem must contain exactly one digest assembler")
    if re.search(r"\bfn\s+blake2b_keyed\b", sighash_source):
        errors.append("offline signer retains unused blake2b_keyed helper")

    return errors

def _check_password_kdf_policy(root: Path) -> list[str]:
    errors: list[str] = []
    offline_root = root / "crates/offline-signer/src"
    password_kdf = offline_root / "crypto/password_kdf.rs"
    legacy_kdf = offline_root / "crypto/legacy_pbkdf2.rs"
    password_tests = offline_root / "crypto/unit_tests/password_kdf_tests.rs"
    legacy_tests = offline_root / "crypto/unit_tests/legacy_pbkdf2_tests.rs"
    retired_source = offline_root / "crypto/pbkdf2.rs"
    retired_tests = offline_root / "crypto/unit_tests/pbkdf2_tests.rs"
    bip39 = offline_root / "derivation/bip39/seed.rs"

    for path in (password_kdf, legacy_kdf, password_tests, legacy_tests, bip39):
        if not path.exists():
            errors.append(f"password-KDF contract file is missing: {path.relative_to(root)}")
    if retired_source.exists() or retired_tests.exists():
        errors.append("generic crypto/pbkdf2 module must stay retired; PBKDF2 is BIP39/legacy-only")
    if errors:
        return errors

    current = password_kdf.read_text(errors="ignore")
    legacy = legacy_kdf.read_text(errors="ignore")
    bip39_source = bip39.read_text(errors="ignore")
    for token in (
        "Algorithm::Argon2id", "Version::V0x13", "PasswordKdfPurpose",
        "try_reserve_exact", "AllocationFailed", "UnsupportedParameters",
        "parameters.is_current()", "derive_key_32_with_workspace",
        "workspace_block_count", "zeroize_workspace", "PasswordKdfBlock",
    ):
        if token not in current:
            errors.append(f"central Argon2 password-KDF contract missing: {token}")
    for forbidden in ("derive_legacy_32", "pbkdf2_hmac", "LEGACY_PBKDF2_ROUNDS"):
        if forbidden in current:
            errors.append(f"current Argon2 password-KDF implementation contains legacy PBKDF2 logic: {forbidden}")
    for token in ("Restore-only PBKDF2-HMAC-SHA256", "derive_legacy_32", "derive_legacy_32_progress"):
        if token not in legacy:
            errors.append(f"legacy PBKDF2 reader contract missing: {token}")

    for token in (
        "PBKDF2-HMAC-SHA512", "BIP39_PBKDF2_ROUNDS: u16 = 2048",
        "pbkdf2_hmac_sha512", "iterations=2048", "dklen=64",
    ):
        if token not in bip39_source:
            errors.append(f"BIP39 standard KDF contract changed: {token}")
    for forbidden in ("password_kdf", "Argon2", "legacy_pbkdf2"):
        if forbidden in bip39_source:
            errors.append(f"BIP39 seed derivation must remain outside KasSigner password KDFs: {forbidden}")

    # Direct legacy PBKDF2 use is limited to explicitly version-selected deployed
    # compatibility readers plus their self-tests. New/current writers must use
    # password_kdf and must never probe/fallback after an Argon2 failure.
    allowed_legacy_callers = {
        Path("crates/offline-signer/src/crypto/legacy_pbkdf2.rs"),
        Path("crates/offline-signer/src/crypto/unit_tests/legacy_pbkdf2_tests.rs"),
        Path("apps/signer-firmware/src/services/persistent_wallet/kdf/mod.rs"),
        Path("apps/signer-firmware/src/services/backup/container.rs"),
        Path("apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/crypto.rs"),
        Path("apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/crypto/unit_tests/mod.rs"),
        Path("apps/signer-firmware/src/runtime/unit_tests/software.rs"),
        Path("apps/signer-firmware/src/qemu/validation/target.rs"),
    }
    for source_root in (root / "apps", root / "crates"):
        for path in source_root.rglob("*.rs"):
            relative = path.relative_to(root)
            text = path.read_text(errors="ignore")
            uses_legacy = "legacy_pbkdf2::" in text or "derive_legacy_32" in text
            if uses_legacy and relative not in allowed_legacy_callers:
                errors.append(f"legacy PBKDF2 call escaped the allowlist: {relative}")
            if re.search(r"\bpbkdf2_hmac(?:_sha256)?\b", text) and relative != Path("crates/offline-signer/src/derivation/bip39/seed.rs"):
                errors.append(f"new generic PBKDF2 implementation is forbidden outside BIP39: {relative}")

    explicit_readers = {
        (
            "apps/signer-firmware/src/services/backup/container.rs",
            "crates/offline-signer/src/crypto/container_framing.rs",
        ): ("KASDB005", "KASDB004", "BackupReaderKdf::Argon2id", "BackupReaderKdf::LegacyPbkdf2"),
        (
            "apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/crypto.rs",
            "crates/offline-signer/src/crypto/container_framing.rs",
        ): ("KAS\\x04", "KAS\\x03", "open_current", "open_legacy"),
        (
            "apps/signer-firmware/src/services/persistent_wallet/crypto.rs",
            "apps/signer-firmware/src/services/persistent_wallet/crypto/record.rs",
        ): ("KSWLT004", "KSWLT003", "parse_current", "parse_legacy"),
    }
    for names, tokens in explicit_readers.items():
        text = "\n".join((root / name).read_text(errors="ignore") for name in names)
        label = " + ".join(names)
        for token in tokens:
            if token not in text:
                errors.append(f"explicit current/legacy KDF selector missing in {label}: {token}")
        if re.search(r"argon2.*(?:or_else|unwrap_or_else).*pbkdf2", text, re.I | re.S):
            errors.append(f"automatic Argon2-to-PBKDF2 fallback is forbidden: {label}")
    return errors


def _check_offline_protocol_hygiene(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    offline_root = ROOT / "crates/offline-signer/src"
    online_root = ROOT / "crates/online-watcher/src"
    online_source = "\n".join(path.read_text(errors="ignore") for path in online_root.rglob("*.rs"))
    legacy_storage = offline_root / "storage"
    if legacy_storage.exists():
        errors.append("dormant offline-signer PIN/storage subsystem must not return")
    errors.extend(_check_password_kdf_policy(root))

    qr_payload_source = (ROOT / "crates/kassigner-protocol/src/wire/qr_payload.rs").read_text(errors="ignore")
    if "#[allow(dead_code)]" in qr_payload_source:
        errors.append("public QR compatibility constants must not use dead-code suppression")

    if "#[path" in online_source:
        errors.append("online watcher must use ordinary Rust module structure, not #[path] wiring")
    if "#[allow(dead_code)]" in online_source:
        errors.append("online watcher contains retained dead code")
    for forbidden_pattern, description in (
        (r"\bkspt::create_", "legacy KSPT transaction builder"),
        (r"\bserialize_pskb_(?:single_sig|with_covenants)", "legacy PSKB serializer"),
    ):
        if re.search(forbidden_pattern, online_source):
            errors.append(f"online watcher retains {description}")

    return errors

def check(root: Path) -> list[str]:
    return [
        *check_pskt(root),
        *check_kspt(root),
        *_check_bip32_and_transaction_models(root),
        *_check_xpub_and_sighash(root),
        *_check_offline_protocol_hygiene(root),
    ]
