#!/usr/bin/env python3
"""Enforce the non-firmware watch-only boundary.

Only signer-firmware may possess or use wallet signing private keys. KasSee Web,
the online-watcher WASM core, iOS, and Android must operate from kpub/xpub
public material and route spend authorization to KasSigner.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

RETIRED_TOMBSTONES = (
    "apps/signer-firmware/src/runtime/interactions/sd/backup/seed_backup.rs",
    "apps/signer-firmware/src/runtime/interactions/sd/backup/seed_restore.rs",
    "apps/signer-firmware/src/ui/screens/storage/sd/warning.rs",
)

BROWSER_ROOT = "apps/kassee-web/web/js"
RETIRED_HOT_APIS = (
    "adaptor_generate_keypair",
    "adaptor_create_sig",
    "tagged_vault_keygen",
)
RETIRED_DIRECT_VAULT_CALLS = (
    "tagged_vault_genesis(",
    "tagged_vault_spend(",
    "split_vault_genesis(",
    "split_vault_spend(",
)

BROWSER_PRIVATE_IDENTIFIERS = re.compile(
    r"\b(?:privateKey|private_key|secretKey|secret_key|signingKey|signing_key|"
    r"walletSecret|wallet_secret|xprv|mnemonic|mySecretKey|secretKeyHex|secret_key_hex|sk)\b"
)
RUST_PRIVATE_IDENTIFIERS = re.compile(
    r"\b(?:SigningKey|SecretKey|private_key|secret_key|signer_secret|wallet_secret|xprv|mnemonic)\b"
)
MOBILE_PRIVATE_IDENTIFIERS = re.compile(
    r"\b(?:SigningKey|SecretKey|PrivateKey|privateKey|secretKey|signingKey|xprv|mnemonic)\b"
)



def source_files(root: Path, suffixes: set[str]) -> list[Path]:
    return sorted(
        path for path in root.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and not any(part in {"target", "build", ".idea", "DerivedData"} for part in path.parts)
    )


def require_contains(errors: list[str], path: str, terms: tuple[str, ...]) -> None:
    source_path = ROOT / path
    if not source_path.is_file():
        errors.append(f"missing watcher-only evidence file: {path}")
        return
    source = source_path.read_text(errors="replace")
    for term in terms:
        if term not in source:
            errors.append(f"{path} missing watcher-only evidence {term!r}")


def audit() -> list[str]:
    errors: list[str] = []

    for relative in RETIRED_TOMBSTONES:
        if (ROOT / relative).exists():
            errors.append(f"retired dead tombstone returned: {relative}")

    browser_files = source_files(ROOT / BROWSER_ROOT, {".js"})
    for path in browser_files:
        source = path.read_text(errors="replace")
        relative = str(path.relative_to(ROOT))
        for api in RETIRED_HOT_APIS:
            if api in source:
                errors.append(f"{relative} reintroduces retired hot-wallet API {api!r}")
        for call in RETIRED_DIRECT_VAULT_CALLS:
            if call in source:
                errors.append(f"{relative} reintroduces direct browser vault signer {call!r}")
        match = BROWSER_PRIVATE_IDENTIFIERS.search(source)
        if match:
            errors.append(
                f"{relative} contains forbidden watcher private-key identifier {match.group(0)!r}"
            )

    # Production online-watcher source may perform public verification and
    # protocol-secret arithmetic, but it must not contain wallet-key signing
    # implementations. Unit-test fixtures are excluded from the shipped surface.
    watcher_root = ROOT / "crates/online-watcher/src"
    for path in source_files(watcher_root, {".rs"}):
        relative = str(path.relative_to(ROOT))
        if "unit_tests" in path.parts:
            continue
        source = path.read_text(errors="replace")
        match = RUST_PRIVATE_IDENTIFIERS.search(source)
        if match:
            errors.append(
                f"{relative} contains forbidden watcher wallet-key identifier {match.group(0)!r}"
            )
        for signer in ("fn bip340_sign", "fn create_adaptor_sig", "fn generate_signing_keypair"):
            if signer in source:
                errors.append(f"{relative} contains watcher-side signing implementation {signer!r}")

    # Mobile companions are also strictly watch-only.
    for app_root in ("apps/kassee-ios", "apps/kassee-android"):
        for path in source_files(ROOT / app_root, {".swift", ".kt", ".kts", ".java"}):
            source = path.read_text(errors="replace")
            match = MOBILE_PRIVATE_IDENTIFIERS.search(source)
            if match:
                errors.append(
                    f"{path.relative_to(ROOT)} contains forbidden mobile private-key identifier {match.group(0)!r}"
                )

    # Historical raw-signature adaptor-v1 modules must stay physically absent.
    # Private Swap v2 is permitted only through its transaction-sighash-bound
    # public verifier and hardware-signing protocol; watcher code remains keyless.
    for retired in (
        "apps/kassee-web/web/js/app/events/contracts/adaptor_swap.js",
        "apps/kassee-web/web/js/app/events/contracts/adaptor_swap",
        "apps/kassee-web/web/js/app/state/covenants/adaptor_state.js",
        "apps/kassee-web/web/js/features/covenants/payload_and_swaps/adaptor_policy.js",
        "apps/kassee-web/web/js/features/covenants/payload_and_swaps/adaptor_session_repository.js",
        "apps/kassee-web/web/js/features/covenants/payload_and_swaps/adaptor_watcher.js",
        "apps/kassee-web/web/js/features/covenants/payload_and_swaps/adaptor_watcher",
        "apps/kassee-web/web/js/features/covenants/recovery/scanner/historical_payload.js",
        "apps/kassee-web/web/js/features/covenants/recovery/scanner/primary/adaptor_swap.js",
        "apps/kassee-web/web/html/screens/covenant/create/adaptor_swap.html",
        "crates/online-watcher/src/privacy/adaptor",
        "crates/online-watcher/src/wasm_api/privacy/adaptor",
    ):
        if (ROOT / retired).exists():
            errors.append(f"retired raw-signature implementation returned: {retired}")
    require_contains(errors, "apps/kassee-web/web/js/app/events/contracts/tagged_vault/online.js", (
        "tagged_vault_genesis_pskb", "tagged_vault_spend_pskb", "split_vault_genesis_pskb",
        "split_vault_spend_pskb", "openPsktReview", "walletSession",
    ))
    require_contains(errors, "crates/online-watcher/src/transaction_builder/covenant/vault/spend.rs", (
        "PskbInputPlan::covenant", "encode_wire", "exactly one covenant UTXO",
    ))
    require_contains(errors, "crates/online-watcher/src/wasm_api/contracts/vault/spend.rs", (
        "crate::transaction_builder::covenant::vault::spend",
    ))
    require_contains(errors, "crates/online-watcher/src/wasm_api/contracts/vault/unit_tests/mod.rs", (
        "partialSigs", "watcher must not synthesize a wallet signature",
    ))

    return errors


def main() -> int:
    errors = audit()
    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        return 1
    print("PASS: non-firmware apps are watcher-only; spend authorization is hardware-bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
