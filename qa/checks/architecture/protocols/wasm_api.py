"""Hard ownership boundaries for the grouped online-watcher WASM API."""

from __future__ import annotations

from pathlib import Path


def check(root: Path) -> list[str]:
    errors: list[str] = []
    api = root / "crates/online-watcher/src/wasm_api"
    expected_groups = {"contracts", "privacy", "protocol", "transactions", "utilities", "wallet"}
    actual_groups = {path.name for path in api.iterdir() if path.is_dir()} if api.exists() else set()
    direct_files = {path.name for path in api.glob("*.rs")} if api.exists() else set()
    if actual_groups != expected_groups:
        errors.append(f"wasm_api groups changed: expected {sorted(expected_groups)}, got {sorted(actual_groups)}")
    if direct_files != {"mod.rs"}:
        errors.append(f"wasm_api root must be a façade only, got direct files {sorted(direct_files)}")
    legacy = {
        "account.rs", "address.rs", "common.rs", "covenant.rs", "covenant_payload.rs",
        "crypto.rs", "keys.rs", "pskb_planning.rs", "pskt.rs", "qr.rs", "watcher.rs",
    }
    restored = sorted(name for name in legacy if (api / name).exists())
    if restored:
        errors.append(f"flat wasm_api compatibility modules must not return: {restored}")
    source = "\n".join(path.read_text(errors="ignore") for path in api.rglob("*.rs"))
    if "#[path" in source:
        errors.append("wasm_api grouping must use normal Rust modules, not path aliases")
    contracts_mod = (api / "contracts/mod.rs").read_text(errors="ignore")
    for required in ("mod payload;", "mod wasm;", "pub use payload::*;", "pub use wasm::*;"):
        if required not in contracts_mod:
            errors.append(f"contracts WASM façade lost required export: {required}")
    vault_root = api / "contracts/vault"
    expected_vault_modules = {"mod.rs", "spend.rs", "genesis.rs", "tagged.rs", "split.rs"}
    actual_vault_modules = {path.name for path in vault_root.glob("*.rs")}
    if actual_vault_modules != expected_vault_modules:
        errors.append(
            "vault WASM boundary changed: "
            f"expected {sorted(expected_vault_modules)}, got {sorted(actual_vault_modules)}"
        )
    vault_facade = (vault_root / "mod.rs").read_text(errors="ignore")
    for required in ("mod genesis;", "mod spend;", "mod split;", "mod tagged;"):
        if required not in vault_facade:
            errors.append(f"vault WASM façade lost module boundary: {required}")
    global_thread = api / "contracts/covenant/global_thread"
    if {path.name for path in global_thread.glob("*.rs")} != {"mod.rs", "boundary.rs", "planning.rs"}:
        errors.append("global-thread WASM boundary must remain a thin mod/boundary/planning adapter")
    return errors
