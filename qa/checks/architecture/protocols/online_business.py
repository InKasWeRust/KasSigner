"""KasSee/WASM business-ownership architecture contracts."""

from __future__ import annotations

from pathlib import Path
import re

def _check_shared_pskb_planning(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    for adapter_root in (wasm_boundary_root / "contracts", wasm_boundary_root / "privacy"):
        for adapter in adapter_root.rglob("*.rs"):
            source = adapter.read_text(errors="ignore")
            if 'extend_from_slice(b"PSKB")' in source or "serde_json::json!([pskt])" in source:
                errors.append(
                    f"PSKB envelope assembly bypasses the shared planner: {adapter.relative_to(ROOT)}"
                )

    global_thread_adapters = (
        wasm_boundary_root / "contracts/covenant/families/allowance/global.rs",
        wasm_boundary_root / "contracts/covenant/families/spending_limit/global.rs",
    )
    for adapter in global_thread_adapters:
        if not adapter.exists():
            continue
        source = adapter.read_text(errors="ignore")
        if len(source.splitlines()) > 180:
            errors.append(
                f"global-thread WASM adapter is too large: {adapter.relative_to(ROOT)}"
            )
        for required_call in (
            "create_withdrawal",
            "create_topup",
        ):
            if required_call not in source:
                errors.append(
                    f"global-thread adapter bypasses shared {required_call}: "
                    f"{adapter.relative_to(ROOT)}"
                )
        for forbidden_fragment in (
            '"previousOutpoint"',
            '"covenantBinding"',
            "encode_pskt_value",
        ):
            if forbidden_fragment in source:
                errors.append(
                    f"global-thread adapter contains duplicated PSKB construction: "
                    f"{adapter.relative_to(ROOT)} contains {forbidden_fragment}"
                )

    shared_global_thread_adapter = wasm_boundary_root / "contracts/covenant/global_thread"
    core_global_thread = online_root / "transaction_builder/covenant/global_thread.rs"
    if shared_global_thread_adapter.exists():
        shared_source = "\n".join(
            path.read_text(errors="ignore") for path in shared_global_thread_adapter.glob("*.rs")
        )
        for forbidden in (
            "network::queries",
            "plan_global_thread_withdrawal",
            "plan_global_thread_topup",
            "fn decode_redeem_script",
            "fn decode_covenant_id",
            "fn parse_thread_utxo",
            "fn select_wallet_utxos",
        ):
            if forbidden in shared_source:
                errors.append(
                    f"global-thread business logic leaked into WASM boundary: {forbidden}"
                )
    if not core_global_thread.exists():
        errors.append("global-thread application planner must live under transaction_builder/covenant")
    else:
        core_source = core_global_thread.read_text(errors="ignore")
        for required_call in (
            "build_global_thread_withdrawal",
            "prepare_global_thread_topup_material",
            "build_global_thread_topup",
        ):
            if required_call not in core_source:
                errors.append(f"global-thread core planner lost {required_call}")

    shared_global_thread_paths = [
        *shared_global_thread_adapter.glob("*.rs"),
        core_global_thread,
        online_root / "transaction_builder/pskb/global_thread.rs",
        online_root / "transaction_builder/pskb/thread_input.rs",
        online_root / "transaction_builder/pskb/thread_request.rs",
    ]
    for shared_path in shared_global_thread_paths:
        if shared_path.exists() and len(shared_path.read_text(errors="ignore").splitlines()) > 300:
            errors.append(
                f"shared global-thread module is too large: {shared_path.relative_to(ROOT)}"
            )

    return errors


def _check_wasm_business_boundary(root: Path) -> list[str]:
    """Keep transaction/covenant business policy out of browser bindings."""
    errors: list[str] = []
    online_root = root / "crates/online-watcher/src"
    wasm_root = online_root / "wasm_api"

    required_core_paths = (
        online_root / "serialization/input.rs",
        online_root / "transaction_builder/pskb/application.rs",
        online_root / "transaction_builder/covenant/global_thread.rs",
        online_root / "transaction_builder/covenant/allowance.rs",
        online_root / "transaction_builder/covenant/payjoin.rs",
        online_root / "transaction_builder/covenant/private_swap.rs",
        online_root / "transaction_builder/covenant/sweep.rs",
        online_root / "transaction_builder/covenant/sweeps/owner.rs",
        online_root / "transaction_builder/covenant/sweeps/savings.rs",
        online_root / "transaction_builder/covenant/sweeps/timelocked.rs",
        online_root / "transaction_builder/covenant/shipping/plan.rs",
        online_root / "transaction_builder/covenant/vault/spend.rs",
        online_root / "transaction_builder/covenant/oracle_v1.rs",
        online_root / "transaction_builder/stealth.rs",
        online_root / "transaction_builder/oracle_publish/plan.rs",
        online_root / "transaction_builder/zk/merkle.rs",
        online_root / "transaction_builder/zk/crowdfund.rs",
        online_root / "transaction_builder/zk/commit_reveal.rs",
        online_root / "contracts/covenant/oracle_v1.rs",
        online_root / "contracts/covenant/construction/mod.rs",
        online_root / "contracts/covenant/construction/additive.rs",
        online_root / "contracts/covenant/construction/allowance.rs",
        online_root / "contracts/covenant/construction/dms.rs",
        online_root / "contracts/covenant/construction/escrow.rs",
        online_root / "contracts/covenant/construction/payjoin.rs",
        online_root / "contracts/covenant/construction/private_swap.rs",
        online_root / "contracts/covenant/construction/savings.rs",
        online_root / "contracts/covenant/construction/spending_limit.rs",
        online_root / "contracts/oracle/genesis.rs",
        online_root / "contracts/shipping_escrow/construction.rs",
        online_root / "contracts/merkle/application.rs",
        online_root / "contracts/zk/crowdfund.rs",
        online_root / "contracts/commit_reveal/application.rs",
    )
    for path in required_core_paths:
        if not path.exists():
            errors.append(
                f"production WASM/domain extraction module is missing: {path.relative_to(root)}"
            )

    direct_rpc_allowlist = {Path("wallet/watcher.rs")}
    forbidden_fragments = (
        ("network::submission", "transaction submission"),
        ("transaction_builder::selection", "UTXO selection"),
        ("PskbPlan {", "PSKB plan assembly"),
        ("PskbInputPlan::", "PSKB input assembly"),
        ("PskbOutputPlan::", "PSKB output assembly"),
        ("PskbGlobalPlan::", "PSKB global policy"),
        ("SweepInputPolicy::", "sweep input policy"),
        ("encode_pskt_value", "raw PSKB encoding"),
        ('"previousOutpoint"', "raw PSKB input schema"),
        ('"partialSigs"', "raw PSKB signature schema"),
        ('"covenantBinding"', "raw covenant-binding schema"),
    )
    checked_arithmetic = re.compile(r"\.checked_(?:add|sub|mul)\s*\(")

    for path in wasm_root.rglob("*.rs"):
        if "unit_tests" in path.parts:
            continue
        relative = path.relative_to(wasm_root)
        source = path.read_text(errors="ignore")
        if "network::queries" in source and relative not in direct_rpc_allowlist:
            errors.append(
                f"network-backed business acquisition leaked into WASM boundary: {relative}"
            )
        if checked_arithmetic.search(source):
            errors.append(f"checked monetary/business arithmetic leaked into WASM boundary: {relative}")
        for fragment, description in forbidden_fragments:
            if fragment in source:
                errors.append(f"{description} leaked into WASM boundary: {relative}")

        contract_business_roots = ("contracts/covenant/", "contracts/vault/", "contracts/oracle/", "contracts/zk/")
        if str(relative).startswith(contract_business_roots):
            code_source = "\n".join(
                line for line in source.splitlines()
                if not line.lstrip().startswith("//")
            )
            for fragment, description in (
                ("getrandom::getrandom", "covenant identity/RNG policy"),
                ("script_to_address(", "covenant address construction"),
                ("address_to_script_pubkey(", "covenant address validation/conversion"),
                ("serde_json::json!", "covenant response/business DTO construction"),
            ):
                if fragment in code_source:
                    errors.append(f"{description} leaked into WASM contract boundary: {relative}")
            if re.search(r"(?:build|create)_[A-Za-z0-9_]*(?:script|redeem)\s*\(", code_source):
                errors.append(f"covenant script construction leaked into WASM contract boundary: {relative}")

    adapter_limits = {
        Path("contracts/vault/genesis.rs"): 80,
        Path("contracts/vault/spend.rs"): 80,
        Path("contracts/covenant/global_thread/planning.rs"): 40,
        Path("contracts/oracle/publish/context.rs"): 10,
        Path("contracts/oracle/publish/plan.rs"): 10,
        Path("contracts/oracle/publish/request.rs"): 10,
        Path("privacy/stealth/spend.rs"): 80,
    }
    for relative, limit in adapter_limits.items():
        path = wasm_root / relative
        if path.exists() and len(path.read_text(errors="ignore").splitlines()) > limit:
            errors.append(f"WASM adapter is too large for a binding boundary: {relative}")

    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_shared_pskb_planning(root),
        *_check_wasm_business_boundary(root),
    ]
