from __future__ import annotations

from pathlib import Path
import hashlib
import re

from architecture.core.common import rust_function_lengths
from architecture.protocols import online_business

def _check_browser_boundary(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    required_wasm_boundary_paths = (
        wasm_boundary_root / "mod.rs",
        wasm_boundary_root / "contracts/mod.rs",
        wasm_boundary_root / "contracts/covenant.rs",
        wasm_boundary_root / "contracts/oracle.rs",
        wasm_boundary_root / "contracts/vault/mod.rs",
        wasm_boundary_root / "contracts/zk.rs",
        wasm_boundary_root / "privacy/mod.rs",
        wasm_boundary_root / "privacy/stealth.rs",
        infrastructure_root / "browser_log.rs",
        infrastructure_root / "browser_websocket.rs",
    )
    for required in required_wasm_boundary_paths:
        if not required.exists():
            errors.append(f"required WASM boundary module is missing: {required.relative_to(ROOT)}")

    return errors

def _check_contract_inventory(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    required_contract_family_paths = (
        wasm_boundary_root / "contracts/covenant/global_thread/mod.rs",
        wasm_boundary_root / "contracts/covenant/global_thread/planning.rs",
        wasm_boundary_root / "contracts/covenant/global_thread/boundary.rs",
        wasm_boundary_root / "contracts/covenant/families/additive.rs",
        wasm_boundary_root / "contracts/covenant/families/savings.rs",
        wasm_boundary_root / "contracts/covenant/families/escrow.rs",
        wasm_boundary_root / "contracts/covenant/families/escrow/timelocked.rs",
        wasm_boundary_root / "contracts/covenant/families/escrow/shipping/mod.rs",
        wasm_boundary_root / "contracts/covenant/families/allowance.rs",
        wasm_boundary_root / "contracts/covenant/families/allowance/local.rs",
        wasm_boundary_root / "contracts/covenant/families/allowance/global.rs",
        wasm_boundary_root / "contracts/covenant/families/spending_limit.rs",
        wasm_boundary_root / "contracts/covenant/families/spending_limit/local.rs",
        wasm_boundary_root / "contracts/covenant/families/spending_limit/global.rs",
        wasm_boundary_root / "contracts/covenant/families/private_swap.rs",
        wasm_boundary_root / "contracts/covenant/families/payjoin.rs",
        wasm_boundary_root / "contracts/oracle/genesis.rs",
        wasm_boundary_root / "contracts/oracle/publish.rs",
        wasm_boundary_root / "contracts/oracle/publish/request.rs",
        wasm_boundary_root / "contracts/oracle/publish/context.rs",
        wasm_boundary_root / "contracts/oracle/publish/plan.rs",
        wasm_boundary_root / "contracts/zk/hashes.rs",
        wasm_boundary_root / "contracts/zk/merkle.rs",
        wasm_boundary_root / "contracts/zk/commit_reveal.rs",
        wasm_boundary_root / "privacy/stealth/meta.rs",
        wasm_boundary_root / "privacy/stealth/spend.rs",
        wasm_boundary_root / "privacy/stealth/payment.rs",
        online_root / "contracts/covenant/script/savings.rs",
        online_root / "contracts/covenant/script/escrow.rs",
        online_root / "contracts/covenant/script/spending_limit.rs",
        online_root / "contracts/covenant/script/allowance.rs",
        online_root / "contracts/covenant/script/dms.rs",
        online_root / "contracts/covenant/script/private_swap.rs",
        online_root / "contracts/covenant/script/payjoin.rs",
        online_root / "transaction_builder/pskb/mod.rs",
        online_root / "transaction_builder/pskb/model.rs",
        online_root / "transaction_builder/pskb/global_thread.rs",
        online_root / "transaction_builder/pskb/preparation.rs",
        online_root / "transaction_builder/pskb/thread_input.rs",
        online_root / "transaction_builder/pskb/thread_request.rs",
        online_root / "transaction_builder/pskb/sweep.rs",
        online_root / "transaction_builder/pskb/encoder.rs",
        wasm_boundary_root / "protocol/pskb_planning.rs",
    )
    for required in required_contract_family_paths:
        if not required.exists():
            errors.append(f"required contract-family module is missing: {required.relative_to(ROOT)}")

    contract_facades = (
        wasm_boundary_root / "contracts/covenant.rs",
        wasm_boundary_root / "contracts/oracle.rs",
        wasm_boundary_root / "contracts/zk.rs",
        wasm_boundary_root / "privacy/stealth.rs",
        online_root / "contracts/covenant/script.rs",
    )
    for facade in contract_facades:
        if facade.exists() and len(facade.read_text(errors="ignore").splitlines()) > 80:
            errors.append(f"contract facade is too large: {facade.relative_to(ROOT)}")

    contract_implementation_roots = (
        wasm_boundary_root / "contracts/covenant",
        wasm_boundary_root / "contracts/oracle",
        wasm_boundary_root / "contracts/zk",
        wasm_boundary_root / "privacy/stealth",
        online_root / "contracts/covenant/script",
        online_root / "transaction_builder/pskb",
    )
    for implementation_root in contract_implementation_roots:
        if not implementation_root.exists():
            continue
        for implementation in implementation_root.rglob("*.rs"):
            line_count = len(implementation.read_text(errors="ignore").splitlines())
            if line_count > 500:
                errors.append(
                    f"contract implementation module is too large: "
                    f"{implementation.relative_to(ROOT)} has {line_count} lines"
                )

    return errors

def _check_browser_boundary_placement(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    for legacy_api in (
        online_root / "contracts/covenant/api.rs",
        online_root / "contracts/oracle/api.rs",
        online_root / "contracts/seq_commit/api.rs",
        online_root / "contracts/vault/api.rs",
        online_root / "contracts/zk/api.rs",
        online_root / "privacy/stealth/api.rs",
    ):
        if legacy_api.exists():
            errors.append(f"browser API implementation leaked into domain tree: {legacy_api.relative_to(ROOT)}")

    for path in online_root.rglob("*.rs"):
        if "unit_tests" in path.parts:
            continue
        relative = path.relative_to(online_root)
        source = path.read_text(errors="ignore")
        inside_wasm_boundary = relative.parts[0] == "wasm_api"
        inside_infrastructure = relative.parts[0] == "infrastructure"
        if "#[wasm_bindgen" in source and not inside_wasm_boundary:
            errors.append(f"wasm-bindgen export outside wasm_api/: {path.relative_to(ROOT)}")
        if not inside_wasm_boundary and not inside_infrastructure:
            for forbidden in ("JsValue", "wasm_bindgen", "web_sys", "js_sys", "serde_wasm_bindgen"):
                if forbidden in source:
                    errors.append(
                        f"browser concern outside wasm_api/ or infrastructure/: "
                        f"{path.relative_to(ROOT)} contains {forbidden}"
                    )

    return errors

def _check_rpc_subsystem(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    # transport stays in infrastructure; domain transaction logic stays outside
    # network; WatchWallet remains the only online business facade.
    legacy_rpc = ROOT / "crates/online-watcher/src/network/rpc.rs"
    online_root = ROOT / "crates/online-watcher/src"
    network_root = online_root / "network"
    if legacy_rpc.exists():
        errors.append("legacy monolithic network/rpc.rs must not exist")
    if (network_root / "transport").exists():
        errors.append("browser transport must live under infrastructure/, not network/")

    required_rpc_paths = (
        network_root / "mod.rs",
        network_root / "error.rs",
        network_root / "codec/primitives/reader.rs",
        network_root / "codec/primitives/writer.rs",
        network_root / "wrpc/request.rs",
        network_root / "wrpc/response.rs",
        network_root / "queries/utxos.rs",
        network_root / "submission/encoder.rs",
        network_root / "unit_tests/mod.rs",
        online_root / "infrastructure/browser_log.rs",
        online_root / "infrastructure/browser_websocket.rs",
        online_root / "protocol/transaction/consensus.rs",
        online_root / "protocol/transaction/signed_kspt.rs",
        online_root / "protocol/transaction/sighash.rs",
        online_root / "privacy/stealth/scanner.rs",
        online_root / "wasm_api/contracts/vault/spend.rs",
    )
    for required in required_rpc_paths:
        if not required.exists():
            errors.append(f"required RPC extraction module is missing: {required.relative_to(ROOT)}")

    network_production_files = [
        path for path in network_root.rglob("*.rs") if "unit_tests" not in path.parts
    ]
    network_source = "\n".join(path.read_text(errors="ignore") for path in network_production_files)
    online_source = "\n".join(
        path.read_text(errors="ignore")
        for path in online_root.rglob("*.rs")
        if "unit_tests" not in path.parts
    )

    for path in network_production_files:
        line_count = len(path.read_text().splitlines())
        if line_count > 500:
            errors.append(
                f"network module exceeds 500-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )
        for function_name, line_count in rust_function_lengths(path.read_text()):
            if line_count > 120:
                errors.append(
                    f"network function exceeds 120-line SRP limit: "
                    f"{path.relative_to(ROOT)}::{function_name} ({line_count} lines)"
                )

    for forbidden in (
        "wasm_bindgen",
        "JsValue",
        "web_sys",
        "js_sys",
        "Reflect",
        "console::",
        "#[allow(dead_code)]",
    ):
        if forbidden in network_source:
            errors.append(f"network subsystem contains forbidden concern: {forbidden}")

    for forbidden_pattern, description in (
        (r"\bcrate::rpc\b", "crate::rpc reference"),
        (r"\brpc::", "rpc compatibility path"),
        (r"\bmod\s+rpc\b", "rpc compatibility module"),
        (r"\b(?:build_request|bw_u8|bw_u16|bw_u32|bw_bytes|borsh_write_address)_pub\b", "legacy RPC wrapper"),
    ):
        if re.search(forbidden_pattern, online_source):
            errors.append(f"online watcher retains {description}")

    if len(re.findall(r"\bstruct\s+WireReader\b", network_source)) != 1:
        errors.append("network subsystem must contain exactly one bounded WireReader")
    if len(re.findall(r"\bstruct\s+WireWriter\b", network_source)) != 1:
        errors.append("network subsystem must contain exactly one checked WireWriter")
    if len(re.findall(r"\bfn\s+encode_submit_request\b", network_source)) != 1:
        errors.append("network subsystem must contain exactly one consensus submission encoder")
    if re.search(r"\bfn\s+compute_sighash\b", online_source):
        errors.append("retired simple sighash implementation must not return")
    if len(re.findall(r"\bfn\s+compute_full_sighash\b", online_source)) != 1:
        errors.append("online watcher must contain exactly one full consensus sighash implementation")
    if len(re.findall(r"\bfn\s+decode_signed_kspt\b", online_source)) != 1:
        errors.append("online watcher must contain exactly one signed KSPT decoder")
    if "create_oracle_mb_heartbeat_roll" in online_source:
        errors.append("obsolete standalone Oracle heartbeat-roll API must not return")

    opcode_source = (online_root / "protocol/script/opcode.rs").read_text(errors="ignore")
    dead_opcode_constants = {
        "OP_ROLL", "OP_SIZE", "OP_AND", "OP_OR_BITWISE", "OP_XOR",
        "OP_MUL", "OP_DIV", "OP_MOD", "OP_NUMEQUAL",
        "OP_TX_LOCKTIME", "OP_TX_PAYLOAD_SUBSTR", "OP_TX_INPUT_SPK_SUBSTR",
        "OP_AUTH_OUTPUT_IDX", "OP_OUTPUT_AUTHORIZING_INPUT",
    }
    restored_dead_opcodes = sorted(
        name for name in dead_opcode_constants
        if re.search(rf"(?m)^pub const {name}\b", opcode_source)
    )
    if restored_dead_opcodes:
        errors.append(f"unused opcode constants must not return: {restored_dead_opcodes}")

    return errors

def _check_wasm_exports(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    online_root = ROOT / "crates/online-watcher/src"
    wasm_boundary_root = online_root / "wasm_api"
    infrastructure_root = online_root / "infrastructure"
    # Preserve the existing JavaScript/WASM contract while internals move.
    wasm_boundary_source = "\n".join(
        path.read_text(errors="ignore")
        for path in wasm_boundary_root.rglob("*.rs")
        if "unit_tests" not in path.parts
    )
    wasm_exports = re.findall(
        r"#\[wasm_bindgen(?:\([^\]]*\))?\]\s*(?:#\[[^\]]+\]\s*)*"
        r"pub\s+(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
        wasm_boundary_source,
    )
    # Complete batched UTXO enumeration supports manual KasSee coin control.
    expected_count = 117
    expected_digest = "18736d24a37217164a7c6651afae81c5fbdd96eaeba3225edf8f02d681789e75"
    export_digest = hashlib.sha256("\n".join(sorted(wasm_exports)).encode()).hexdigest()
    if (
        len(wasm_exports) != expected_count
        or len(set(wasm_exports)) != expected_count
        or export_digest != expected_digest
    ):
        errors.append(
            f"default WASM export surface changed: expected {expected_count} unique functions / "
            f"{expected_digest}, got {len(set(wasm_exports))} unique / "
            f"{len(wasm_exports)} total / {export_digest}"
        )

    return errors

def check(root: Path) -> list[str]:
    return [
        *_check_browser_boundary(root),
        *_check_contract_inventory(root),
        *online_business.check(root),
        *_check_browser_boundary_placement(root),
        *_check_rpc_subsystem(root),
        *_check_wasm_exports(root),
    ]
