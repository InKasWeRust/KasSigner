"""Architecture contracts for PSKT and compact KSPT protocol subsystems."""

from __future__ import annotations

from pathlib import Path
import re

from architecture.core.common import rust_function_lengths

def check_pskt(root: Path) -> list[str]:
    ROOT = root
    errors: list[str] = []
    # PSKT is a grouped protocol subsystem, never a monolithic source file.
    legacy_pskt = ROOT / "crates/online-watcher/src/protocol/pskt.rs"
    pskt_root = ROOT / "crates/online-watcher/src/protocol/pskt"
    if legacy_pskt.exists():
        errors.append("legacy monolithic protocol/pskt.rs must not exist")
    for required in (
        pskt_root / "mod.rs",
        pskt_root / "error.rs",
        pskt_root / "model/mod.rs",
        pskt_root / "model/format.rs",
        pskt_root / "model/signatures.rs",
        pskt_root / "model/summary.rs",
        pskt_root / "wire/mod.rs",
        pskt_root / "wire/json.rs",
        pskt_root / "review/mod.rs",
        pskt_root / "kspt_bridge/mod.rs",
        pskt_root / "consensus/mod.rs",
        pskt_root / "scripts/mod.rs",
        pskt_root / "unit_tests/mod.rs",
    ):
        if not required.exists():
            errors.append(f"required PSKT module is missing: {required.relative_to(ROOT)}")

    pskt_production_files = [
        path for path in pskt_root.rglob("*.rs") if "unit_tests" not in path.parts
    ]
    for path in pskt_production_files:
        line_count = len(path.read_text().splitlines())
        if line_count > 1000:
            errors.append(
                f"PSKT module exceeds 1,000-line SRP limit: "
                f"{path.relative_to(ROOT)} ({line_count} lines)"
            )

    pskt_source = "\n".join(path.read_text(errors="ignore") for path in pskt_production_files)
    pskt_core_source = "\n".join(
        path.read_text(errors="ignore")
        for path in pskt_production_files
        if "pskb" not in path.parts
    )
    pskb_source = "\n".join(
        path.read_text(errors="ignore")
        for path in pskt_production_files
        if "pskb" in path.parts
    )
    for forbidden in ("web_sys", "submit_consensus_tx", "encode_compact_kspt_input_relay"):
        if forbidden in pskt_source:
            errors.append(f"PSKT protocol subsystem contains forbidden concern: {forbidden}")
    if len(re.findall(r"\bfn\s+decode_wire\b", pskt_source)) != 1:
        errors.append("PSKT subsystem must contain exactly one wire decoder")
    if len(re.findall(r"serde_json::from_slice", pskt_core_source)) != 1:
        errors.append("PSKT subsystem must contain exactly one JSON body decoder")
    if len(re.findall(r"serde_json::to_vec", pskt_core_source)) != 1:
        errors.append("PSKT subsystem must contain exactly one JSON body encoder")
    if re.search(r"\bfn\s+encode_compact_kspt_input\b", pskt_source):
        errors.append("KasSee must not own a duplicate compact KSPT input wire encoder")
    if len(re.findall(r"serde_json::to_vec", pskb_source)) != 1:
        errors.append("PSKB subsystem must contain exactly one JSON encoder")
    subnetwork_decoder = pskt_root / "wire/json_fields.rs"
    subnetwork_source = subnetwork_decoder.read_text(errors="ignore") if subnetwork_decoder.exists() else ""
    if "missing subnetworkId" not in subnetwork_source or "unwrap_or_default" in subnetwork_source:
        errors.append("PSKT subnetwork decoding must require a valid explicit identifier")
    canonical_pskb_encoder = pskt_root / "pskb/encoder.rs"
    canonical_pskb_source = canonical_pskb_encoder.read_text(errors="ignore") if canonical_pskb_encoder.exists() else ""
    if '.entry("subnetworkId".to_string())' not in canonical_pskb_source:
        errors.append("canonical PSKB encoding must explicitly supply the native subnetwork")
    pskb_encoder = ROOT / "crates/online-watcher/src/transaction_builder/pskb/encoder.rs"
    pskb_encoder_source = pskb_encoder.read_text(errors="ignore") if pskb_encoder.exists() else ""
    if 'crate::protocol::pskt::pskb::encode_pskt_value(pskt)' not in pskb_encoder_source:
        errors.append("transaction-builder PSKB encoding must delegate to the canonical PSKB wire encoder")
    if '.entry("subnetworkId".to_string())' in pskb_encoder_source:
        errors.append("transaction-builder PSKB encoding must not duplicate native-subnetwork insertion")
    if re.search(r"\bfn\s+finalize_and_broadcast\b", pskt_source):
        errors.append("network broadcast orchestration must remain in WatchWallet")

    for path in pskt_production_files:
        for function_name, line_count in rust_function_lengths(path.read_text()):
            if line_count > 100:
                errors.append(
                    f"PSKT function exceeds 100-line SRP limit: "
                    f"{path.relative_to(ROOT)}::{function_name} ({line_count} lines)"
                )

    errors.extend(check_monetary_arithmetic(root))
    errors.extend(check_thin_covenant_boundaries(root))
    return errors

def check_thin_covenant_boundaries(root: Path) -> list[str]:
    errors: list[str] = []
    online_root = root / "crates/online-watcher/src"
    wasm_pskb = online_root / "wasm_api/protocol/pskb_planning.rs"
    wasm_global = online_root / "wasm_api/contracts/covenant/global_thread/planning.rs"
    core_preparation = online_root / "transaction_builder/pskb/preparation.rs"
    core_global = online_root / "transaction_builder/pskb/global_thread.rs"
    core_thread_input = online_root / "transaction_builder/pskb/thread_input.rs"
    core_thread_request = online_root / "transaction_builder/pskb/thread_request.rs"
    core_fee = online_root / "transaction_builder/covenant/fee.rs"
    browser_planner = root / "apps/kassee-web/web/js/features/transactions/send/compose/planners/covenant.js"

    for required in (core_preparation, core_global, core_thread_input, core_thread_request, core_fee, browser_planner):
        if not required.is_file():
            errors.append(f"thin covenant boundary dependency missing: {required.relative_to(root)}")

    if wasm_pskb.is_file():
        source = wasm_pskb.read_text(errors="ignore")
        for forbidden in (
            "fn require_sweep_utxos",
            "fn sweep_amounts",
            "fn require_sweep_balance",
            "fn sweep_scripts",
            "struct SelectedUtxo",
            "fn selected_utxo_entry",
            "fn checked_total",
        ):
            if forbidden in source:
                errors.append(
                    f"PSKB business logic leaked back into WASM adapter: {forbidden}"
                )
        for required_call in (
            "prepare_sweep_from_utxos_core",
            "prepare_selected_sweep_core",
            "encode_prepared_sweep_core",
        ):
            if required_call not in source:
                errors.append(f"thin PSKB WASM adapter bypasses core {required_call}")

    if wasm_global.is_file():
        source = wasm_global.read_text(errors="ignore")
        for forbidden in (
            "fn withdrawal_policy(", "fn topup_policy(", "fn decode_redeem_script",
            "fn decode_covenant_id", "fn parse_thread_utxo", "fn parse_withdrawal_thread_utxos",
            "fn select_wallet_utxos", "plan_global_thread_withdrawal", "plan_global_thread_topup",
        ):
            if forbidden in source:
                errors.append(
                    f"global-thread business logic leaked back into WASM adapter: {forbidden}"
                )
        application_source = (
            online_root / "transaction_builder/covenant/global_thread.rs"
        ).read_text(errors="ignore")
        if "transaction_builder::covenant::global_thread" not in source:
            errors.append("global-thread WASM adapter must remain a thin re-export of the browser-neutral application layer")
        for required_call in (
            "build_global_thread_withdrawal", "prepare_global_thread_topup_material",
            "build_global_thread_topup",
        ):
            if required_call not in application_source:
                errors.append(f"global-thread application layer bypasses core {required_call}")

    if browser_planner.is_file():
        source = browser_planner.read_text(errors="ignore")
        for forbidden in (
            "KIP9_MIN_CHANGE",
            "covenantDepositFee",
            "function selectedTotal",
            "function payloadAwareFee",
            "function prepareDepositAmount",
        ):
            if forbidden in source:
                errors.append(
                    f"covenant monetary policy leaked back into browser adapter: {forbidden}"
                )
        for required_call in ("estimate_covenant_fee", "covenant_type: covenantType"):
            if required_call not in source:
                errors.append(f"covenant browser adapter bypasses typed core intent: {required_call}")

    return errors


def check_monetary_arithmetic(root: Path) -> list[str]:
    """Keep wallet/transaction values on explicit checked-error paths."""
    errors: list[str] = []
    online_root = root / "crates/online-watcher/src"
    balance = (online_root / "account/balance.rs").read_text(errors="ignore")
    global_thread_path = online_root / "transaction_builder/pskb/global_thread.rs"
    global_thread = global_thread_path.read_text(errors="ignore")
    global_thread_topup = global_thread_path.with_suffix("") / "topup.rs"
    if global_thread_topup.exists():
        global_thread += "\n" + global_thread_topup.read_text(errors="ignore")
    covenant = (online_root / "transaction_builder/covenant/builder.rs").read_text(errors="ignore")
    covenant_fee = (online_root / "transaction_builder/covenant/fee.rs").read_text(errors="ignore")
    amounts = (online_root / "transaction_builder/planning/amounts.rs").read_text(errors="ignore")
    shipping_script = (online_root / "contracts/shipping_escrow/script.rs").read_text(errors="ignore")
    shipping_withdraw = (
        online_root / "transaction_builder/covenant/shipping/withdraw.rs"
    ).read_text(errors="ignore")
    payjoin = (
        online_root / "transaction_builder/covenant/payjoin.rs"
    ).read_text(errors="ignore")
    vault_spend = (
        online_root / "transaction_builder/covenant/vault/spend.rs"
    ).read_text(errors="ignore")
    vault_split = vault_spend
    review_parser = (
        online_root / "protocol/pskt/review/parser.rs"
    ).read_text(errors="ignore")

    if ".sum()" in balance or ".sum::<u64>()" in balance:
        errors.append("wallet balance aggregation must not use unchecked u64 sum")
    if "try_fold(0u64" not in balance or ".checked_add(entry.amount)" not in balance:
        errors.append("wallet balance aggregation must use checked_add with an explicit error")

    for forbidden in (
        ".map(|utxo| utxo.amount).sum", "thread_amount + wallet_total",
        "total - withdrawal", "withdrawal - fee",
    ):
        if forbidden in global_thread:
            errors.append(f"global-thread monetary arithmetic bypasses checked operations: {forbidden}")
    for required in (
        "checked_utxo_total(thread_utxos", "checked_utxo_total(wallet_utxos",
        ".checked_add(wallet_total)", "GlobalThreadPlanError::ArithmeticOverflow",
    ):
        if required not in global_thread:
            errors.append(f"global-thread checked arithmetic contract changed: {required}")

    for forbidden in (".sum::<u64>()", "total - plan.adjusted_send", "total - fee"):
        if forbidden in covenant:
            errors.append(f"covenant monetary arithmetic bypasses checked operations: {forbidden}")
    if "selection::checked_total(&plan.selected)?" not in covenant:
        errors.append("covenant output planning must use the shared checked UTXO total")
    if ".checked_sub(plan.adjusted_send)" not in covenant or ".checked_sub(plan.fee)" not in covenant:
        errors.append("covenant output planning must return an explicit underflow error")

    for required in (
        ".checked_mul(45 + 66 + 4)",
        ".checked_add(self.payload_bytes)",
        ".checked_mul(FEE_RATE)",
        "Result<u64, String>",
    ):
        if required not in covenant_fee:
            errors.append(f"covenant fee arithmetic must remain checked: {required}")
    for forbidden in (
        "input_count * (45 + 66 + 4)",
        "compute_mass * FEE_RATE",
    ):
        if forbidden in covenant_fee:
            errors.append(f"covenant fee arithmetic bypasses checked operations: {forbidden}")

    if "pub fn storage_mass_estimate" not in amounts or "-> Result<u64, String>" not in amounts:
        errors.append("storage-mass transaction planning must return checked arithmetic errors")
    if "saturating_add" in amounts or "saturating_mul" in amounts:
        errors.append("storage-mass transaction planning must not silently saturate overflow arithmetic")
    if (
        amounts.count(".saturating_sub(") != 1
        or "harmonic_outputs.saturating_sub(input_mass)" not in amounts
    ):
        errors.append(
            "storage-mass subtraction must only floor the final non-negative mass contribution"
        )
    for required in (
        ".checked_add(plurality)",
        ".checked_mul(plurality)",
        "checked_sum(ins.iter().map",
        ".checked_mul(STORAGE_MASS_C / mean_input)",
    ):
        if required not in amounts:
            errors.append(f"storage-mass checked arithmetic contract changed: {required}")

    for forbidden in ("product_sompi + fee_sompi", "total - first_tranche"):
        if forbidden in shipping_script:
            errors.append(f"shipping-escrow script arithmetic bypasses checked operations: {forbidden}")
    for required in (".checked_add(fee_sompi)", ".checked_sub(first_tranche)", "Result<Vec<u8>, String>"):
        if required not in shipping_script:
            errors.append(f"shipping-escrow script checked arithmetic contract changed: {required}")

    for forbidden in ("plan.funding_total - fee", "withdraw_sompi + funding_after_fee"):
        if forbidden in shipping_withdraw:
            errors.append(f"shipping withdrawal arithmetic bypasses checked operations: {forbidden}")
    for required in (".checked_sub(fee)", ".checked_add(funding_after_fee)"):
        if required not in shipping_withdraw:
            errors.append(f"shipping withdrawal checked arithmetic contract changed: {required}")

    for forbidden in ("fee - covenant_fee", ".saturating_sub("):
        if forbidden in payjoin:
            errors.append(f"PayJoin monetary arithmetic bypasses checked operations: {forbidden}")
    for required in (
        ".checked_add(mixing_utxo.amount)",
        ".checked_mul(3)",
        ".checked_sub(covenant_fee)",
        ".checked_sub(mixing_fee)",
    ):
        if required not in payjoin:
            errors.append(f"PayJoin checked arithmetic contract changed: {required}")

    if "spendable: total - fee" in vault_spend or "total - fee" in vault_spend:
        errors.append("vault spendable balance must not use raw subtraction")
    if ".checked_sub(fee)" not in vault_spend:
        errors.append("vault spendable balance must use checked_sub")
    if "prepared.spendable - amount_a" in vault_split:
        errors.append("vault split must not use raw subtraction")
    if ".checked_sub(amount_a)" not in vault_split:
        errors.append("vault split must use checked_sub")

    if "saturating_add" in review_parser or "saturating_sub" in review_parser:
        errors.append("PSKT review monetary totals must not silently saturate")
    for required in (
        "checked_total(total_sompi, summary.amount_sompi",
        ".checked_sub(outputs.total_sompi)",
        "PSKT outputs exceed inputs",
    ):
        if required not in review_parser:
            errors.append(f"PSKT review checked arithmetic contract changed: {required}")
    return errors

def check_kspt(root: Path) -> list[str]:
    errors: list[str] = []
    offline_root = root / "crates/offline-signer/src/transaction/kspt"
    bridge_root = root / "crates/online-watcher/src/protocol/pskt/kspt_bridge"
    protocol_wire = root / "crates/kassigner-protocol/src/wire/kspt"

    required_offline = (
        offline_root / "mod.rs",
        offline_root / "wire_adapter.rs",
        offline_root / "kssn_io.rs",
        offline_root / "signing/mod.rs",
        offline_root / "validation.rs",
    )
    required_protocol = (
        protocol_wire / "mod.rs",
        protocol_wire / "model.rs",
        protocol_wire / "io.rs",
        protocol_wire / "decode.rs",
        protocol_wire / "encode.rs",
        protocol_wire / "error.rs",
    )
    required_bridge = (
        bridge_root / "mod.rs",
        bridge_root / "signatures.rs",
        bridge_root / "parser_compact.rs",
        bridge_root / "parser_transaction.rs",
        bridge_root / "relay.rs",
        bridge_root / "merger.rs",
    )
    for required in (*required_offline, *required_protocol, *required_bridge):
        if not required.exists():
            errors.append(f"required compact KSPT module is missing: {required.relative_to(root)}")

    forbidden_files = (
        offline_root / "codec/unsigned.rs",
        offline_root / "codec/signed_v1.rs",
        bridge_root / "parser_v1.rs",
        bridge_root / "parser_v2.rs",
        bridge_root / "finalizer.rs",
    )
    for path in forbidden_files:
        if path.exists():
            errors.append(f"retired KSPT generation module remains: {path.relative_to(root)}")

    production_files = [
        path for base in (offline_root, protocol_wire, bridge_root)
        for path in base.rglob("*.rs")
        if "unit_tests" not in path.parts
    ]
    source = "\n".join(path.read_text(errors="ignore") for path in production_files)
    for path in production_files:
        line_count = len(path.read_text().splitlines())
        if line_count > 400:
            errors.append(
                f"compact KSPT module exceeds 400-line SRP limit: "
                f"{path.relative_to(root)} ({line_count} lines)"
            )
        for function_name, function_lines in rust_function_lengths(path.read_text()):
            if function_lines > 100:
                errors.append(
                    f"compact KSPT function exceeds 100-line SRP target: "
                    f"{path.relative_to(root)}::{function_name} ({function_lines} lines)"
                )

    for forbidden in (
        "GENERATION_V1", "GENERATION_V2", "parse_signed_pskt_v2",
        "serialize_signed_pskt_v2", "serialize_signed_pskt", "parse_pskt",
        "KsptV1", "KsptV2", "UnsignedEnvelopeFormat",
    ):
        if forbidden in source:
            errors.append(f"retired KSPT API remains: {forbidden}")
    wire_model = (protocol_wire / "model.rs").read_text(errors="ignore")
    wire_decode = (protocol_wire / "decode.rs").read_text(errors="ignore")
    wire_encode = (protocol_wire / "encode.rs").read_text(errors="ignore")
    if "GENERATION_CURRENT: u8 = 0x04" not in wire_model:
        errors.append("canonical compact KSPT current generation must remain exactly v4")
    duplicate_grammar_files = []
    for path in production_files:
        if path == protocol_wire / "model.rs":
            continue
        text = path.read_text(errors="ignore")
        if 'b"KSPT"' in text or re.search(r"(?:KSPT|COMPACT_KSPT).*0x04", text):
            duplicate_grammar_files.append(path.relative_to(root))
    if duplicate_grammar_files:
        errors.append(f"KSPT magic/generation wire knowledge must have one owner: {duplicate_grammar_files}")
    for marker in ("NETWORK_MARKER", "MS45_INPUT_MARKER", "MS45_OUTPUT_MARKER", "STEALTH_MARKER", "COVENANT_MARKER", "INPUT_DERIVATION_MARKER", "OUTPUT_DERIVATION_MARKER"):
        if marker not in wire_model:
            errors.append(f"canonical KSPT wire model is missing trailer marker: {marker}")
    if "reader.u8()? != GENERATION_CURRENT" not in wire_decode:
        errors.append("canonical compact KSPT decoder must accept only generation v4")
    if "write_network(writer, source.network())" not in wire_encode:
        errors.append("canonical compact KSPT encoder must own network trailer emission")
    trailer_body = wire_encode.split("fn write_trailers", 1)[1].split("fn write_ms45_trailers", 1)[0]
    trailer_calls = [
        "write_network(writer, source.network())",
        "write_ms45_trailers(writer, source, inputs, outputs)",
        "write_stealth(writer, source.stealth())",
        "write_covenant_trailers(writer, source, outputs)",
        "write_derivation_trailers(writer, source, inputs, outputs)",
    ]
    offsets = [trailer_body.find(token) for token in trailer_calls]
    ms45_body = wire_encode.split("fn write_ms45_trailers", 1)[1].split("fn write_stealth", 1)[0]
    derivation_body = wire_encode.split("fn write_derivation_trailers", 1)[1].split("fn position", 1)[0]
    grouped_order = (
        ms45_body.find("source.input_ms45") >= 0
        and ms45_body.find("source.output_ms45") > ms45_body.find("source.input_ms45")
        and derivation_body.find("source.input_derivation") >= 0
        and derivation_body.find("source.output_derivation") > derivation_body.find("source.input_derivation")
    )
    if any(offset < 0 for offset in offsets) or offsets != sorted(offsets) or not grouped_order:
        errors.append("canonical compact KSPT encoder trailer order must remain N/I/O/S/C/A/D")

    offline_codec = (offline_root / "wire_adapter.rs").read_text(errors="ignore")
    if (
        "kassigner_protocol::wire::kspt" not in offline_codec
        or "kspt::decode_with_limits" not in offline_codec
        or "kspt::DecodeLimits::new" not in offline_codec
        or "kspt::encode" not in offline_codec
    ):
        errors.append("offline signer must consume the canonical KSPT codec with explicit resource limits")
    for duplicate in ('b"KSPT"', "NETWORK_TRAILER_MARKER", "KSPT_GENERATION_CURRENT"):
        if duplicate in offline_codec:
            errors.append(f"offline signer reintroduced duplicated KSPT wire knowledge: {duplicate}")
    protocol_manifest = (root / "crates/kassigner-protocol/Cargo.toml").read_text(errors="ignore")
    offline_manifest = (root / "crates/offline-signer/Cargo.toml").read_text(errors="ignore")
    if 'default-features = false' not in offline_manifest or 'kassigner-protocol' not in offline_manifest:
        errors.append("offline signer must consume kassigner-protocol with host features disabled")
    if "online-watcher" in protocol_manifest or "offline-signer" in protocol_manifest:
        errors.append("kassigner-protocol must not depend upward on host or hardware consumers")

    envelope_source = (root / "crates/offline-signer/src/transaction/std_pskt/envelope.rs").read_text(errors="ignore")
    if "kassigner_protocol::wire::kspt::GENERATION_CURRENT" not in envelope_source:
        errors.append("transaction envelope detection must use the canonical KSPT generation constant")

    firmware_parser_source = (root / "crates/signer-firmware-core/src/qr/classification.rs").read_text(errors="ignore")
    for canonical in (
        "kspt::MAGIC",
        "kspt::GENERATION_CURRENT",
        "pskt_envelope::PSKB_MAGIC",
        "pskt_envelope::PSKT_MAGIC",
    ):
        if canonical not in firmware_parser_source:
            errors.append(f"firmware QR classification must use canonical protocol constant: {canonical}")
    for duplicate in ('b"KSPT"', 'b"PSKB"', 'b"PSKT"', "input[4] == 0x04"):
        if duplicate in firmware_parser_source:
            errors.append(f"firmware QR classification must not duplicate public wire knowledge: {duplicate}")
    firmware_core_manifest = (root / "crates/signer-firmware-core/Cargo.toml").read_text(errors="ignore")
    if 'kassigner-protocol = { version = "=2.0.0", path = "../kassigner-protocol", default-features = false }' not in firmware_core_manifest:
        errors.append("signer-firmware-core must consume no_std kassigner-protocol constants directly")

    parser_source = (bridge_root / "parser_transaction.rs").read_text(errors="ignore")
    if "kassigner_protocol::wire::kspt" not in parser_source or "kspt::decode(data, &mut sink)" not in parser_source:
        errors.append("KasSee compact KSPT parsing must delegate to the canonical protocol decoder")
    for duplicate in ('b"KSPT"', "KSPT_V4", "GENERATION_CURRENT: u8", "NETWORK_MARKER"):
        if duplicate in parser_source:
            errors.append(f"KasSee compact parser reintroduced KSPT wire grammar: {duplicate}")
    parser_tests = (root / "crates/online-watcher/src/protocol/pskt/unit_tests/kspt_compact.rs").read_text(errors="ignore")
    if "compact_v4_parser_covers_network_and_derivation_trailer_contract" not in parser_tests:
        errors.append("KasSee canonical KSPT adapter must retain network/derivation behavior coverage")
    if "assert_eq!(transaction.network, network)" not in parser_tests or "transaction.outputs[0].derivation" not in parser_tests:
        errors.append("KasSee canonical KSPT adapter tests must bind decoded network and derivation metadata")

    online_anti_klepto = (root / "crates/online-watcher/src/protocol/pskt/anti_klepto.rs").read_text(errors="ignore")
    if "left.network" not in online_anti_klepto or "right.network" not in online_anti_klepto:
        errors.append("online anti-klepto transcript comparison must bind the KSPT v4 network")

    offline_anti_klepto = (offline_root / "signing/anti_klepto/transaction_body.rs").read_text(errors="ignore")
    for required in ("left.network", "left.has_derivation_hint", "left.derivation_branch", "left.derivation_index"):
        if required not in offline_anti_klepto:
            errors.append(f"offline anti-klepto transaction comparison must bind v4 metadata: {required}")

    signed_source = (root / "crates/online-watcher/src/protocol/transaction/signed_kspt.rs").read_text(errors="ignore")
    if "kassigner_protocol::wire::kspt" not in signed_source or "kspt::decode(&bytes, &mut sink)" not in signed_source:
        errors.append("signed compact KSPT conversion must delegate to the canonical protocol decoder")
    for duplicate in ('b"KSPT"', "COMPACT_KSPT_V4", "GENERATION_CURRENT: u8", "NETWORK_MARKER"):
        if duplicate in signed_source:
            errors.append(f"signed KSPT adapter reintroduced KSPT wire grammar: {duplicate}")

    kssn_source = (offline_root / "kssn.rs").read_text(errors="ignore")
    if "KSSN_VERSION_CURRENT" not in kssn_source or "reader.read_u8()? != KSSN_VERSION_CURRENT" not in kssn_source:
        errors.append("KSSN parser must accept only the current protocol version")
    if "KSSN_VERSION_LEGACY" in kssn_source:
        errors.append("KSSN parser retains retired version-v1 compatibility")
    return errors
