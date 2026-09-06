from pathlib import Path
import importlib.util
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WATCHER = ROOT / "crates/online-watcher/src"
RUST_SYNTAX_PATH = ROOT / "qa/checks/architecture/core/rust_syntax.py"
RUST_SYNTAX_SPEC = importlib.util.spec_from_file_location("rust_syntax_contract", RUST_SYNTAX_PATH)
rust_syntax = importlib.util.module_from_spec(RUST_SYNTAX_SPEC)
assert RUST_SYNTAX_SPEC.loader is not None
RUST_SYNTAX_SPEC.loader.exec_module(rust_syntax)


class OnlineWatcherTestCompileContractTests(unittest.TestCase):
    def test_rust_syntax_gate_rejects_stray_prose_in_function_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "broken.rs"
            source = "#[test]\nfn valid_prefix stray_token() {}\n"
            path.write_text(source)
            errors = rust_syntax._function_declaration_errors(path, source, root)
        self.assertEqual(len(errors), 1)
        self.assertIn("unexpected token 'stray_token'", errors[0])


    def test_consensus_finalizer_decode_helper_returns_owned_pskt_value(self) -> None:
        source = (WATCHER / "protocol/pskt/consensus/finalizer.rs").read_text()
        body = source.split("fn decode_pskt(wire_hex: &str) -> Result<Value, String> {", 1)[1].split("\n}", 1)[0]
        self.assertIn("pskt_from_root(&root, format).cloned()", body)

    def test_pskt_tests_do_not_resolve_decode_root_through_shadowing_test_module(self) -> None:
        source = (WATCHER / "protocol/pskt/unit_tests/mod.rs").read_text()
        self.assertIn("use super::wire::{decode_root, inject_tx_payload};", source)
        self.assertNotIn("wire::decode_root(&result)", source)

    def test_covenant_tests_use_facade_reexports_instead_of_private_modules(self) -> None:
        source = (
            WATCHER
            / "wasm_api/contracts/covenant/families/unit_tests/mod.rs"
        ).read_text()
        for private_path in (
            "address::build_escrow_json",
            "shipping::address::build_shipping_escrow_json",
            "timelocked::build_timelocked_escrow_json",
            "allowance::local::build_allowance_withdrawal",
        ):
            self.assertNotIn(private_path, source)

        shipping_facade = (
            WATCHER
            / "wasm_api/contracts/covenant/families/escrow/shipping/mod.rs"
        ).read_text()
        self.assertIn(
            "pub(crate) use address::build_shipping_escrow_json;",
            shipping_facade,
        )

    def test_qr_frame_supports_result_error_assertions(self) -> None:
        source = (WATCHER / "protocol/qr.rs").read_text()
        self.assertIn("#[derive(Debug, Serialize)]\npub struct QrFrame", source)

    def test_test_helpers_are_not_shadowed_before_reuse(self) -> None:
        shipping = (
            WATCHER
            / "wasm_api/contracts/covenant/families/escrow/shipping/unit_tests/mod.rs"
        ).read_text()
        self.assertNotIn("let wallet = wallet(", shipping)
        self.assertIn("let borrower_wallet = wallet(", shipping)


    def test_crowdfund_test_facade_visibility_and_wasm_error_mapping_compile_contracts(self) -> None:
        facade = (WATCHER / "wasm_api/contracts/zk/crowdfund.rs").read_text()
        campaign = (WATCHER / "wasm_api/contracts/zk/crowdfund/campaign.rs").read_text()
        sweep = (WATCHER / "wasm_api/contracts/zk/crowdfund/sweep.rs").read_text()

        compact_facade = "".join(facade.split())
        self.assertIn("pub(super)usecampaign::{build_crowdfund_address_json,build_proof_json,compute_campaign_id_hex,};", compact_facade)
        self.assertIn("pub(super)usesweep::{prepare_crowdfund_sweep,ContributionRef,CrowdfundSweepRequest};", compact_facade)
        campaign_core = (WATCHER / "contracts/zk/crowdfund.rs").read_text()
        sweep_core = (WATCHER / "transaction_builder/zk/crowdfund.rs").read_text()
        for symbol in ("build_proof_json", "compute_campaign_id_hex", "build_address_json"):
            self.assertIn(f"pub(crate) fn {symbol}", campaign_core)
        for symbol in ("ContributionRef", "CrowdfundSweepRequest"):
            self.assertIn(f"pub(crate) struct {symbol}", sweep_core)
        self.assertIn("pub(crate) fn prepare_crowdfund_sweep", sweep_core)
        self.assertIn("crate::contracts::zk::crowdfund::", campaign)
        self.assertIn("crate::transaction_builder::zk::crowdfund::", sweep)
        self.assertNotIn("network::queries", campaign)
        self.assertNotIn("network::queries", sweep)

    def test_private_swap_watcher_compile_contracts_follow_current_pskt_and_adaptor_apis(self) -> None:
        pskt = (WATCHER / "protocol/pskt/mod.rs").read_text()
        anti_klepto = (WATCHER / "protocol/pskt/anti_klepto.rs").read_text()
        family = (WATCHER / "wasm_api/contracts/covenant/families/private_swap.rs").read_text()
        tests = (WATCHER / "contracts/covenant/script/private_swap/unit_tests/mod.rs").read_text()

        self.assertIn("compact_kspt_sighash_wire", pskt)
        self.assertIn("expected_added_sighash(&transaction.inputs[0])", anti_klepto)
        self.assertNotIn("input.sighash_type", anti_klepto)
        compact_family = "".join(family.split())
        self.assertIn("crate::protocol::pskt::compact_kspt_sighash_wire(&kspt)", compact_family)
        self.assertNotIn("pskt::anti_klepto::compact_kspt_sighash_wire", compact_family)
        self.assertIn("extract_secret(&final_sig,&p)", compact_family)
        self.assertNotIn("extract_secret(&p,&final_sig)", compact_family)
        self.assertIn("OP_BLAKE2B, OP_CHECKSIGFROMSTACK, OP_SHA256", tests)

    def test_transaction_builder_boundary_test_imports_storage_mass_from_amounts_owner(self) -> None:
        source = (WATCHER / "transaction_builder/unit_tests/boundaries.rs").read_text()
        self.assertIn("planning::amounts::storage_mass_estimate", source)
        self.assertNotIn("planning::storage_mass_estimate", source)

    def test_multisig_small_int_decoder_cannot_eagerly_underflow_on_invalid_opcode(self) -> None:
        source = (WATCHER / "protocol/pskt/review/classification.rs").read_text()
        self.assertNotIn("then_some(opcode - 0x50)", source)
        self.assertIn("0x51..=0x60 => Some(opcode - 0x50)", source)
        self.assertIn("_ => None", source)

    def test_network_wrpc_unit_test_uses_network_owned_module_path(self) -> None:
        source = (WATCHER / "network/unit_tests/mod.rs").read_text()
        self.assertIn("use super::wrpc::operation::Operation;", source)
        self.assertNotIn("use super::super::wrpc::operation::Operation;", source)

    def test_allowance_logger_is_visible_only_inside_covenant_families_for_host_coverage(self) -> None:
        family_tests = (
            WATCHER
            / "wasm_api/contracts/covenant/families/unit_tests/mod.rs"
        ).read_text()
        local = (
            WATCHER
            / "wasm_api/contracts/covenant/families/allowance/local.rs"
        ).read_text()
        self.assertIn("super::allowance::log_withdrawal", family_tests)
        self.assertIn(
            "pub(in crate::wasm_api::contracts::covenant::families) fn log_withdrawal",
            local,
        )
        self.assertNotIn("pub(crate) fn log_withdrawal", local)
        self.assertNotIn("pub fn log_withdrawal", local)
        self.assertNotIn("withdrawal_logging_accepts_completed_summary", local)

    def test_oracle_publish_heartbeat_template_matches_fetch_visibility(self) -> None:
        context = (
            WATCHER
            / "wasm_api/contracts/oracle/publish/context.rs"
        ).read_text()
        tests = (
            WATCHER
            / "wasm_api/contracts/oracle/publish/unit_tests/mod.rs"
        ).read_text()
        core = (WATCHER / "transaction_builder/oracle_publish/context.rs").read_text()
        self.assertIn("pub(crate) struct HeartbeatTemplate", core)
        self.assertIn("pub(crate) async fn fetch_heartbeat_utxos", core)
        self.assertIn("crate::transaction_builder::oracle_publish::context", context)
        self.assertIn('fetch_heartbeat_utxos("ws://unused", None)', tests)

    def test_standard_covenant_sigscript_imports_its_push_helper(self) -> None:
        source = (WATCHER / "protocol/pskt/scripts/contracts/standard.rs").read_text()
        self.assertIn("first_schnorr_signature, push_data_sigscript, push_redeem_script", source)


    def test_oracle_v1_builder_is_native_host_testable_without_jsvalue_roundtrip(self) -> None:
        family = (
            WATCHER
            / "wasm_api/contracts/covenant/families/oracle_v1.rs"
        ).read_text()
        tests = (
            WATCHER
            / "wasm_api/contracts/covenant/families/unit_tests/feature_contracts.rs"
        ).read_text()

        core = (WATCHER / "contracts/covenant/oracle_v1.rs").read_text()
        self.assertIn("decode_pubkey32(value)", core)
        self.assertNotIn("JsValue", core)
        self.assertNotIn("wasm_bindgen", core)
        self.assertIn("crate::contracts::covenant::oracle_v1::build_json", family)
        self.assertIn("build_oracle_v1_json(", tests)

    def test_covenant_context_test_asserts_the_parsed_oracle_signature(self) -> None:
        tests = (WATCHER / "protocol/pskt/scripts/unit_tests/mod.rs").read_text()
        self.assertIn('"oracleV1Signature": "11"', tests)
        self.assertIn(
            "assert_eq!(context.oracle.v1.signature.as_deref(), Some(&[0x11][..]));",
            tests,
        )
        self.assertNotIn("assert_eq!(None::<&[u8]>, Some(&[0x11][..]));", tests)

    def test_oracle_script_facade_does_not_retain_publish_only_opcode_imports(self) -> None:
        facade = (WATCHER / "contracts/oracle/script/mod.rs").read_text()
        publish = (WATCHER / "contracts/oracle/script/publish.rs").read_text()
        self.assertNotIn("OP_TX_INPUT_SCRIPT_SIG_LEN", facade)
        self.assertNotIn("OP_TX_INPUT_SCRIPT_SIG_SUBSTR", facade)
        self.assertIn("OP_TX_INPUT_SCRIPT_SIG_LEN", publish)
        self.assertIn("OP_TX_INPUT_SCRIPT_SIG_SUBSTR", publish)


if __name__ == "__main__":
    unittest.main()
