from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class TransactionReviewCoinControlPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(errors="ignore")

    def test_transaction_inputs_are_dynamic_and_v4_binds_network(self) -> None:
        model = self.read("crates/offline-signer/src/transaction/model/transaction.rs")
        constants = self.read("crates/offline-signer/src/transaction/model/constants.rs")
        wire_model = self.read("crates/kassigner-protocol/src/wire/kspt/model.rs")
        offline_codec = self.read("crates/offline-signer/src/transaction/kspt/wire_adapter.rs")
        self.assertIn("pub inputs: Vec<TransactionInput>", model)
        self.assertIn("SIGNER_CAPABILITIES.max_inputs as usize", constants)
        self.assertIn("count > MAX_INPUTS", model)
        self.assertIn("GENERATION_CURRENT: u8 = 0x04", wire_model)
        self.assertIn("NETWORK_MARKER", wire_model)
        self.assertIn("OUTPUT_DERIVATION_MARKER", wire_model)
        self.assertIn("kassigner_protocol::wire::kspt", offline_codec)
        self.assertIn("kspt::decode", offline_codec)
        self.assertIn("kspt::encode", offline_codec)

    def test_hardware_review_uses_bound_network_and_verified_derivation_hint(self) -> None:
        address = self.read("apps/signer-firmware/src/ui/screens/signing/transaction_review/address.rs")
        review = self.read("apps/signer-firmware/src/runtime/signing/review.rs")
        summary = self.read("apps/signer-firmware/src/ui/screens/signing/transaction_review/summary.rs")
        self.assertIn("tx.network", summary)
        self.assertIn("encode_address_str_for_network", address)
        self.assertIn("has_derivation_hint", review)
        self.assertIn("derivation_branch", review)
        self.assertIn("derivation_index", review)
        self.assertIn("OutputOwnership::Change", review)
        self.assertNotIn("change_pubkey_cache", review)

    def test_monetary_overflow_is_rejected_before_firmware_review(self) -> None:
        model = self.read("crates/offline-signer/src/transaction/model/transaction.rs")
        validation = self.read("crates/offline-signer/src/transaction/kspt/validation.rs")
        compact = self.read("crates/offline-signer/src/transaction/kspt/wire_adapter.rs")
        standard = self.read("crates/offline-signer/src/transaction/std_pskt/parser/mod.rs")
        review = self.read("apps/signer-firmware/src/runtime/signing/review.rs")
        dispatch = self.read("apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/transaction.rs")
        transaction_input = self.read("apps/signer-firmware/src/runtime/interactions/tx/transaction.rs")
        anti_klepto = self.read("apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/anti_klepto.rs")
        redraw = self.read("apps/signer-firmware/src/ui/redraw/signing/transaction.rs")

        self.assertIn("checked_add(input.utxo_entry.amount)", model)
        self.assertIn("checked_add(output.value)", model)
        self.assertIn("checked_sub(output_total)", model)
        self.assertNotIn("saturating_sub", model)
        self.assertIn("TransactionAmountError::InputTotalOverflow", validation)
        self.assertIn("PsktError::InputAmountOverflow", validation)
        self.assertIn("PsktError::OutputAmountOverflow", validation)
        self.assertIn("PsktError::OutputsExceedInputs", validation)
        self.assertIn("validate_partial_signed(tx)", compact)
        self.assertIn("validate_monetary_shape(tx)", standard)

        self.assertIn("-> Result<ReviewTotals", review)
        self.assertIn("transaction_amounts(tx)?", review)
        self.assertIn("checked_add(output.value)", review)
        self.assertNotIn("saturating_add", review)
        self.assertNotIn("saturating_sub", review)

        self.assertIn("load_compact_transaction", dispatch)
        self.assertIn("load_standard_transaction", dispatch)
        compact_branch = transaction_input.split("pub(crate) fn load_compact_transaction", 1)[1].split("pub(crate) fn load_standard_transaction", 1)[0]
        standard_branch = transaction_input.split("pub(crate) fn load_standard_transaction", 1)[1]
        for branch in (compact_branch, standard_branch):
            self.assertIn("validate_transaction_for_review", branch)
            self.assertIn("show_error_spec_previous", transaction_input)
            self.assertIn("presentation::TX_IMPORT", transaction_input)
            self.assertLess(branch.index("validate_transaction_for_review"), branch.index("begin_import_review"))
        self.assertLess(transaction_input.index("validate_transaction_for_review"), transaction_input.index("start_review"))
        self.assertIn("validate_transaction_for_review", anti_klepto)
        self.assertLess(anti_klepto.index("validate_transaction_for_review"), anti_klepto.index("start_review"))
        self.assertGreaterEqual(redraw.count("Invalid monetary totals"), 2)

    def test_anti_klepto_binds_v4_network_and_derivation_metadata(self) -> None:
        parser = self.read("crates/online-watcher/src/protocol/pskt/kspt_bridge/parser_transaction.rs")
        parser_tests = self.read("crates/online-watcher/src/protocol/pskt/unit_tests/kspt_compact.rs")
        online = self.read("crates/online-watcher/src/protocol/pskt/anti_klepto.rs")
        offline = self.read("crates/offline-signer/src/transaction/kspt/signing/anti_klepto/transaction_body.rs")
        self.assertIn("kassigner_protocol::wire::kspt", parser)
        self.assertIn("kspt::decode(data, &mut sink)", parser)
        self.assertIn("compact_v4_parser_covers_network_and_derivation_trailer_contract", parser_tests)
        self.assertIn("assert_eq!(transaction.network, network)", parser_tests)
        self.assertIn("assert_eq!(transaction.outputs[0].derivation, Some((0, 7)))", parser_tests)
        self.assertIn("left.network", online)
        self.assertIn("right.network", online)
        self.assertIn("left.network", offline)
        self.assertIn("left.has_derivation_hint", offline)
        self.assertIn("left.derivation_branch", offline)
        self.assertIn("left.derivation_index", offline)

    def test_kassee_coin_control_defaults_to_eight_but_supports_override(self) -> None:
        state = self.read("apps/kassee-web/web/js/app/state/core/transaction_state.js")
        form = self.read("apps/kassee-web/web/html/screens/transactions/send.html")
        planner = self.read("apps/kassee-web/web/js/features/transactions/send/compose/planners/standard.js")
        selector = self.read("apps/kassee-web/web/js/features/transactions/shared/utxo_selector.js")
        self.assertIn("\'utxoSelectionLimit\': 8", state)
        self.assertIn('value="8"', form)
        self.assertIn("SDK capability ceiling (32 inputs for the v2 reference signer)", form)
        self.assertNotIn('max="4294967295"', form)
        self.assertIn("limit === 8", planner)
        self.assertIn("create_send_pskb_limited", planner)
        self.assertIn("Select UTXOs manually", form)
        for mode in ("amount-desc", "amount-asc", "daa-desc", "daa-asc"):
            self.assertIn(f'value="{mode}"', form)
        self.assertIn("block_daa_score", selector)
        self.assertIn("orderedUtxoEntries", selector)
        self.assertLess(selector.index("SELECTED UTXOs"), selector.index("AVAILABLE UTXOs"))

    def test_signer_progress_and_utxo_inspection_are_transaction_bound(self) -> None:
        workflow = self.read("apps/signer-firmware/src/runtime/signing/workflow.rs")
        progress = self.read("apps/signer-firmware/src/ui/screens/signing/progress.rs")
        inspection = self.read("apps/signer-firmware/src/ui/screens/signing/transaction_review/input.rs")
        self.assertIn("draw_signing_screen(input_idx, ad.navigation.app.total_inputs)", workflow)
        self.assertIn('"Input {}/{}"', progress)
        self.assertIn('"Transaction UTXOs: {}"', inspection)
        self.assertIn('"Output index: {}"', inspection)
        self.assertIn('"DAA: {}"', inspection)
        self.assertIn("draw_tx_destination(&input.utxo_entry.script_public_key, tx.network)", inspection)


if __name__ == "__main__":
    unittest.main()
