#!/usr/bin/env python3
"""Contracts for funded multisig finalize/broadcast standardness and UI containment."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
CONSENSUS = ROOT / "crates/online-watcher/src/protocol/transaction/consensus.rs"
SUBMIT_ENCODER = ROOT / "crates/online-watcher/src/network/submission/encoder.rs"
SUBMIT_DECODER = ROOT / "crates/online-watcher/src/network/codec/responses/submission.rs"
FINALIZER = ROOT / "crates/online-watcher/src/protocol/pskt/consensus/finalizer.rs"
AMOUNTS = ROOT / "crates/online-watcher/src/transaction_builder/planning/amounts.rs"
MULTISIG = ROOT / "crates/online-watcher/src/transaction_builder/multisig.rs"
MULTISIG_TESTS = ROOT / "crates/online-watcher/src/transaction_builder/multisig/unit_tests/mod.rs"
SUBMISSION_TESTS = ROOT / "crates/online-watcher/src/network/unit_tests/submission.rs"
FINALIZER_TESTS = ROOT / "crates/online-watcher/src/protocol/pskt/unit_tests/consensus_finalizer.rs"
CSS = ROOT / "apps/kassee-web/web/css/app/components/qr_and_address.css"
SELECTION_MOD = ROOT / "crates/online-watcher/src/transaction_builder/selection/mod.rs"
SELECTION_AUTO = ROOT / "crates/online-watcher/src/transaction_builder/selection/automatic.rs"
BUILDER_TESTS = ROOT / "crates/online-watcher/src/transaction_builder/unit_tests/mod.rs"


class MultisigBroadcastStandardnessTests(unittest.TestCase):
    def test_submit_transaction_carries_kip9_storage_mass_instead_of_zero(self) -> None:
        consensus = CONSENSUS.read_text(encoding="utf-8")
        encoder = SUBMIT_ENCODER.read_text(encoding="utf-8")
        finalizer = FINALIZER.read_text(encoding="utf-8")
        amounts = AMOUNTS.read_text(encoding="utf-8")
        self.assertIn("pub storage_mass: u64", consensus)
        self.assertIn("writer.write_u64(transaction.storage_mass);", encoder)
        self.assertNotIn("writer.write_u64(0);\n    writer.write_bytes(&[0])?;", encoder)
        self.assertIn("let storage_mass = calculate_storage_mass(document.inputs, &outputs)?;", finalizer)
        self.assertIn("storage_mass_estimate(&input_cells, &output_cells)", finalizer)
        self.assertIn("pub fn utxo_plurality(script_len: usize, has_covenant_id: bool)", amounts)

    def test_multisig_builder_enforces_post_toccata_signed_transaction_fee_floor(self) -> None:
        source = MULTISIG.read_text(encoding="utf-8")
        tests = MULTISIG_TESTS.read_text(encoding="utf-8")
        self.assertIn("fn multisig_standard_fee(", source)
        self.assertIn("const MIN_STANDARD_FEE_PER_GRAM: u64 = 100;", source)
        self.assertIn("const TRANSIENT_MASS_PER_BYTE: u64 = 2;", source)
        self.assertIn("prepared.minimum_signatures", source)
        self.assertIn("let fee = multisig_standard_fee(prepared, selected.len(), request.fee)?;", source)
        self.assertIn("fn toccata_multisig_fee_uses_final_signed_shape()", tests)
        self.assertIn("Ok(319_400)", tests)
        self.assertIn("Ok(400_000)", tests)

    def test_storage_mass_and_full_node_rejection_are_unit_tested(self) -> None:
        submission = SUBMISSION_TESTS.read_text(encoding="utf-8")
        finalizer = FINALIZER_TESTS.read_text(encoding="utf-8")
        decoder = SUBMIT_DECODER.read_text(encoding="utf-8")
        self.assertIn("committed.storage_mass = 10_111;", submission)
        self.assertIn("submission_error_decoder_strips_borsh_prefix_and_keeps_full_node_reason", submission)
        self.assertIn("finalized_transaction_commits_kip9_storage_mass_from_pskt_utxos", finalizer)
        self.assertIn("assert_eq!(finalized.storage_mass, 10_111);", finalizer)
        self.assertIn('"Rejected transaction"', decoder)
        self.assertIn(".take(2_048)", decoder)


    def test_transaction_builder_test_fixtures_track_current_selection_and_multisig_shape(self) -> None:
        selection_mod = SELECTION_MOD.read_text(encoding="utf-8")
        selection_auto = SELECTION_AUTO.read_text(encoding="utf-8")
        builder_tests = BUILDER_TESTS.read_text(encoding="utf-8")
        self.assertIn("pub use automatic::select_automatic_with_limit;", selection_mod)
        self.assertNotIn("select_automatic, select_automatic_with_limit", selection_mod)
        self.assertNotIn("pub fn select_automatic(", selection_auto)
        self.assertIn("super::selection::select_automatic_with_limit(", builder_tests)
        self.assertIn("minimum_signatures: 1,", builder_tests)

    def test_multisig_branch_utxo_address_wraps_inside_card(self) -> None:
        css = CSS.read_text(encoding="utf-8")
        self.assertIn(".utxo-row {", css)
        self.assertIn("grid-template-columns: auto minmax(0, 1fr);", css)
        self.assertIn(".utxo-row > span {", css)
        self.assertIn("overflow-wrap: anywhere;", css)
        self.assertIn("word-break: break-word;", css)


if __name__ == "__main__":
    unittest.main()
