#!/usr/bin/env python3
"""prevents orphaned stepped operations and test-only PSKB parser re-exports."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class ParserAndOperationOwnershipTests(unittest.TestCase):
    def test_private_thread_parsers_are_not_reexported_from_pskb(self) -> None:
        facade = (ROOT / "crates/online-watcher/src/transaction_builder/pskb/mod.rs").read_text()
        self.assertNotIn("pub(crate) use thread_input::{parse_thread_utxo, parse_withdrawal_thread_utxos};", facade)
        owner = (ROOT / "crates/online-watcher/src/transaction_builder/pskb/thread_input.rs").read_text()
        owner_tests = (ROOT / "crates/online-watcher/src/transaction_builder/pskb/thread_input/unit_tests/mod.rs").read_text()
        self.assertIn("mod unit_tests;", owner)
        self.assertIn("private_thread_parsers_have_owner_local_native_coverage", owner_tests)

    def test_connect_kassee_returns_home_through_authoritative_cancellation(self) -> None:
        source = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/root.rs").read_text()
        body = source.split("fn connect_kassee_from_home", 1)[1]
        self.assertNotIn("clear_operation(ad)", body)
        self.assertIn("effects::home(ad)", body)
        self.assertIn("OperationKind::ConnectKasSee", body)

    def test_signing_and_sd_home_precede_sensitive_scrub(self) -> None:
        signing = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs").read_text()
        signing_body = signing.split("fn prepare_probe", 1)[1].split("fn begin_scan", 1)[0]
        self.assertNotIn("clear_operation", signing_body)
        self.assertLess(signing_body.index("reset_tranche_to_home"), signing_body.index("zeroize_sensitive"))
        self.assertIn("operation_kind(ctx.ad).is_some()", signing_body)

        sd = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/sd_workflows/mod.rs").read_text()
        sd_body = sd.split("fn prepare_probe", 1)[1].split("fn finish", 1)[0]
        self.assertNotIn("clear_operation", sd_body)
        self.assertLess(sd_body.index("ctx.home()"), sd_body.index("zeroize_sensitive"))
        self.assertIn("operation_kind(ctx.ad).is_some()", sd_body)

    def test_create24_has_one_reset_owner(self) -> None:
        orchestration = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/mod.rs").read_text()
        self.assertIn("let create_24_ok = creation::create_24_passphrase(&mut ctx);", orchestration)
        creation = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/creation.rs").read_text()
        body = creation.split("pub(super) fn create_24_passphrase", 1)[1].split("fn begin_create", 1)[0]
        self.assertEqual(body.count("reset_to_storage_choice(ctx.ad)"), 1)


if __name__ == "__main__":
    unittest.main()
