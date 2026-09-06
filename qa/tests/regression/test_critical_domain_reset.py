#!/usr/bin/env python3
"""targets measured critical-domain entries and connected probe isolation."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[3]

class CriticalDomainResetTests(unittest.TestCase):
    def test_direct_native_coverage_targets_measured_domain_functions(self) -> None:
        text = (ROOT / "crates/online-watcher/src/transaction_builder/unit_tests/function_coverage.rs").read_text()
        self.assertIn("measured_domain_uncovered_entries_have_direct_native_coverage", text)
        for token in (
            "build_oracle_mb_heartbeat_script",
            "build_oracle_mb_genesis_redeem",
            "crowdfund::decode_hex",
            "uses_tagged_genesis_policy",
            "shipping::plan::encode_pskb",
        ):
            self.assertIn(token, text)
        owner = (ROOT / "crates/online-watcher/src/transaction_builder/pskb/thread_input.rs").read_text()
        owner_tests = (ROOT / "crates/online-watcher/src/transaction_builder/pskb/thread_input/unit_tests/mod.rs").read_text()
        self.assertIn("mod unit_tests;", owner)
        self.assertIn("private_thread_parsers_have_owner_local_native_coverage", owner_tests)
        self.assertIn("parse_thread_utxo(&one)", owner_tests)
        self.assertIn("parse_withdrawal_thread_utxos(&many)", owner_tests)
        policy = json.loads((ROOT / "qa/checks/quality/crap/policy.json").read_text())["health"]
        self.assertEqual(policy["minimum_critical_domain_coverage_percent"], 90.0)

    def test_onboarding_create24_restarts_from_storage_choice(self) -> None:
        text = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/mod.rs").read_text()
        self.assertIn('let create_24_ok = creation::create_24_passphrase(&mut ctx);', text)
        creation = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/creation.rs").read_text()
        self.assertIn("if !super::reset_to_storage_choice(ctx.ad)", creation)

    def test_wallet_backup_signing_and_sd_probes_own_clean_entry_state(self) -> None:
        wallet = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/wallet.rs").read_text()
        self.assertIn("WALLET PRODUCTION ENTRY ROUTE FAIL", wallet)
        backup = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/backup.rs").read_text()
        self.assertIn("BACKUP HOME RESET FAIL", backup)
        signing = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/signing/mod.rs").read_text()
        self.assertIn("super::reset_tranche_to_home(ctx.ad)", signing)
        self.assertIn("operation_kind(ctx.ad).is_some()", signing)
        self.assertNotIn("presentation::clear_operation(ctx.ad)", signing)
        sd = (ROOT / "apps/signer-firmware/src/runtime/workflow_tests/connected/sd_workflows/mod.rs").read_text()
        self.assertIn("ctx.ad.signing.zeroize_sensitive()", sd)
        self.assertIn("operation_kind(ctx.ad).is_some()", sd)
        self.assertNotIn("presentation::clear_operation(ctx.ad)", sd)

if __name__ == "__main__":
    unittest.main()
