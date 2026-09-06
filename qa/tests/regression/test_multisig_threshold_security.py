#!/usr/bin/env python3
"""regressions for explicit multi-wallet multisig relay signing."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
SIGNING = FW / "src/runtime/workflow_tests/connected/multisig/signing.rs"
LOADED = FW / "src/runtime/signing/loaded_accounts.rs"
KSPT = FW / "src/runtime/signing/kspt.rs"
KSPT_BRIDGE_TEST = ROOT / "crates/online-watcher/src/protocol/pskt/unit_tests/kspt_bridge.rs"


class MultisigThresholdSecurityTests(unittest.TestCase):

    def test_signing_fixture_has_two_local_participants_and_one_external_cosigner(self) -> None:
        source = SIGNING.read_text(encoding="utf-8")
        self.assertIn("const EXPECTED_THRESHOLD: u8 = 2;", source)
        self.assertNotIn("EXPECTED_LOCAL_SIGNERS", source)
        self.assertIn("let first = local_parts(ad, 0)?;", source)
        self.assertIn("let second = local_parts(ad, 1)?;", source)
        self.assertIn("let external = external_parts()?;", source)
        self.assertIn("config.set_cosigner(0, &first)", source)
        self.assertIn("config.set_cosigner(1, &second)", source)
        self.assertIn("config.set_cosigner(2, &external)", source)
        self.assertIn("let mut seed = [EXTERNAL_COSIGNER_ENTROPY; 64];", source)
        self.assertNotIn("local_parts(ad, 2)", source)

    def test_signing_fixture_does_not_reuse_mutable_multisig_ui_state(self) -> None:
        source = SIGNING.read_text(encoding="utf-8")
        fixture = source.split("fn multisig_wire", 1)[1].split("fn build_multisig_transaction", 1)[0]
        self.assertIn("deterministic_signing_config(ad)?", fixture)
        self.assertNotIn("signing.multisig.creating", fixture)
        self.assertNotIn("signing.multisig.store", fixture)

    def test_family_is_resolved_from_real_loaded_local_cosigners(self) -> None:
        source = SIGNING.read_text(encoding="utf-8")
        config = source.split("fn deterministic_signing_config", 1)[1].split("fn local_parts", 1)[0]
        self.assertIn("config.sort_cosigners();", config)
        self.assertIn("config.resolve_cosigner_index(&first)", config)
        self.assertIn("second_check.resolve_cosigner_index(&second)", config)
        self.assertIn("config.chain = 0;", config)
        self.assertIn("config.addr_index = 0;", config)

    def test_each_multisig_signing_step_uses_only_the_explicit_active_wallet(self) -> None:
        loaded = LOADED.read_text(encoding="utf-8")
        kspt = KSPT.read_text(encoding="utf-8")
        self.assertIn("pub(super) fn derive_active(", loaded)
        derive = loaded.split("pub(super) fn derive_active", 1)[1].split("fn push_slot", 1)[0]
        self.assertIn("active_manager_slot", derive)
        self.assertIn("loaded.push_slot(&seed_manager.slots[active_manager_slot]", derive)
        self.assertNotIn("for manager_index", derive)
        self.assertGreaterEqual(kspt.count("LoadedSigningAccounts::derive_active("), 2)
        self.assertNotIn("LoadedSigningAccounts::derive(&", kspt)


    def test_multisig_relay_fixture_uses_exact_integer_json_for_max_sequence(self) -> None:
        source = KSPT_BRIDGE_TEST.read_text(encoding="utf-8")
        self.assertIn('"sequence": u64::MAX.to_string(),', source)
        self.assertNotIn('"sequence": u64::MAX,', source)

    def test_connected_workflow_relays_partial_kspt_switches_wallet_and_finishes_threshold(self) -> None:
        source = SIGNING.read_text(encoding="utf-8")
        for marker in (
            "MULTISIG SIGN FIXTURE IMPORT PASS",
            "MULTISIG FIRST SIGNER PARTIAL",
            "MULTISIG RELAY SWITCH WALLET + PARTIAL KSPT REIMPORT PASS",
            "MULTISIG SIGN RESULT sigs=",
        ):
            self.assertIn(marker, source)
        self.assertIn("input.sig_count == 1", source)
        self.assertIn("activate_slot_with_cache(ctx.ad, 1", source)
        self.assertIn("load_compact_transaction(partial_wire, ctx.ad)", source)
        self.assertIn("input.ms45_hint == expected_hint", source)
        self.assertIn("input.sig_count == EXPECTED_THRESHOLD", source)
        self.assertIn("present == required", source)
        self.assertIn('7 => "WALLET-SWITCH-REIMPORT"', source)


if __name__ == "__main__":
    unittest.main()
