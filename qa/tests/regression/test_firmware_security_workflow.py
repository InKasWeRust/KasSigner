#!/usr/bin/env python3
"""connected advanced security-policy E2E tranche contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
CONNECTED = FW / "src/runtime/workflow_tests/connected"
SCENARIOS = ROOT / "qa/config/workflow/production_e2e_scenarios.json"
MANIFEST = ROOT / "qa/config/workflow/production_e2e_manifest.json"
REQUIREMENTS = ROOT / "qa/specs/production_e2e_requirements.md"


class SecurityPolicyE2ETrancheTests(unittest.TestCase):
    def test_security_runner_is_partitioned_and_emits_bounded_markers(self) -> None:
        root = (CONNECTED / "mod.rs").read_text()
        security = CONNECTED / "security_policies"
        self.assertEqual(
            {path.name for path in security.glob("*.rs")},
            {"mod.rs", "duress.rs", "time.rs", "signing.rs", "pop_it.rs"},
        )
        self.assertIn("mod security_policies;", root)
        self.assertIn("(\"SECURITY-POLICIES\", security_policies::exercise)", root)
        source = "\n".join(path.read_text() for path in sorted(security.glob("*.rs")))
        for marker in (
            "SECURITY SAVED-WALLET/INTEGRITY FAIL-CLOSED PASS",
            "SECURITY DURESS WARNING CANCEL PASS",
            "SECURITY DURESS INVALID/MISMATCH REJECT PASS",
            "SECURITY DURESS PERSISTENCE ERROR PASS",
            "SECURITY DURESS CONFIRM/READ-ONLY PASS",
            "SECURITY RTC INVALID/LOW-VOLTAGE/VERIFY PASS",
            "SECURITY NO-SIGN-BEFORE INVALID/CANCEL/PERSIST/READ-ONLY PASS",
            "SECURITY WEEKLY INVALID/CANCEL/PERSIST/READ-ONLY PASS",
            "SECURITY SIGNING POLICY INTEGRITY/ROLLBACK/LOCK/WINDOW BOUNDARIES PASS",
            "SECURITY SIGNING POLICY ACTUAL SIGN DENY/ALLOW PASS",
            "SECURITY POP-IT EXPLAIN/NO PASS",
            "SECURITY POP-IT PHRASE/PREFLIGHT/ARM-FAIL PASS",
            "SECURITY POP-IT SAFE SIMULATED SUCCESS PASS",
            "SECURITY PERSISTENT FLASH/HMAC + PHYSICAL RTC/EFUSE HIL DEFERRED",
            "SECURITY POLICIES TRANCHE PASS",
        ):
            self.assertIn(marker, source)

    def test_policy_signing_uses_same_production_evaluator(self) -> None:
        service = (FW / "src/services/signing_policy.rs").read_text()
        workflow = (FW / "src/runtime/signing/workflow_test.rs").read_text()
        self.assertIn("fn authorize_at(policy: SigningPolicy, now_unix: u64)", service)
        self.assertIn("workflow_authorize_transaction_time", service)
        self.assertIn("authorize_at(policy, now_unix).map(Some)", service)
        self.assertIn("workflow_signing_step_with_policy", workflow)
        policy_call = workflow.split("workflow_signing_step_with_policy", 1)[1]
        self.assertLess(policy_call.index("workflow_authorize_transaction_time"), policy_call.index("workflow_signing_step(ad)"))

    def test_workflow_adapters_are_cfg_only_and_efuse_safe(self) -> None:
        adapter = (FW / "src/runtime/interactions/settings/advanced/workflow.rs").read_text()
        workflow_cfgs = (
            adapter.count('#[cfg(feature = "workflow-test-auto")]')
            + adapter.count('#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]')
        )
        self.assertGreaterEqual(workflow_cfgs, 10)
        self.assertIn(
            '#[cfg(all(feature = "workflow-test-auto", feature = "m5stack"))]\npub(crate) fn submit_rtc',
            adapter,
        )
        self.assertNotIn("software_reset", adapter)
        self.assertNotIn("request_pop_it", adapter)
        self.assertNotIn("pop_it_preflight()", adapter)
        self.assertNotRegex(adapter, r"efuse|EFUSE")
        pop_it = (FW / "src/runtime/interactions/settings/advanced/pop_it.rs").read_text()
        self.assertIn("boot_security::pop_it_preflight()", pop_it)
        self.assertIn("persistence.request_pop_it()", pop_it)
        self.assertIn("esp_hal::system::software_reset()", pop_it)


    def test_requirements_remain_frozen(self) -> None:
        self.assertEqual(
            hashlib.sha256(REQUIREMENTS.read_bytes()).hexdigest(),
            "d645cd7483ddc4443936e60a1b063bd596cb0fe31f5216d79e520009eabf8ef7",
        )


if __name__ == "__main__":
    unittest.main()
