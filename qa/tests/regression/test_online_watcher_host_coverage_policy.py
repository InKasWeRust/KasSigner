import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
RATCHET_PATH = ROOT / "qa/contracts/quality/crap_ratchets.json"
REMEDIATION_PATH = ROOT / "qa/baselines/remediation"
CRAP_CHECK_DIR = ROOT / "qa/checks/quality/crap"
sys.path.insert(0, str(CRAP_CHECK_DIR))
from report import CrapEntry  # noqa: E402


def _online_watcher_failures(document: dict) -> list[dict]:
    return [
        row
        for row in document["functions"]
        if row.get("scope") == "production"
        and row.get("status") == "fail"
        and row.get("path", "").startswith("crates/online-watcher/")
    ]


class OnlineWatcherHostCoveragePolicyTests(unittest.TestCase):
    def test_historical_remediation_baseline_is_not_retained(self) -> None:
        self.assertFalse(
            REMEDIATION_PATH.exists(),
            "completed remediation manifests must not remain in qa/baselines",
        )

    def test_fresh_crap_evidence_is_target_only_and_zero_debt_is_policy(self) -> None:
        self.assertFalse((ROOT / "qa/baselines/crap").exists())
        policy = json.loads((ROOT / "qa/checks/quality/crap/policy.json").read_text())
        self.assertEqual(policy["report"]["maximum_production_failures"], 0)
        self.assertEqual(policy["report"]["maximum_production_warnings"], 0)
        self.assertTrue(RATCHET_PATH.is_file())

    def test_native_host_coverage_reaches_browser_transport_and_public_facades(self) -> None:
        websocket = (ROOT / "crates/online-watcher/src/infrastructure/browser_websocket.rs").read_text()
        queries = (ROOT / "crates/online-watcher/src/network/unit_tests/queries.rs").read_text()
        oracle = (ROOT / "crates/online-watcher/src/wasm_api/contracts/oracle/publish/unit_tests/mod.rs").read_text()
        vault = (ROOT / "crates/online-watcher/src/wasm_api/contracts/vault/unit_tests/mod.rs").read_text()
        self.assertIn('#[cfg(not(target_arch = "wasm32"))]', websocket)
        self.assertIn("browser WebSocket transport is unavailable on native hosts", websocket)
        self.assertIn("submission::submit", queries)
        self.assertIn("oracle_publish_async_boundaries_are_native_host_covered", oracle)
        self.assertIn("vault_async_builders_and_public_wrappers_reach_native_transport_fail_closed", vault)

    def test_crap_classifier_retains_effective_and_raw_assessment_fields(self) -> None:
        fields = set(CrapEntry.__dataclass_fields__)
        self.assertTrue({"assessment_basis", "raw_status", "coverage_state"} <= fields)



if __name__ == "__main__":
    unittest.main()
