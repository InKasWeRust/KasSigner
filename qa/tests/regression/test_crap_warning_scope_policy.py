import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
CHECK_DIR = ROOT / "qa/checks/quality/crap"
sys.path.insert(0, str(CHECK_DIR))
from source_complexity import check_source_policy  # noqa: E402

POLICY = ROOT / "qa/checks/quality/crap/policy.json"


class CrapWarningScopePolicyTests(unittest.TestCase):
    def test_current_warning_target_is_zero_debt_without_persisted_run_evidence(self) -> None:
        policy = json.loads(POLICY.read_text())
        self.assertEqual(policy["report"]["maximum_production_failures"], 0)
        self.assertEqual(policy["report"]["maximum_production_warnings"], 0)
        self.assertFalse((ROOT / "qa/baselines/crap").exists())
        self.assertTrue((ROOT / "qa/contracts/quality/crap_ratchets.json").is_file())

    def test_source_assessed_rows_obey_current_complexity_policy(self) -> None:
        policy = json.loads(POLICY.read_text())
        errors, stats = check_source_policy(ROOT, policy.get("source_complexity", {}))
        self.assertEqual(errors, [])
        self.assertEqual(stats.get("warning_functions"), 0)
        self.assertLessEqual(
            stats.get("maximum_decisions", 0),
            policy["source_complexity"]["maximum_production_source_decisions"],
        )

    def test_crap_generation_uses_scope_matched_coverage_legs(self) -> None:
        linux = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        windows = (ROOT / "scripts/windows/quality/crap_windows.py").read_text()
        for source in (linux, windows):
            self.assertIn("apps/kassee-web", source)
            self.assertIn("apps/signer-firmware", source)
            self.assertIn("--workspace", source)
            self.assertIn("merge_reports.py", source)
        self.assertNotIn("--path .", linux)
        self.assertNotIn("'--path','.'", windows)

    def test_kassee_web_rust_shell_is_in_source_complexity_fallback_scope(self) -> None:
        from source_complexity import PRODUCTION_ROOTS

        self.assertIn("apps/kassee-web/src", PRODUCTION_ROOTS)


if __name__ == "__main__":
    unittest.main()
