import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "qa/contracts/coverage/online_watcher_coverage_targets.json"


class OnlineWatcherCoverageTargetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(MANIFEST.read_text())

    def test_requested_target_counts_are_encoded(self):
        requirements = self.document["requirements"]
        summary = self.document["summary"]
        self.assertGreaterEqual(
            summary["zero_function_targets"],
            requirements["minimum_zero_function_targets"],
        )
        self.assertGreaterEqual(
            summary["warning_targets"],
            requirements["minimum_warning_targets"],
        )
        self.assertGreaterEqual(
            summary["parser_function_targets"],
            requirements["minimum_parser_function_targets"],
        )
        self.assertGreaterEqual(
            summary["parser_estimated_source_lines"],
            requirements["minimum_parser_line_gain"],
        )
        self.assertGreaterEqual(
            summary["transaction_construction_targets"],
            requirements["minimum_transaction_boundary_targets"],
        )

    def test_every_target_has_a_real_source_and_test_seam(self):
        for target in self.document["targets"]:
            source_path = ROOT / target["path"]
            self.assertTrue(source_path.is_file(), target["path"])
            function_parts = target["function"].split("::")
            function_token = function_parts[-1]
            owner_token = (
                function_parts[-2]
                if len(function_parts) > 1 and function_parts[-2][:1].isupper()
                else None
            )
            self.assertIn(function_token, source_path.read_text(errors="replace"))
            seams = target["test_seams"]
            self.assertTrue(seams, target)
            self.assertTrue(
                any(
                    function_token in (ROOT / seam).read_text(errors="replace")
                    and (
                        owner_token is None
                        or owner_token in (ROOT / seam).read_text(errors="replace")
                    )
                    for seam in seams
                ),
                target,
            )

    def test_historical_raw_signature_targets_are_absent(self):
        manifest_text = MANIFEST.read_text().lower()
        self.assertNotIn("privacy/adaptor", manifest_text)
        self.assertNotIn("adaptor_generate_keypair", manifest_text)
        self.assertTrue((ROOT / "crates/online-watcher/src/protocol/schnorr.rs").is_file())
        self.assertTrue((ROOT / "crates/online-watcher/src/protocol/private_swap/adaptor.rs").is_file())
        signing_policy = (ROOT / "qa/checks/quality/crap/policy.json").read_text()
        self.assertIn("crates/online-watcher/src/protocol/schnorr.rs", signing_policy)

    def test_branch_coverage_has_reproducible_internal_runner_and_bundle(self):
        makefile = (ROOT / "Makefile").read_text()
        dispatch = (ROOT / "scripts/common/lib/make_tasks.py").read_text()
        runner = (ROOT / "qa/linux/run-pinned-branch-coverage.sh").read_text()
        self.assertNotIn("branch-coverage-setup:", makefile)
        self.assertNotIn("branch-coverage-bundle:", makefile)
        self.assertIn("scripts/linux/quality/branch-coverage-setup.sh", runner)
        self.assertIn("qa/checks/quality/crap/package_branch_artifacts.py", runner)
        self.assertIn("CRAP_ENABLE_BRANCH=1", runner)
        self.assertIn("CRAP_BRANCH_TOOLCHAIN", runner)
        self.assertNotIn('env["CRAP_ENABLE_BRANCH"]', dispatch)
        self.assertTrue((ROOT / "qa/checks/quality/crap/package_branch_artifacts.py").is_file())



if __name__ == "__main__":
    unittest.main()
