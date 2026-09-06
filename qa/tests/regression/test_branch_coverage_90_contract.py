import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECK_DIR = ROOT / "qa/checks/quality/crap"
sys.path.insert(0, str(CHECK_DIR))
from regression import compare_coverage_manifests, compare_health_summaries  # noqa: E402

class BranchCoverage90ContractTests(unittest.TestCase):
    def test_rust_host_and_critical_domains_require_ninety_percent_branches(self):
        policy = json.loads((ROOT / "qa/checks/quality/crap/policy.json").read_text())["health"]
        self.assertEqual(policy["minimum_host_line_coverage_percent"], 90.0)
        self.assertEqual(policy["minimum_host_function_coverage_percent"], 90.0)
        self.assertEqual(policy["minimum_host_branch_coverage_percent"], 90.0)
        for name, domain in policy["critical_domains"].items():
            self.assertGreaterEqual(domain["minimum_branch_coverage_percent"], 90.0, name)
        crypto = policy["critical_domains"]["critical_crypto"]
        self.assertEqual(crypto["target_branch_coverage_percent"], 100.0)

    def test_browser_recovery_and_full_web_runtime_require_ninety_percent_branches(self):
        recovery = (ROOT / "qa/checks/web/run_web_recovery_coverage.py").read_text()
        runtime = (ROOT / "qa/checks/web/run_web_runtime_coverage.py").read_text()
        self.assertIn("MINIMUM_BRANCH = 90.0", recovery)
        self.assertIn("branch_percent >= args.minimum_branch", recovery)
        self.assertIn("MIN_BRANCH_COVERAGE_PERCENT = 90.0", runtime)
        self.assertIn("branches_rounded >= MIN_BRANCH_COVERAGE_PERCENT", runtime)


    def test_branch_coverage_uses_compact_committed_ratchet_and_unoptimized_profile(self):
        regression = (ROOT / "qa/checks/quality/crap/regression.py").read_text()
        runner = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        ratchet = json.loads((ROOT / "qa/contracts/quality/crap_ratchets.json").read_text())
        self.assertIn('def compare_health_summaries(', regression)
        self.assertIn('for metric in ("lines", "functions", "branches")', regression)
        self.assertIn('host production {metric} coverage regressed', regression)
        self.assertIn('COVERAGE_DEV_OPT_LEVEL="${CRAP_DEV_OPT_LEVEL:-0}"', runner)
        self.assertIn('COVERAGE_TEST_OPT_LEVEL="${CRAP_TEST_OPT_LEVEL:-0}"', runner)
        self.assertIn('CARGO_PROFILE_DEV_OPT_LEVEL="$COVERAGE_DEV_OPT_LEVEL"', runner)
        self.assertIn('CARGO_PROFILE_TEST_OPT_LEVEL="$COVERAGE_TEST_OPT_LEVEL"', runner)
        self.assertIn("source-faithful LLVM function/branch mapping", runner)
        profile = ratchet["coverage_profile"]
        self.assertEqual(profile["dev_opt_level"], "0")
        self.assertEqual(profile["test_opt_level"], "0")
        self.assertIs(profile["branch_instrumentation"], True)
        self.assertFalse((ROOT / "qa/baselines/crap").exists())

    def test_crypto_branch_vectors_cover_real_fail_closed_boundaries(self):
        adaptor = (ROOT / "crates/offline-signer/src/crypto/unit_tests/adaptor_tests.rs").read_text()
        anti_klepto = (ROOT / "crates/offline-signer/src/crypto/unit_tests/anti_klepto_tests.rs").read_text()
        storage = (ROOT / "crates/offline-signer/src/crypto/unit_tests/device_bound_storage_tests.rs").read_text()
        schnorr = (ROOT / "crates/offline-signer/src/crypto/unit_tests/schnorr_tests.rs").read_text()
        for needle in ("nonzero_reduced_scalar", "nonzero_scalar_sum"):
            self.assertIn(needle, adaptor)
        self.assertIn("nonce_cancellation_fail_closed", anti_klepto)
        self.assertIn("FailSecondEntropy", storage)
        self.assertIn("ZeroNonceEntropy", storage)
        self.assertIn("SigningFailed", schnorr)

    def test_hard_target_failure_reports_concrete_lcov_branch_identities(self) -> None:
        ratchet = (ROOT / "qa/checks/security/branch_ratchets.py").read_text()
        self.assertIn('LCOV = ROOT / "target/qa/crap/lcov.info"', ratchet)
        self.assertIn("def _uncovered_domain_branches", ratchet)
        self.assertIn('raw.startswith("BRDA:")', ratchet)
        self.assertIn('_print_target_branch_diagnostics(document)', ratchet)

    def test_critical_crypto_copy_nonzero_covers_short_exact_and_overlong_lengths(self) -> None:
        tests = (
            ROOT / "crates/offline-signer/src/crypto/unit_tests/container_framing_tests.rs"
        ).read_text()
        self.assertIn("copy_nonzero::<4>(&[1, 2, 3])", tests)
        self.assertIn("copy_nonzero::<4>(&[1, 2, 3, 4, 5])", tests)
        self.assertIn("copy_nonzero::<4>(&[1, 2, 3, 4])", tests)

    def test_critical_crypto_timing_predicate_has_no_impossible_both_zero_branch(self) -> None:
        security = (ROOT / "crates/signer-firmware-core/src/security.rs").read_text()
        tests = (ROOT / "crates/signer-firmware-core/src/unit_tests/security_tests.rs").read_text()
        self.assertIn("pub fn timing_observations_usable", security)
        self.assertIn("first != second", security)
        self.assertNotIn("first != second &&", security)
        self.assertNotIn("second == (0, 0)", security)
        self.assertIn("timing_observations_usable((0, 0), (0, 0))", tests)
        self.assertIn("timing_observations_usable((5, 9), (5, 9))", tests)
        self.assertIn("timing_observations_usable((0, 0), (0, 1))", tests)
        self.assertIn("timing_observations_usable((1, 0), (0, 0))", tests)
        self.assertIn("timing_observations_usable((5, 9), (5, 10))", tests)

    def test_transaction_construction_branch_boundaries_have_direct_host_vectors(self) -> None:
        private_swap = (
            ROOT
            / "crates/online-watcher/src/contracts/covenant/script/private_swap/unit_tests/mod.rs"
        ).read_text()
        construction = (
            ROOT / "crates/online-watcher/src/contracts/unit_tests/construction.rs"
        ).read_text()
        script_tests = (
            ROOT / "crates/online-watcher/src/protocol/script/unit_tests/mod.rs"
        ).read_text()
        self.assertIn("private_swap_rejects_invalid_configuration_boundaries", private_swap)
        self.assertIn("crowdfund_configuration_validation_boundaries_are_covered", construction)
        self.assertIn("allowance_builders_cover_absent_optional_locktimes", script_tests)
        canonical_decode = (
            ROOT
            / "crates/kassigner-protocol/src/unit_tests/kspt_wire/decode_boundaries.rs"
        ).read_text()
        canonical_encode = (
            ROOT
            / "crates/kassigner-protocol/src/unit_tests/kspt_wire/encode_boundaries.rs"
        ).read_text()
        canonical_sink = (
            ROOT
            / "crates/kassigner-protocol/src/unit_tests/kspt_wire/sink_boundaries.rs"
        ).read_text()
        self.assertIn(
            "canonical_decoder_rejects_duplicate_and_out_of_range_trailers",
            canonical_decode,
        )
        self.assertIn(
            "canonical_encoder_rejects_every_resource_and_signature_boundary",
            canonical_encode,
        )
        self.assertIn(
            "canonical_decoder_propagates_every_sink_boundary", canonical_sink
        )

    def test_fail_closed_field_mutation_coverage_is_security_meaningful(self):
        covenant = (ROOT / "crates/shared-signer/src/covenant_sign/unit_tests/mod.rs").read_text()
        private_swap = (ROOT / "crates/shared-signer/src/covenant_sign/private_swap/unit_tests/mod.rs").read_text()
        self.assertIn("request_field_invariants_reject_each_independent_invalid_shape", covenant)
        self.assertIn("response_field_invariants_reject_each_independent_invalid_shape", covenant)
        self.assertIn("private_swap_request_fields_fail_closed_one_at_a_time", private_swap)
        self.assertIn("private_swap_response_fields_fail_closed_one_at_a_time", private_swap)

    def test_existing_thresholds_are_not_lowered(self) -> None:
        policy = json.loads((ROOT / "qa/checks/quality/crap/policy.json").read_text())
        ratchet = json.loads((ROOT / "qa/contracts/quality/crap_ratchets.json").read_text())
        self.assertEqual(policy["regression"]["coverage_drop_tolerance_percent"], 0.05)
        self.assertEqual(policy["health"]["minimum_host_branch_coverage_percent"], 90.0)
        self.assertEqual(ratchet["host_production_minimum_percent"]["lines"], 95.9701)
        self.assertEqual(ratchet["host_production_minimum_percent"]["functions"], 90.6473)
        self.assertEqual(ratchet["host_production_minimum_percent"]["branches"], 91.4141)
        self.assertIs(ratchet["coverage_profile"]["branch_instrumentation"], True)

    def test_raw_manifest_keeps_branch_instrumentation_contract_only(self) -> None:
        profile = {"dev_opt_level": "0", "test_opt_level": "0", "branch_instrumentation": True}
        previous = {
            "coverage_profile": profile,
            "branch_coverage_requested": True,
            "coverage": {"branches": {"available": True, "percent": 95.0}},
        }
        current = {
            "coverage_profile": profile,
            "branch_coverage_requested": True,
            "coverage": {"branches": {"available": True, "percent": 50.0}},
        }
        self.assertEqual(compare_coverage_manifests(previous, current, {}), [])
        current["coverage"]["branches"]["available"] = False
        self.assertIn("branch coverage disappeared", compare_coverage_manifests(previous, current, {})[0])

    def test_classified_host_production_metric_is_the_regression_ratchet(self) -> None:
        profile = {"dev_opt_level": "0", "test_opt_level": "0", "branch_instrumentation": True}
        run = {"coverage_profile": profile}
        previous = {
            "host_metrics": {
                "lines": {"percent": 96.0},
                "functions": {"percent": 91.0},
                "branches": {"percent": 91.4141},
            }
        }
        current = {
            "host_metrics": {
                "lines": {"percent": 96.0},
                "functions": {"percent": 91.0},
                "branches": {"percent": 91.30},
            }
        }
        errors = compare_health_summaries(
            previous,
            current,
            run,
            run,
            {"coverage_drop_tolerance_percent": 0.05},
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("host production branches coverage regressed", errors[0])
        current["host_metrics"]["branches"]["percent"] = 91.37
        self.assertEqual(
            compare_health_summaries(
                previous,
                current,
                run,
                run,
                {"coverage_drop_tolerance_percent": 0.05},
            ),
            [],
        )





    def test_platform_runners_preserve_previous_health_summary(self) -> None:
        linux = (ROOT / "scripts/linux/quality/crap.sh").read_text()
        windows = (ROOT / "scripts/windows/quality/crap_windows.py").read_text()
        for source in (linux, windows):
            self.assertIn("previous_health_summary.json", source)
            self.assertIn("--previous-health-summary", source)


if __name__ == "__main__":
    unittest.main()
