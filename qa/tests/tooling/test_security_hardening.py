#!/usr/bin/env python3
"""Regression tests for the non-HIL production-hardening gates."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))
from toolchains import load_toolchains  # noqa: E402
from security.fuzz_targets import registered_targets  # noqa: E402

PINS = load_toolchains()


def load_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


invariants = load_module("security_invariants", "qa/checks/security/security_invariants.py")
test_quality = load_module("security_test_quality", "qa/checks/security/test_quality.py")
repository_test_quality = load_module(
    "repository_test_quality", "qa/checks/security/repository_test_quality.py"
)
mutation = load_module("security_mutation", "qa/checks/security/mutation.py")
mutation_support = sys.modules["mutation_support"]
mutation_reuse = sys.modules["mutation_reuse"]
mutation_runner = sys.modules["mutation_runner"]
security_evidence = load_module("security_evidence", "qa/checks/security/security_control_evidence.py")
security_scans = sys.modules["security_control_scans"]


class SecurityHardeningTests(unittest.TestCase):

    def test_security_review_paths_are_canonical_across_host_separators(self) -> None:
        with mock.patch.object(
            Path,
            "relative_to",
            return_value=PureWindowsPath(r"apps\signer-firmware\src\boot\waveshare\mod.rs"),
        ):
            self.assertEqual(
                security_scans.relative(ROOT / "placeholder.rs"),
                "apps/signer-firmware/src/boot/waveshare/mod.rs",
            )

    def test_repository_security_invariants_are_enforced(self) -> None:
        errors, report = invariants.audit()
        self.assertEqual(errors, [])
        self.assertTrue(report["healthy"])
        self.assertEqual(report["invariants_met"], report["invariants_total"])

    def test_critical_tests_have_assertions_and_required_evidence(self) -> None:
        errors, report = test_quality.audit()
        self.assertEqual(errors, [])
        self.assertTrue(report["healthy"])
        self.assertEqual(report["trivial_assertion_tests"], [])
        self.assertGreater(report["tests_scanned"], 300)
        self.assertGreater(report["capabilities"]["negative_path_tests"], 100)
        self.assertGreater(report["capabilities"]["exact_error_tests"], 30)
        self.assertGreater(report["capabilities"]["round_trip_tests"], 10)
        self.assertGreater(report["capabilities"]["state_transition_tests"], 20)

    def test_repository_wide_test_quality_has_no_vacuous_or_tautological_passes(self) -> None:
        errors, report = repository_test_quality.audit()
        self.assertEqual(errors, [])
        self.assertTrue(report["healthy"])
        self.assertGreater(report["tests_scanned"], 1200)
        self.assertGreater(report["by_language"]["rust"], 800)
        self.assertGreater(report["by_language"]["python"], 400)
        self.assertGreaterEqual(report["by_language"]["javascript"], 30)
        self.assertGreaterEqual(report["by_language"]["kotlin"], 4)
        self.assertGreaterEqual(report["by_language"]["swift"], 3)

    def test_repository_test_quality_rejects_python_tautologies(self) -> None:
        node = __import__("ast").parse("def test_bad():\n    assert True\n").body[0]
        self.assertEqual(repository_test_quality._python_trivial(node), ["assert True"])

    def test_repository_test_quality_rejects_javascript_tautologies(self) -> None:
        code = repository_test_quality._strip_javascript_strings_and_comments(
            "assert.equal(value, value);\nassert.ok(true);\n"
        )
        self.assertEqual(
            repository_test_quality._javascript_trivial(code),
            ["constant true assertion", "self/constant equality"],
        )

    def test_test_quality_rejects_tautologies_and_trivial_passes(self) -> None:
        cases = {
            "constant true": "fn t() { assert!(true); }",
            "self equality": "fn t() { let value = compute(); assert_eq!(value, value); }",
            "same function call": "fn t() { assert_eq!(view_tag(&shared), view_tag(&shared)); }",
            "constant equality": "fn t() { assert_eq!(7, 7); }",
            "constant inequality": "fn t() { assert_ne!(1, 2); }",
            "assert self equality": "fn t() { let value = compute(); assert!(value == value); }",
        }
        for label, body in cases.items():
            with self.subTest(label=label):
                self.assertTrue(test_quality.trivial_assertions(body), body)

        meaningful = (
            'fn t() { let actual = view_tag(&[0x77; 32]); '
            'assert_eq!(actual, 0x63); assert_ne!(actual, view_tag(&[0x78; 32])); }'
        )
        self.assertEqual(test_quality.trivial_assertions(meaningful), [])

    def test_mutation_summary_enforces_score_and_timeout_gates(self) -> None:
        policy = mutation.load_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            output.mkdir(parents=True)
            outcomes = {
                "cargo_mutants_version": policy["cargo_mutants_version"],
                "total_mutants": 26,
                "caught": 23,
                "missed": 2,
                "timeout": 0,
                "unviable": 1,
                "start_time": "2026-08-06T00:00:00Z",
                "end_time": "2026-08-06T01:00:00Z",
                "outcomes": [],
            }
            (output / "outcomes.json").write_text(json.dumps(outcomes))
            artifact = root / "summary.json"
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            retained_triage = ROOT / "target/qa/security/latest/mutation-triage.json"
            retained_before = retained_triage.read_bytes() if retained_triage.is_file() else None
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                errors, report = mutation.summarize(policy, output_parent, artifact)
                self.assertEqual(errors, [])
                self.assertEqual(report["score_percent"], 92.0)
                self.assertEqual(report["counts"]["caught"], 23)
                self.assertEqual(report["total_mutants"], 26)
                self.assertEqual(report["reported_version"], PINS["KASSIGNER_CARGO_MUTANTS_VERSION"])
                self.assertEqual(len(report["mutation_scope_sha256"]), 64)
                self.assertEqual(len(report["workspace_test_sha256"]), 64)
                self.assertIsNone(report["evidence_run_scope"])
                self.assertFalse((output / mutation.RUN_SCOPE_FILE).exists())
                self.assertTrue((root / "persisted/mutation-results.zip").is_file())
                self.assertTrue((root / "mutation-triage.json").is_file())
                if retained_before is None:
                    self.assertFalse(retained_triage.is_file())
                else:
                    self.assertEqual(retained_triage.read_bytes(), retained_before)

                outcomes["timeout"] = 1
                outcomes["total_mutants"] = 27
                (output / "outcomes.json").write_text(json.dumps(outcomes))
                errors, report = mutation.summarize(policy, output_parent, artifact)
                self.assertFalse(report["healthy"])
                self.assertTrue(any("timeout" in error for error in errors))
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir



    def _crypto_outcome(self, name: str, summary: str) -> dict[str, object]:
        return {
            "scenario": {
                "Mutant": {
                    "name": name,
                    "package": "shared-signer",
                    "file": "crates/shared-signer/src/bytes.rs",
                    "function": {"function_name": "constant_time_eq_32"},
                    "replacement": "false",
                    "genre": "FnValue",
                }
            },
            "summary": summary,
        }

    def _write_crypto_evidence(self, output: Path, outcomes: list[dict[str, object]]) -> None:
        counts = {
            "caught": sum(item["summary"] == "CaughtMutant" for item in outcomes),
            "missed": sum(item["summary"] == "MissedMutant" for item in outcomes),
            "timeout": sum(item["summary"] == "Timeout" for item in outcomes),
            "unviable": sum(item["summary"] == "Unviable" for item in outcomes),
        }
        document = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "total_mutants": len(outcomes),
            **counts,
            "outcomes": outcomes,
        }
        output.mkdir(parents=True, exist_ok=True)
        (output / "outcomes.json").write_text(json.dumps(document))
        inventory = []
        for outcome in outcomes:
            mutant = dict(outcome["scenario"]["Mutant"])
            mutant.setdefault("diff", "")
            inventory.append(mutant)
        (output / "mutants.json").write_text(json.dumps(inventory))
        mutation.write_run_scope(
            output,
            source_digest=mutation.mutation_scope_sha256(),
            test_digest=mutation.workspace_test_sha256(),
            tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            evidence_mode="development-full",
            candidate_certified=False,
            config_digest=mutation.mutation_config_sha256(),
            inventory_digest=mutation_reuse.inventory_sha256(inventory),
        )

    def test_crypto_mutation_domain_requires_100_percent_and_zero_timeouts(self) -> None:
        policy = mutation._load_crypto_policy()
        self.assertEqual(policy["minimum_score_percent"], 100.0)
        self.assertEqual(policy["maximum_timeouts"], 0)
        self.assertEqual(policy["equivalent_mutants"], [])
        self.assertIn("crates/online-watcher/src/privacy/stealth/derivation.rs", policy["include_globs"])
        self.assertNotIn("crates/online-watcher/src/contracts/zk/rng.rs", policy["include_globs"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            caught = self._crypto_outcome("crypto-caught", "CaughtMutant")
            self._write_crypto_evidence(output, [caught])
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary.json"
                )
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir
            self.assertEqual(errors, [])
            self.assertTrue(report["healthy"])
            self.assertEqual(report["score_percent"], 100.0)
            self.assertEqual(report["counts"]["timeout"], 0)
            self.assertGreater(len(report["domain_files"]), 20)

    def test_crypto_mutation_domain_accepts_windows_native_path_separators(self) -> None:
        policy = mutation._load_crypto_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            caught = self._crypto_outcome("crypto-windows-path", "CaughtMutant")
            caught["scenario"]["Mutant"]["file"] = r"crates\shared-signer\src\bytes.rs"
            self._write_crypto_evidence(output, [caught])
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary.json"
                )
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir
            self.assertEqual(errors, [])
            self.assertEqual(
                report["domain_files_with_mutants"],
                ["crates/shared-signer/src/bytes.rs"],
            )

    def test_crypto_mutation_domain_rejects_missed_and_timeout_mutants(self) -> None:
        policy = mutation._load_crypto_policy()
        for summary, expected in (("MissedMutant", "missed"), ("Timeout", "timeout")):
            with self.subTest(summary=summary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output_parent = root / "mutation"
                output = output_parent / "mutants.out"
                self._write_crypto_evidence(output, [self._crypto_outcome("crypto-bad", summary)])
                old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
                os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
                try:
                    errors, report = mutation.summarize_crypto_domain(
                        policy, output_parent, root / "crypto-summary.json"
                    )
                finally:
                    if old_run_dir is None:
                        os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                    else:
                        os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir
                self.assertFalse(report["healthy"])
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_crypto_equivalent_mutant_requires_exact_current_miss_and_refactor_record(self) -> None:
        policy = mutation._load_crypto_policy()
        equivalent_name = "equivalent-after-refactor"
        source_file = "crates/shared-signer/src/bytes.rs"
        policy["equivalent_mutants"] = [{
            "name": equivalent_name,
            "file": source_file,
            "function": "constant_time_eq_32",
            "replacement": "false",
            "source_sha256": mutation._sha256_file(ROOT / source_file),
            "justification": "The replacement is mathematically identical for disjoint bit lanes.",
            "refactor_attempted": "The expression was first refactored to remove the redundant branch; this residual compiler form remained.",
        }]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            self._write_crypto_evidence(output, [
                self._crypto_outcome("crypto-caught", "CaughtMutant"),
                self._crypto_outcome(equivalent_name, "MissedMutant"),
            ])
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary.json"
                )
                self.assertEqual(errors, [])
                self.assertEqual(report["counts"]["approved_equivalent"], 1)
                self.assertEqual(report["counts"]["remaining_missed"], 0)
                self.assertEqual(report["score_percent"], 100.0)

                policy["equivalent_mutants"][0]["name"] = "stale-mutant-name"
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary-stale.json"
                )
                self.assertFalse(report["healthy"])
                self.assertTrue(any("stale or non-missed" in error for error in errors))
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir


    def test_crypto_equivalent_mutant_rejects_test_difficulty_and_identity_drift(self) -> None:
        policy = mutation._load_crypto_policy()
        source_file = "crates/shared-signer/src/bytes.rs"
        equivalent_name = "equivalent-after-refactor"
        base_entry = {
            "name": equivalent_name,
            "file": source_file,
            "function": "constant_time_eq_32",
            "replacement": "false",
            "source_sha256": mutation._sha256_file(ROOT / source_file),
            "justification": "The replacement is mathematically identical after the attempted simplification.",
            "refactor_attempted": "The redundant expression was rewritten first and the remaining mutant was re-measured.",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            self._write_crypto_evidence(output, [
                self._crypto_outcome("crypto-caught", "CaughtMutant"),
                self._crypto_outcome(equivalent_name, "MissedMutant"),
            ])
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                policy["equivalent_mutants"] = [dict(
                    base_entry, justification="This mutant is hard to test in practice."
                )]
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary-difficulty.json"
                )
                self.assertFalse(report["healthy"])
                self.assertTrue(any("test difficulty" in error for error in errors), errors)

                policy["equivalent_mutants"] = [dict(
                    base_entry, replacement="true"
                )]
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary-identity.json"
                )
                self.assertFalse(report["healthy"])
                self.assertTrue(any("identity does not match" in error for error in errors), errors)
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir

    def test_crypto_mutation_domain_rejects_stale_provenance(self) -> None:
        policy = mutation._load_crypto_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            self._write_crypto_evidence(output, [self._crypto_outcome("crypto-caught", "CaughtMutant")])
            scope = json.loads((output / mutation.RUN_SCOPE_FILE).read_text())
            scope["mutation_scope_sha256"] = "0" * 64
            (output / mutation.RUN_SCOPE_FILE).write_text(json.dumps(scope))
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                errors, report = mutation.summarize_crypto_domain(
                    policy, output_parent, root / "crypto-summary.json"
                )
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir
            self.assertFalse(report["healthy"])
            self.assertTrue(any("production scope is stale" in error for error in errors))

    def test_mutation_summary_never_blesses_stale_outcomes_with_current_scope(self) -> None:
        policy = mutation.load_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            output = output_parent / "mutants.out"
            output.mkdir(parents=True)
            outcomes = {
                "cargo_mutants_version": policy["cargo_mutants_version"],
                "total_mutants": 10,
                "caught": 9,
                "missed": 1,
                "timeout": 0,
                "unviable": 0,
                "outcomes": [],
            }
            (output / "outcomes.json").write_text(json.dumps(outcomes))
            stale = {
                "schema_version": 1,
                "mutation_scope_sha256": "1" * 64,
                "workspace_test_sha256": "2" * 64,
                "cargo_mutants_version": policy["cargo_mutants_version"],
            }
            provenance = output / mutation.RUN_SCOPE_FILE
            provenance.write_text(json.dumps(stale))
            before = provenance.read_bytes()
            old_run_dir = os.environ.get("KASSIGNER_SECURITY_RUN_DIR")
            os.environ["KASSIGNER_SECURITY_RUN_DIR"] = str(root / "persisted")
            try:
                _, report = mutation.summarize(policy, output_parent, root / "summary.json")
            finally:
                if old_run_dir is None:
                    os.environ.pop("KASSIGNER_SECURITY_RUN_DIR", None)
                else:
                    os.environ["KASSIGNER_SECURITY_RUN_DIR"] = old_run_dir
            self.assertEqual(provenance.read_bytes(), before)
            self.assertEqual(report["evidence_run_scope"]["schema_version"], 1)
            self.assertEqual(report["evidence_run_scope"]["evidence_mode"], "legacy")
            self.assertFalse(report["evidence_run_scope"]["candidate_certified"])
            for key in (
                "mutation_scope_sha256",
                "workspace_test_sha256",
                "cargo_mutants_version",
            ):
                self.assertEqual(report["evidence_run_scope"][key], stale[key])
            self.assertNotEqual(
                report["mutation_scope_sha256"],
                report["evidence_run_scope"]["mutation_scope_sha256"],
            )


    def test_mutation_evidence_without_run_provenance_is_not_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            (results / "outcomes.json").write_text("{}")
            self.assertIsNone(mutation.load_run_scope(results))

    def test_mutation_cache_requires_immutable_matching_run_provenance(self) -> None:
        current_source = "a" * 64
        current_tests = "b" * 64
        matching = {
            "mutation_scope_sha256": current_source,
            "workspace_test_sha256": current_tests,
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
        }
        self.assertEqual(
            mutation.mutation_cache_action(
                use_iterate=True,
                has_existing_outcomes=True,
                run_scope=None,
                current_scope=current_source,
                current_test_scope=current_tests,
                reuse_unchanged=True,
            ),
            "fresh-unprovenanced",
        )
        changed_source = dict(matching, mutation_scope_sha256="c" * 64)
        self.assertEqual(
            mutation.mutation_cache_action(
                use_iterate=True,
                has_existing_outcomes=True,
                run_scope=changed_source,
                current_scope=current_source,
                current_test_scope=current_tests,
                reuse_unchanged=True,
            ),
            "iterate-source-changed",
        )
        changed_tests = dict(matching, workspace_test_sha256="d" * 64)
        self.assertEqual(
            mutation.mutation_cache_action(
                use_iterate=True,
                has_existing_outcomes=True,
                run_scope=changed_tests,
                current_scope=current_source,
                current_test_scope=current_tests,
                reuse_unchanged=True,
            ),
            "iterate-tests-changed",
        )
        self.assertEqual(
            mutation.mutation_cache_action(
                use_iterate=True,
                has_existing_outcomes=True,
                run_scope=matching,
                current_scope=current_source,
                current_test_scope=current_tests,
                reuse_unchanged=True,
            ),
            "reuse",
        )

    def test_incremental_mutation_results_merge_with_prior_caught_outcomes(self) -> None:
        def outcome(name: str, summary: str) -> dict[str, object]:
            return {
                "scenario": {"Mutant": {"name": name}},
                "summary": summary,
                "log_path": None,
                "diff_path": None,
                "phase_results": [],
            }

        previous = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "start_time": "2026-08-06T00:00:00Z",
            "end_time": "2026-08-06T01:00:00Z",
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("caught-before", "CaughtMutant"),
                outcome("still-missed", "MissedMutant"),
                outcome("still-timeout", "Timeout"),
                outcome("unviable-before", "Unviable"),
            ],
        }
        current = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "start_time": "2026-08-06T02:00:00Z",
            "end_time": "2026-08-06T03:00:00Z",
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("still-missed", "CaughtMutant"),
                outcome("still-timeout", "Timeout"),
                outcome("new-mutant", "MissedMutant"),
            ],
        }

        merged = mutation.merge_outcome_documents(previous, current)
        self.assertEqual(merged["total_mutants"], 5)
        self.assertEqual(merged["caught"], 2)
        self.assertEqual(merged["missed"], 1)
        self.assertEqual(merged["timeout"], 1)
        self.assertEqual(merged["unviable"], 1)
        self.assertEqual(merged["start_time"], previous["start_time"])
        self.assertEqual(merged["end_time"], current["end_time"])

    def test_mutation_checkpoint_restore_is_atomic_and_requires_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "checkpoint.zip"
            output_parent = root / "target/qa/mutation"
            prefix = "mutation/mutants.out/"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(prefix + "outcomes.json", json.dumps({"caught": 1, "outcomes": []}))
                archive.writestr(prefix + "mutants.json", "[]")
                archive.writestr(
                    prefix + mutation.RUN_SCOPE_FILE,
                    json.dumps({"schema_version": 2, "evidence_mode": "development-full"}),
                )
            self.assertTrue(
                mutation_support._restore_results_archive(archive_path, output_parent)
            )
            restored = output_parent / "mutants.out"
            self.assertTrue((restored / "outcomes.json").is_file())
            self.assertTrue((restored / "mutants.json").is_file())
            self.assertTrue((restored / mutation.RUN_SCOPE_FILE).is_file())

    def test_mutation_checkpoint_restore_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "checkpoint.zip"
            output_parent = root / "target/qa/mutation"
            prefix = "mutation/mutants.out/"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(prefix + "outcomes.json", "{}")
                archive.writestr(prefix + "mutants.json", "[]")
                archive.writestr(prefix + mutation.RUN_SCOPE_FILE, "{}")
                archive.writestr(prefix + "../../escaped.txt", "bad")
            self.assertFalse(
                mutation_support._restore_results_archive(archive_path, output_parent)
            )
            self.assertFalse((root / "target/escaped.txt").exists())

    def test_context_aware_mutation_reuse_carries_only_unchanged_caught_mutants(self) -> None:
        def mutant(name: str, diff: str) -> dict[str, object]:
            return {
                "name": name,
                "package": "online-watcher",
                "file": "crates/online-watcher/src/example.rs",
                "function": {
                    "function_name": "example",
                    "return_type": "-> bool",
                    "span": {"start": {"line": 1, "column": 1}, "end": {"line": 3, "column": 2}},
                },
                "span": {"start": {"line": 2, "column": 5}, "end": {"line": 2, "column": 9}},
                "replacement": "false",
                "genre": "FnValue",
                "diff": diff,
            }

        def outcome(name: str, summary: str) -> dict[str, object]:
            return {
                "scenario": {"Mutant": {"name": name}},
                "summary": summary,
                "log_path": f"log/{name}.log",
                "diff_path": f"diff/{name}.diff",
            }

        previous_inventory = [
            mutant("stable-caught", "same-context"),
            mutant("changed-caught", "old-context"),
            mutant("stable-missed", "missed-context"),
            mutant("stable-unviable", "unviable-context"),
            mutant("removed-caught", "removed-context"),
        ]
        current_inventory = [
            mutant("stable-caught", "same-context"),
            mutant("changed-caught", "new-context"),
            mutant("stable-missed", "missed-context"),
            mutant("stable-unviable", "unviable-context"),
            mutant("new-mutant", "new-mutant-context"),
        ]
        previous = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("stable-caught", "CaughtMutant"),
                outcome("changed-caught", "CaughtMutant"),
                outcome("stable-missed", "MissedMutant"),
                outcome("stable-unviable", "Unviable"),
                outcome("removed-caught", "CaughtMutant"),
            ],
        }

        plan = mutation_reuse.plan_incremental_reuse(
            previous, previous_inventory, current_inventory
        )
        self.assertEqual(plan["carry_caught_names"], ["stable-caught"])
        self.assertEqual(plan["carry_unviable_names"], ["stable-unviable"])
        self.assertEqual(
            set(plan["rerun_names"]),
            {"changed-caught", "stable-missed", "new-mutant"},
        )
        self.assertEqual(plan["changed_names"], ["changed-caught"])
        self.assertEqual(plan["new_names"], ["new-mutant"])
        self.assertEqual(plan["removed_names"], ["removed-caught"])
        self.assertEqual(plan["carried_forward_caught"], 1)
        self.assertEqual(plan["carried_forward_unviable"], 1)

        carried = mutation_reuse.carry_forward_document(
            previous, plan["carry_caught_names"], plan["carry_unviable_names"]
        )
        self.assertEqual(carried["caught"], 1)
        self.assertEqual(carried["unviable"], 1)
        self.assertEqual(
            [mutation_reuse.outcome_name(item) for item in carried["outcomes"] if isinstance(item, dict)],
            [None, "stable-caught", "stable-unviable"],
        )

        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            (results / "caught.txt").write_text("stale-changed-caught\n")
            (results / "unviable.txt").write_text("stale-changed-unviable\n")
            mutation_reuse.write_iterate_skip_state(
                results, plan["carry_caught_names"], plan["carry_unviable_names"]
            )
            self.assertEqual((results / "caught.txt").read_text(), "")
            self.assertEqual((results / "unviable.txt").read_text(), "")
            self.assertEqual(
                (results / "previously_caught.txt").read_text(),
                "stable-caught\nstable-unviable\n",
            )

    def test_source_changed_execute_reuses_only_context_proven_development_outcomes(self) -> None:
        def mutant(name: str, diff: str) -> dict[str, object]:
            return {
                "name": name,
                "package": "online-watcher",
                "file": "crates/online-watcher/src/example.rs",
                "function": {
                    "function_name": "example",
                    "return_type": "-> bool",
                    "span": {"start": {"line": 1, "column": 1}, "end": {"line": 3, "column": 2}},
                },
                "span": {"start": {"line": 2, "column": 5}, "end": {"line": 2, "column": 9}},
                "replacement": "false",
                "genre": "FnValue",
                "diff": diff,
            }

        def outcome(name: str, summary: str) -> dict[str, object]:
            return {
                "scenario": {"Mutant": {"name": name}},
                "summary": summary,
                "log_path": None,
                "diff_path": None,
                "phase_results": [],
            }

        previous_inventory = [
            mutant("stable-caught", "same-context"),
            mutant("stable-unviable", "same-unviable"),
            mutant("changed-caught", "old-context"),
            mutant("old-missed", "miss-context"),
            mutant("removed-caught", "removed-context"),
        ]
        current_inventory = [
            mutant("stable-caught", "same-context"),
            mutant("stable-unviable", "same-unviable"),
            mutant("changed-caught", "new-context"),
            mutant("old-missed", "miss-context"),
            mutant("new-mutant", "new-context"),
        ]
        previous = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "total_mutants": 5,
            "caught": 3,
            "missed": 1,
            "timeout": 0,
            "unviable": 1,
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("stable-caught", "CaughtMutant"),
                outcome("stable-unviable", "Unviable"),
                outcome("changed-caught", "CaughtMutant"),
                outcome("old-missed", "MissedMutant"),
                outcome("removed-caught", "CaughtMutant"),
            ],
        }
        current_run = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "total_mutants": 3,
            "caught": 2,
            "missed": 1,
            "timeout": 0,
            "unviable": 0,
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("changed-caught", "CaughtMutant"),
                outcome("old-missed", "CaughtMutant"),
                outcome("new-mutant", "MissedMutant"),
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            results = output_parent / "mutants.out"
            results.mkdir(parents=True)
            (results / "outcomes.json").write_text(json.dumps(previous))
            (results / "mutants.json").write_text(json.dumps(previous_inventory))
            (results / "caught.txt").write_text("stable-caught\nchanged-caught\nremoved-caught\n")
            (results / "unviable.txt").write_text("stable-unviable\n")
            mutation.write_run_scope(
                results,
                source_digest="a" * 64,
                test_digest="t" * 64,
                tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                evidence_mode="development-full",
                candidate_certified=False,
                config_digest="c" * 64,
                inventory_digest=mutation_reuse.inventory_sha256(previous_inventory),
            )
            policy = {
                "toolchain": "1.95.0",
                "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                "output_directory": str(output_parent),
                "artifact": str(root / "summary.json"),
                "iterate": True,
                "reuse_unchanged_results": True,
            }
            commands: list[list[str]] = []

            def fake_run(command: list[str], *, check: bool = True):
                commands.append(command)
                self.assertIn("--iterate", command)
                self.assertEqual((results / "caught.txt").read_text(), "")
                self.assertEqual((results / "unviable.txt").read_text(), "")
                self.assertEqual(
                    (results / "previously_caught.txt").read_text(),
                    "stable-caught\nstable-unviable\n",
                )
                import shutil
                shutil.rmtree(results)
                results.mkdir(parents=True)
                (results / "outcomes.json").write_text(json.dumps(current_run))
                (results / "mutants.json").write_text(json.dumps(current_inventory))
                return type("Result", (), {"returncode": 2})()

            def fake_summary(_policy, parent: Path, _artifact: Path):
                merged = json.loads((parent / "mutants.out/outcomes.json").read_text())
                return [], {
                    "score_percent": 80.0,
                    "counts": {"caught": merged["caught"]},
                    "viable_mutants": merged["caught"] + merged["missed"] + merged["timeout"],
                    "raw_artifact": "test.zip",
                    "candidate_certified": False,
                }

            with mock.patch.object(mutation_runner, "mutation_scope_sha256", return_value="b" * 64), \
                 mock.patch.object(mutation_runner, "workspace_test_sha256", return_value="t" * 64), \
                 mock.patch.object(mutation_runner, "mutation_config_sha256", return_value="c" * 64), \
                 mock.patch.object(mutation_runner, "_discover_current_mutants", return_value=(current_inventory, None)), \
                 mock.patch.object(mutation_runner, "run", side_effect=fake_run):
                status = mutation_runner.execute(
                    policy, install=False, fresh=False, summarize_fn=fake_summary
                )

            self.assertEqual(status, 0)
            self.assertEqual(len(commands), 1)
            merged = json.loads((results / "outcomes.json").read_text())
            merged_names = {
                mutation_reuse.outcome_name(item)
                for item in merged["outcomes"]
                if isinstance(item, dict) and mutation_reuse.outcome_name(item) is not None
            }
            self.assertEqual(
                merged_names,
                {"stable-caught", "stable-unviable", "changed-caught", "old-missed", "new-mutant"},
            )
            self.assertNotIn("removed-caught", merged_names)
            scope = mutation.load_run_scope(results)
            self.assertIsNotNone(scope)
            assert scope is not None
            self.assertEqual(scope["evidence_mode"], "development-incremental")
            self.assertFalse(scope["candidate_certified"])
            self.assertEqual(scope["carried_forward_caught"], 1)
            self.assertEqual(scope["carried_forward_unviable"], 1)
            self.assertEqual(scope["mutation_scope_sha256"], "b" * 64)

    def test_unprovenanced_partial_mutation_output_restores_verified_checkpoint(self) -> None:
        def mutant(name: str) -> dict[str, object]:
            return {
                "name": name,
                "package": "online-watcher",
                "file": "crates/online-watcher/src/example.rs",
                "function": {
                    "function_name": "example",
                    "return_type": "-> bool",
                    "span": {"start": {"line": 1, "column": 1}, "end": {"line": 3, "column": 2}},
                },
                "span": {"start": {"line": 2, "column": 5}, "end": {"line": 2, "column": 9}},
                "replacement": "false",
                "genre": "FnValue",
                "diff": name,
            }

        def outcome(name: str, summary: str) -> dict[str, object]:
            return {
                "scenario": {"Mutant": {"name": name}},
                "summary": summary,
                "log_path": None,
                "diff_path": None,
                "phase_results": [],
            }

        inventory = [mutant("stable-caught"), mutant("old-missed")]
        previous = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("stable-caught", "CaughtMutant"),
                outcome("old-missed", "MissedMutant"),
            ],
        }
        current_run = {
            "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                outcome("old-missed", "CaughtMutant"),
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output_parent = root / "mutation"
            partial = output_parent / "mutants.out"
            partial.mkdir(parents=True)
            (partial / "outcomes.json").write_text(json.dumps(current_run))
            policy = {
                "toolchain": "1.95.0",
                "cargo_mutants_version": PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                "output_directory": str(output_parent),
                "artifact": str(root / "summary.json"),
                "iterate": True,
                "reuse_unchanged_results": True,
            }

            def fake_restore(_output: Path) -> bool:
                restored = output_parent / "mutants.out"
                self.assertFalse(restored.exists())
                restored.mkdir(parents=True)
                (restored / "outcomes.json").write_text(json.dumps(previous))
                (restored / "mutants.json").write_text(json.dumps(inventory))
                (restored / "caught.txt").write_text("stable-caught\n")
                (restored / "unviable.txt").write_text("")
                mutation.write_run_scope(
                    restored,
                    source_digest="b" * 64,
                    test_digest="d" * 64,
                    tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                    evidence_mode="development-full",
                    candidate_certified=False,
                    config_digest="c" * 64,
                    inventory_digest=mutation_reuse.inventory_sha256(inventory),
                )
                return True

            def fake_run(command: list[str], *, check: bool = True):
                self.assertIn("--iterate", command)
                results = output_parent / "mutants.out"
                self.assertEqual((results / "caught.txt").read_text(), "")
                self.assertEqual((results / "unviable.txt").read_text(), "")
                self.assertEqual((results / "previously_caught.txt").read_text(), "stable-caught\n")
                import shutil
                shutil.rmtree(results)
                results.mkdir(parents=True)
                (results / "outcomes.json").write_text(json.dumps(current_run))
                (results / "mutants.json").write_text(json.dumps(inventory))
                return type("Result", (), {"returncode": 0})()

            def fake_summary(_policy, parent: Path, _artifact: Path):
                merged = json.loads((parent / "mutants.out/outcomes.json").read_text())
                return [], {
                    "score_percent": 100.0,
                    "counts": {"caught": merged["caught"]},
                    "viable_mutants": merged["caught"],
                    "raw_artifact": "test.zip",
                    "candidate_certified": False,
                }

            with mock.patch.object(mutation_runner, "mutation_scope_sha256", return_value="b" * 64), \
                 mock.patch.object(mutation_runner, "workspace_test_sha256", return_value="t" * 64), \
                 mock.patch.object(mutation_runner, "mutation_config_sha256", return_value="c" * 64), \
                 mock.patch.object(mutation_runner, "restore_results", side_effect=fake_restore), \
                 mock.patch.object(mutation_runner, "_discover_current_mutants", return_value=(inventory, None)), \
                 mock.patch.object(mutation_runner, "run", side_effect=fake_run):
                status = mutation_runner.execute(
                    policy, install=False, fresh=False, summarize_fn=fake_summary
                )

            self.assertEqual(status, 0)
            merged = json.loads((output_parent / "mutants.out/outcomes.json").read_text())
            self.assertEqual(merged["caught"], 2)
            self.assertEqual(merged["missed"], 0)

    def test_mutation_context_fingerprint_changes_when_source_context_changes(self) -> None:
        base = {
            "name": "same-name",
            "package": "shared-signer",
            "file": "crates/shared-signer/src/example.rs",
            "function": {"function_name": "f", "return_type": "-> bool"},
            "replacement": "false",
            "genre": "FnValue",
            "diff": "- old\n+ false",
        }
        changed = dict(base, diff="- changed source\n+ false")
        self.assertNotEqual(
            mutation_reuse.mutant_context_sha256(base),
            mutation_reuse.mutant_context_sha256(changed),
        )
        self.assertEqual(
            mutation_reuse.mutant_context_sha256(base),
            mutation_reuse.mutant_context_sha256(dict(base)),
        )

    def test_fresh_mutation_provenance_is_the_only_candidate_certified_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            mutation.write_run_scope(
                results,
                source_digest="a" * 64,
                test_digest="b" * 64,
                tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                evidence_mode="certification-fresh",
                candidate_certified=True,
                config_digest="c" * 64,
                inventory_digest="d" * 64,
            )
            loaded = mutation.load_run_scope(results)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertTrue(loaded["candidate_certified"])
            self.assertEqual(loaded["evidence_mode"], "certification-fresh")
            self.assertEqual(loaded["carried_forward_caught"], 0)
            self.assertEqual(loaded["carried_forward_unviable"], 0)

            with self.assertRaisesRegex(ValueError, "only certification-fresh"):
                mutation.write_run_scope(
                    results,
                    source_digest="a" * 64,
                    test_digest="b" * 64,
                    tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                    evidence_mode="development-incremental",
                    candidate_certified=True,
                    config_digest="c" * 64,
                    inventory_digest="d" * 64,
                )
            with self.assertRaisesRegex(ValueError, "cannot carry prior outcomes"):
                mutation.write_run_scope(
                    results,
                    source_digest="a" * 64,
                    test_digest="b" * 64,
                    tool_version=PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
                    evidence_mode="certification-fresh",
                    candidate_certified=True,
                    config_digest="c" * 64,
                    inventory_digest="d" * 64,
                    carried_forward_caught=1,
                )

    def test_healthy_hardening_bundle_requires_fresh_candidate_mutation_evidence(self) -> None:
        source = (ROOT / "qa/checks/security/package_artifacts.py").read_text()
        self.assertIn('document.get("candidate_certified") is not True', source)
        self.assertIn("development-only, not fresh candidate-certified", source)
        completion = (ROOT / "qa/checks/security/complete_hardening.py").read_text()
        self.assertIn('mutation.get("candidate_certified") is not True', completion)
        self.assertIn('crypto.get("candidate_certified") is not True', completion)

    def test_internal_security_evidence_is_explicit_about_limitations(self) -> None:
        errors, report = security_evidence.audit()
        self.assertEqual(errors, [])
        self.assertTrue(report["healthy"])
        self.assertFalse(report["third_party_independent_review"])
        self.assertEqual(report["hardware_in_the_loop"]["status"], "deferred-by-owner")
        self.assertGreaterEqual(len(report["limitations"]), 3)
        self.assertGreaterEqual(report["summary"]["residual_risks"], 1)
        self.assertTrue(report["source_scans"]["offline_network_boundary"]["met"])
        self.assertTrue(report["source_scans"]["unsafe_inventory"]["met"])
        self.assertTrue(report["source_scans"]["panic_inventory"]["met"])
        self.assertTrue(report["source_scans"]["secret_log_arguments"]["met"])
        self.assertEqual(report["review_type"], "internal source security control evidence scan")
        self.assertTrue(all(area["evidence_locations"] for area in report["areas"]))
        self.assertEqual(
            security_evidence.evidence_matches(
                "apps/signer-firmware/src/services/backup/mod.rs",
                "Historical password-only wallet",
            ),
            [],
        )
        self.assertTrue(
            security_evidence.evidence_matches(
                "crates/offline-signer/src/crypto/container_framing.rs", "KASDB004"
            )
        )

    def test_authoritative_qa_owns_hardening_mutation_and_fuzz_order(self) -> None:
        alias = (ROOT / "qa/linux/run-production-hardening.sh").read_text()
        self.assertIn("authoritative make qa catalog", alias)
        self.assertIn('run-all.sh" --profile full', alias)
        self.assertNotIn("run_gate", alias)

        rows = [
            line.split("\t") for line in (ROOT / "qa/config/run_all_steps.tsv").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        ids = [row[3] for row in rows]
        self.assertLess(ids.index("integration.real-node"), ids.index("mutation.repository-security-fresh"))
        self.assertLess(ids.index("integration.funded-testnet-e2e"), ids.index("mutation.repository-security-fresh"))
        self.assertLess(ids.index("mutation.repository-security-fresh"), ids.index("mutation.repository-crypto-certification"))
        self.assertLess(ids.index("mutation.repository-crypto-certification"), ids.index("fuzz.repository-security-targets"))

        dispatch = (ROOT / "qa/linux/runner/catalog.sh").read_text()
        self.assertIn("mutation.py run --fresh", dispatch)
        self.assertIn("mutation.py crypto-check", dispatch)
        self.assertIn("run_fuzz_targets", dispatch)
        mutation_source = (ROOT / "qa/checks/security/mutation.py").read_text()
        mutation_runner = (ROOT / "qa/checks/security/mutation_runner.py").read_text()
        self.assertIn("Mutation source and workspace tests are unchanged", mutation_runner)
        self.assertIn("Context-aware mutation reuse", mutation_runner)
        self.assertIn("_execute_mutation_run", mutation_source)
        makefile = (ROOT / "Makefile").read_text()
        helper = (ROOT / "scripts/common/lib/make_tasks.py").read_text()
        self.assertNotIn("mutation-certify:", makefile)
        self.assertNotIn('platform("production-hardening")', helper)


    def test_sole_failed_real_node_gate_can_be_completed_without_rewriting_original_results(self) -> None:
        completion = (ROOT / "qa/checks/security/complete_hardening.py").read_text()
        packager = (ROOT / "qa/checks/security/package_artifacts.py").read_text()
        real_node = (ROOT / "qa/linux/run-real-node-integration.sh").read_text()
        self.assertIn('failed != [REAL_NODE_GATE]', completion)
        self.assertIn('mutation_scope_sha256()', completion)
        self.assertIn('workspace_test_sha256()', completion)
        self.assertIn('base_gate_results_sha256', completion)
        self.assertIn('supplemental-sole-failed-gate-rerun', completion)
        self.assertNotIn('gates_path.write_text', completion)
        self.assertIn('valid_completion(current_run)', packager)
        self.assertIn('kassigner-production-hardening.zip', completion)
        self.assertIn('KASSIGNER_SECURITY_RUN_DIR', real_node)

    def test_compact_kspt_fuzzer_handles_empty_input_without_blind_slice(self) -> None:
        source = (ROOT / "qa/fuzz/compact_kspt_roundtrip.rs").read_text()
        self.assertIn('data.get(13..).unwrap_or_default()', source)
        self.assertNotIn('&data[13..13 + payload_len]', source)
        self.assertTrue((ROOT / "qa/fuzz/seeds/compact_kspt_roundtrip/empty").is_file())

    def test_fuzz_runner_persists_results_even_when_a_target_fails(self) -> None:
        source = (ROOT / "qa/linux/run-security-fuzz.sh").read_text()
        self.assertIn('set -uo pipefail', source)
        self.assertNotIn('set -euo pipefail', source)
        self.assertIn('statuses.tsv', source)
        self.assertIn('fuzz_results.py', source)
        self.assertIn('PIPESTATUS[0]', source)

    def test_mutation_and_fuzz_versions_are_pinned(self) -> None:
        policy = json.loads((ROOT / "qa/checks/security/policy.json").read_text())
        mutation_policy = mutation.load_policy()
        self.assertEqual(
            mutation_policy["cargo_mutants_version"],
            PINS["KASSIGNER_CARGO_MUTANTS_VERSION"],
        )
        self.assertEqual(mutation_policy["toolchain"], PINS["KASSIGNER_STABLE_RUST"])
        self.assertNotIn("cargo_mutants_version", policy["mutation"])
        self.assertNotIn("toolchain", policy["mutation"])
        for duplicated in ("cargo_fuzz_version", "installer_toolchain", "execution_toolchain", "targets"):
            self.assertNotIn(duplicated, policy["fuzz"])
        self.assertEqual(policy["mutation"]["minimum_score_percent"], 92.0)
        self.assertEqual(policy["mutation"]["output_directory"], "target/qa/mutation")
        self.assertTrue(policy["mutation"]["iterate"])
        self.assertTrue(policy["mutation"]["reuse_unchanged_results"])
        self.assertEqual(policy["crypto_mutation_domain"]["minimum_score_percent"], 100.0)
        self.assertEqual(policy["crypto_mutation_domain"]["maximum_timeouts"], 0)
        self.assertEqual(policy["crypto_mutation_domain"]["equivalent_mutants"], [])
        self.assertTrue(policy["crypto_mutation_domain"]["scope_statement"].startswith("Host-testable"))
        self.assertTrue(policy["crypto_mutation_domain"]["scope_limitations"])
        mutants_config = (ROOT / ".cargo/mutants.toml").read_text()
        self.assertIn('output = "target/qa/mutation"', mutants_config)
        mutation_support = (ROOT / "qa/checks/security/mutation_support.py").read_text()
        self.assertIn('reconcile_root_lock(toolchain)', mutation_support)
        self.assertIn('CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS', mutation_support)
        self.assertIn('_cargo_metadata(toolchain, "--offline")', mutation_support)
        self.assertIn('_cargo_metadata(toolchain, "--locked")', mutation_support)
        self.assertIn('lockfile.write_bytes(original)', mutation_support)
        targets = registered_targets()
        self.assertEqual(len(targets), 10)

        manifest = (ROOT / "qa/fuzz/Cargo.toml").read_text()
        self.assertIn('libfuzzer-sys = "=0.4.13"', manifest)
        for target in targets:
            corpus = ROOT / "qa/fuzz/seeds" / target
            self.assertTrue(corpus.is_dir(), target)
            self.assertGreaterEqual(len(list(corpus.iterdir())), 3, target)

    def test_mutation_reconciles_stale_root_lock_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\n")
            lockfile = root / "Cargo.lock"
            lockfile.write_bytes(b"stale-lock")

            def metadata(_toolchain: str, *arguments: str):
                if arguments == ("--locked",) and lockfile.read_bytes() == b"stale-lock":
                    return type("Result", (), {"returncode": 1, "stderr": "stale"})()
                if arguments == ("--offline",):
                    lockfile.write_bytes(b"reconciled-lock")
                return type("Result", (), {"returncode": 0, "stderr": ""})()

            with mock.patch.object(mutation_support, "ROOT", root), mock.patch.object(
                mutation_support, "_cargo_metadata", side_effect=metadata
            ):
                self.assertEqual(mutation_support.reconcile_root_lock("1.95.0"), 0)
            self.assertEqual(lockfile.read_bytes(), b"reconciled-lock")

    def test_mutation_restores_lock_when_reconciliation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text("[workspace]\n")
            lockfile = root / "Cargo.lock"
            lockfile.write_bytes(b"original-lock")

            calls = 0

            def metadata(_toolchain: str, *arguments: str):
                nonlocal calls
                calls += 1
                if arguments != ("--locked",):
                    lockfile.write_bytes(f"failed-{calls}".encode())
                return type("Result", (), {"returncode": 1, "stderr": "refresh failed"})()

            with mock.patch.object(mutation_support, "ROOT", root), mock.patch.object(
                mutation_support, "_cargo_metadata", side_effect=metadata
            ):
                self.assertEqual(mutation_support.reconcile_root_lock("1.95.0"), 2)
            self.assertEqual(lockfile.read_bytes(), b"original-lock")

    def test_cargo_fuzz_is_built_with_stable_and_executed_with_nightly(self) -> None:
        standalone = (ROOT / "qa/linux/run-security-fuzz.sh").read_text()
        commands = (ROOT / "qa/linux/runner/commands.sh").read_text()

        for source in (standalone, commands):
            self.assertIn('install cargo-fuzz', source)
            self.assertNotIn(PINS["KASSIGNER_STABLE_RUST"], source)
            self.assertNotIn(PINS["KASSIGNER_BRANCH_RUST"], source)

        self.assertIn('INSTALLER_TOOLCHAIN="$KASSIGNER_STABLE_RUST"', standalone)
        self.assertIn('EXECUTION_TOOLCHAIN="$KASSIGNER_BRANCH_RUST"', standalone)
        self.assertIn(
            'rustup run "$INSTALLER_TOOLCHAIN" cargo install cargo-fuzz', standalone
        )
        self.assertIn(
            'rustup run "$EXECUTION_TOOLCHAIN" cargo fuzz run "$target"', standalone
        )
        self.assertIn(
            'rustup run "$installer_toolchain" cargo install cargo-fuzz', commands
        )
        self.assertIn(
            'rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz run "$target"', commands
        )


if __name__ == "__main__":
    unittest.main()
