#!/usr/bin/env python3
"""Run the consolidated CRAP report, complexity, and testability checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
CHECK_DIR = ROOT / "qa/checks/quality/crap"
POLICY_PATH = CHECK_DIR / "policy.json"
RATCHET_PATH = ROOT / "qa/contracts/quality/crap_ratchets.json"
GENERATED_REPORT_PATH = ROOT / "target/qa/crap/current.json"
sys.path.insert(0, str(CHECK_DIR))

from firmware_testability import check_firmware_policy  # noqa: E402
from health import audit_health, parse_lcov  # noqa: E402
from report import (  # noqa: E402
    apply_coverage_unavailable_source_policy,
    baseline_document,
    classify_path,
    parse_report,
)
from source_complexity import check_source_policy  # noqa: E402
from regression import (  # noqa: E402
    compare_coverage_manifests,
    compare_health_summaries,
    compare_reports,
)


def fail(errors: list[str]) -> int:
    for error in errors:
        print(f"ERROR: {error}")
    return 1


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} cannot be read: {path}: {error}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return document


def validate_reference(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema_version") != 1:
        return ["reference report uses an unsupported schema"]

    source = document.get("source")
    summary = document.get("summary")
    functions = document.get("functions")
    if not isinstance(source, dict) or not isinstance(source.get("report_sha256"), str):
        errors.append("reference report source identity is incomplete")
    if not isinstance(summary, dict) or not isinstance(functions, list) or not functions:
        errors.append("reference report is incomplete")
        return errors

    identities: set[tuple[str, int | None, str]] = set()
    counts = {
        scope: {"functions": 0, "fail": 0, "warning": 0, "pass": 0}
        for scope in ("production", "tests", "external", "tools")
    }
    for entry in functions:
        if not isinstance(entry, dict):
            errors.append("reference report contains an invalid function record")
            continue
        path = entry.get("path")
        scope = entry.get("scope")
        status = entry.get("status")
        function = entry.get("function")
        line = entry.get("line")
        if not isinstance(path, str) or not isinstance(function, str):
            errors.append("reference report contains an invalid function identity")
            continue
        try:
            expected_scope = classify_path(path)
        except ValueError as error:
            errors.append(str(error))
            continue
        if scope != expected_scope:
            errors.append(
                f"reference report scope drift: {path} is classified as {scope}"
            )
            continue
        if status not in {"fail", "warning", "pass"}:
            errors.append(f"reference report has an invalid status: {path}::{function}")
            continue
        identity = (path, line if isinstance(line, int) else None, function)
        if identity in identities:
            errors.append(f"reference report contains a duplicate identity: {identity}")
            continue
        identities.add(identity)
        counts[scope]["functions"] += 1
        counts[scope][status] += 1

    summary_all = summary.get("all", {})
    summary_scopes = summary.get("scopes", {})
    if summary_all.get("functions") != len(functions):
        errors.append("reference report total does not match its function records")
    for scope, actual in counts.items():
        expected = summary_scopes.get(scope, {})
        expected_status = expected.get("status", {})
        if expected.get("functions") != actual["functions"]:
            errors.append(f"reference report {scope} function count is inconsistent")
        for status in ("fail", "warning", "pass"):
            if expected_status.get(status) != actual[status]:
                errors.append(
                    f"reference report {scope} {status} count is inconsistent"
                )
    return errors


def load_exact_report(
    path: Path,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        document = load_json(path, "CRAP report")
        if document.get("schema_version") == 1:
            return document
    report = parse_report(path)
    if policy is not None:
        report = apply_coverage_unavailable_source_policy(report, policy)
    return baseline_document(report, path.name)


def validate_exact_report(
    document: dict[str, Any],
    report_policy: dict[str, Any],
    strict: bool,
) -> tuple[list[str], dict[str, int]]:
    errors = validate_reference(document)
    functions = document.get("functions")
    if not isinstance(functions, list):
        return [*errors, "CRAP report has no function records"], {}

    threshold = document.get("source", {}).get("threshold")
    expected_threshold = report_policy.get("threshold")
    if threshold != expected_threshold:
        errors.append(
            f"CRAP threshold changed: {threshold!r} != {expected_threshold!r}"
        )

    production = [
        entry for entry in functions
        if isinstance(entry, dict) and entry.get("scope") == "production"
    ]
    failures = sum(entry.get("status") == "fail" for entry in production)
    warnings = sum(entry.get("status") == "warning" for entry in production)
    maximum_failures = report_policy.get("maximum_production_failures")
    maximum_warnings = report_policy.get("maximum_production_warnings")
    if not isinstance(maximum_failures, int) or not isinstance(maximum_warnings, int):
        errors.append("CRAP report limits are incomplete")
    elif strict:
        if failures > maximum_failures:
            errors.append(
                f"production CRAP failures remain: {failures} > {maximum_failures}"
            )
        if warnings > maximum_warnings:
            warning_entries = [
                entry for entry in production if entry.get("status") == "warning"
            ]
            detail = "; ".join(
                f"{entry.get('path')}:{entry.get('line')}::{entry.get('function')} "
                f"CRAP={entry.get('crap')} coverage={entry.get('coverage_percent')}%"
                for entry in warning_entries
            )
            errors.append(
                f"production CRAP warnings regressed: {warnings} > {maximum_warnings}"
                + (f" [{detail}]" if detail else "")
            )
    return errors, {
        "production_functions": len(production),
        "production_failures": failures,
        "production_warnings": warnings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="enforce CRAP scope, source complexity, and firmware testability"
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="fresh full CRAP report (.txt) or classified JSON",
    )
    parser.add_argument(
        "--strict-report",
        action="store_true",
        help="enforce the configured production failure and warning limits",
    )
    parser.add_argument(
        "--previous-report",
        type=Path,
        help="previous classified snapshot used to reject new production failures",
    )
    parser.add_argument(
        "--run-manifest",
        type=Path,
        help="fresh coverage run manifest containing aggregate coverage totals",
    )
    parser.add_argument(
        "--lcov",
        type=Path,
        help="fresh LCOV trace used for complete health-criteria measurement",
    )
    parser.add_argument(
        "--health-output",
        type=Path,
        help="write a machine-readable complete health audit",
    )
    parser.add_argument(
        "--browser-recovery-coverage",
        type=Path,
        help="persisted KasSee browser recovery coverage summary",
    )
    parser.add_argument(
        "--web-runtime-coverage",
        type=Path,
        help="persisted all-module KasSee runtime V8 coverage summary",
    )
    parser.add_argument(
        "--previous-run-manifest",
        type=Path,
        help="previous coverage run manifest used to verify comparable instrumentation",
    )
    parser.add_argument(
        "--previous-health-summary",
        type=Path,
        help="previous classified health summary used to ratchet host-production coverage",
    )
    parser.add_argument(
        "--ratchet-contract",
        type=Path,
        default=RATCHET_PATH,
        help="compact committed host-coverage ratchet contract",
    )
    parser.add_argument(
        "--ignore-generated-report",
        action="store_true",
        help="run source/testability policy without loading target/qa/crap/current.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        policy = load_json(POLICY_PATH, "CRAP policy")
        ratchet = load_json(arguments.ratchet_contract, "CRAP ratchet contract")
    except ValueError as error:
        return fail([str(error)])

    if policy.get("schema_version") != 1:
        return fail(["CRAP policy uses an unsupported schema"])
    if ratchet.get("schema_version") != 1:
        return fail(["CRAP ratchet contract uses an unsupported schema"])

    errors: list[str] = []
    profile = ratchet.get("coverage_profile")
    floors = ratchet.get("host_production_minimum_percent")
    if not isinstance(profile, dict) or not isinstance(floors, dict):
        errors.append("CRAP ratchet contract is incomplete")
    else:
        for metric in ("lines", "functions", "branches"):
            value = floors.get(metric)
            if not isinstance(value, (int, float)) or value < 0 or value > 100:
                errors.append(f"CRAP ratchet contract has invalid {metric} floor")

    source_errors, source_stats = check_source_policy(
        ROOT,
        policy.get("source_complexity", {}),
    )
    firmware_errors, firmware_stats = check_firmware_policy(
        ROOT,
        policy.get("firmware_testability", {}),
    )
    errors.extend(source_errors)
    errors.extend(firmware_errors)

    exact_stats: dict[str, int] | None = None
    regression_stats = None
    health_document: dict[str, Any] | None = None
    report_path = arguments.report
    if (
        report_path is None
        and not arguments.ignore_generated_report
        and GENERATED_REPORT_PATH.is_file()
    ):
        report_path = GENERATED_REPORT_PATH
    if report_path is not None:
        if not report_path.is_file():
            errors.append(f"CRAP report does not exist: {report_path}")
        else:
            try:
                exact = load_exact_report(report_path, policy)
            except (ValueError, OSError) as error:
                errors.append(str(error))
            else:
                exact_errors, exact_stats = validate_exact_report(
                    exact,
                    policy.get("report", {}),
                    arguments.strict_report,
                )
                errors.extend(exact_errors)
                if arguments.previous_report is not None:
                    try:
                        previous = load_exact_report(arguments.previous_report, policy)
                    except (ValueError, OSError) as error:
                        errors.append(str(error))
                    else:
                        regression_errors, regression_stats = compare_reports(
                            previous,
                            exact,
                            policy.get("regression", {}),
                        )
                        errors.extend(regression_errors)

    current_run: dict[str, Any] | None = None
    previous_run: dict[str, Any] | None = None
    if arguments.run_manifest is not None and arguments.previous_run_manifest is not None:
        try:
            current_run = load_json(arguments.run_manifest, "coverage run manifest")
            previous_run = load_json(
                arguments.previous_run_manifest,
                "previous coverage run manifest",
            )
        except ValueError as error:
            errors.append(str(error))
        else:
            errors.extend(
                compare_coverage_manifests(
                    previous_run,
                    current_run,
                    policy.get("regression", {}),
                )
            )

    if report_path is not None and arguments.lcov is not None and arguments.run_manifest is not None:
        try:
            health_report = load_exact_report(report_path, policy)
            health_run = load_json(arguments.run_manifest, "coverage run manifest")
            health_records = parse_lcov(arguments.lcov)
        except (ValueError, OSError) as error:
            errors.append(str(error))
        else:
            supplemental_coverage: dict[str, dict[str, Any]] = {}
            if arguments.browser_recovery_coverage is not None:
                try:
                    supplemental_coverage["browser_recovery"] = load_json(
                        arguments.browser_recovery_coverage,
                        "browser recovery coverage",
                    )
                except ValueError as error:
                    errors.append(str(error))
            if arguments.web_runtime_coverage is not None:
                try:
                    supplemental_coverage["web_runtime"] = load_json(
                        arguments.web_runtime_coverage,
                        "web runtime coverage",
                    )
                except ValueError as error:
                    errors.append(str(error))
            health_errors, health_document = audit_health(
                health_report,
                health_records,
                health_run,
                policy,
                supplemental_coverage,
            )
            if isinstance(profile, dict):
                current_profile = health_run.get("coverage_profile")
                if current_profile != profile:
                    errors.append(
                        "fresh coverage profile does not match committed CRAP ratchet: "
                        f"{current_profile!r} != {profile!r}"
                    )
            if isinstance(floors, dict):
                tolerance = policy.get("regression", {}).get(
                    "coverage_drop_tolerance_percent", 0.05
                )
                if not isinstance(tolerance, (int, float)) or tolerance < 0:
                    tolerance = 0.05
                host_metrics = health_document.get("host_metrics", {})
                for metric in ("lines", "functions", "branches"):
                    observed = host_metrics.get(metric, {})
                    actual = observed.get("percent") if isinstance(observed, dict) else None
                    floor = floors.get(metric)
                    if (
                        isinstance(actual, (int, float))
                        and isinstance(floor, (int, float))
                        and actual + tolerance < floor
                    ):
                        errors.append(
                            f"host production {metric} coverage regressed: "
                            f"{actual:.2f}% < {floor:.2f}% "
                            f"(tolerance {tolerance:.2f}%)"
                        )
            if (
                arguments.previous_health_summary is not None
                and current_run is not None
                and previous_run is not None
            ):
                try:
                    previous_health = load_json(
                        arguments.previous_health_summary,
                        "previous health summary",
                    )
                except ValueError as error:
                    errors.append(str(error))
                else:
                    errors.extend(
                        compare_health_summaries(
                            previous_health,
                            health_document,
                            previous_run,
                            current_run,
                            policy.get("regression", {}),
                        )
                    )
            if arguments.strict_report:
                errors.extend(
                    error
                    for error in health_errors
                    if not error.startswith("production CRAP failures remain:")
                    and not error.startswith("production warning target is not met:")
                )
            if arguments.health_output is not None:
                arguments.health_output.parent.mkdir(parents=True, exist_ok=True)
                arguments.health_output.write_text(
                    json.dumps(health_document, indent=2, sort_keys=True) + "\n"
                )

    if errors:
        return fail(errors)

    message = (
        "PASS: CRAP quality check "
        f"({source_stats.get('production_functions', 0)} production functions; "
        f"max source decisions {source_stats.get('maximum_decisions', 0)}; "
        f"{source_stats.get('warning_functions', 0)} source warnings; "
        f"{firmware_stats.get('host_tests', 0)} firmware host tests)"
    )
    if exact_stats is not None:
        mode = "strict" if arguments.strict_report else "debt-aware"
        message += (
            f"; fresh report ({mode}): "
            f"{exact_stats['production_failures']} failures, "
            f"{exact_stats['production_warnings']} warnings"
        )
    if regression_stats is not None:
        message += (
            "; regression gate: "
            f"{regression_stats.new_failures} new failures, "
            f"{regression_stats.new_warnings} new warnings, "
            f"{regression_stats.measured_to_unavailable} coverage losses"
        )
    if health_document is not None:
        criteria = health_document.get("criteria", {})
        host = health_document.get("host_metrics", {})
        message += (
            "; complete health audit: "
            f"host lines {host.get('lines', {}).get('percent', 0.0):.2f}%, "
            f"host functions {host.get('functions', {}).get('percent', 0.0):.2f}%, "
            f"{criteria.get('pure_firmware_models', {}).get('actual', 0)}/"
            f"{criteria.get('pure_firmware_models', {}).get('target', 0)} "
            "firmware models measured, "
            f"{criteria.get('board_adapters_above_cc_limit', {}).get('actual', 0)} "
            "board adapters above CC 4"
        )
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
