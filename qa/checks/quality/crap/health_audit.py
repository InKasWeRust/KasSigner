"""Strict healthy-codebase audit calculations."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

CHECK_DIR = Path(__file__).resolve().parent
if str(CHECK_DIR) not in sys.path:
    sys.path.insert(0, str(CHECK_DIR))
from lcov_metrics import aggregate as _aggregate  # noqa: E402
from lcov_metrics import matches as _matches  # noqa: E402
from report import classify_path  # noqa: E402

def _production_entries(report: dict[str, Any]) -> list[dict[str, Any]]:
    functions = report.get("functions")
    if not isinstance(functions, list):
        return []
    return [
        entry
        for entry in functions
        if isinstance(entry, dict) and entry.get("scope") == "production"
    ]


def _criterion(actual: float | int, target: float | int, met: bool) -> dict[str, Any]:
    return {"actual": actual, "target": target, "met": met}


def _supplemental_domain_result(
    name: str,
    document: dict[str, Any] | None,
    minimum_percent: float,
) -> dict[str, Any]:
    coverage = document.get("coverage") if isinstance(document, dict) else None
    lines = coverage.get("lines") if isinstance(coverage, dict) else None
    functions = coverage.get("functions") if isinstance(coverage, dict) else None
    branches = coverage.get("branches") if isinstance(coverage, dict) else None
    line_percent = float(lines.get("percent", 0.0)) if isinstance(lines, dict) else 0.0
    function_percent = (
        float(functions.get("percent", 0.0)) if isinstance(functions, dict) else 0.0
    )
    branch_percent = (
        float(branches.get("percent", 0.0)) if isinstance(branches, dict) else 0.0
    )
    available = bool(
        isinstance(lines, dict)
        and lines.get("available")
        and isinstance(functions, dict)
        and functions.get("available")
        and isinstance(branches, dict)
        and branches.get("available")
    )
    files = document.get("files") if isinstance(document, dict) else None
    missing = files.get("missing", []) if isinstance(files, dict) else []
    complete = isinstance(missing, list) and not missing
    return {
        "name": name,
        "available": available,
        "complete": complete,
        "line_percent": line_percent,
        "function_percent": function_percent,
        "branch_percent": branch_percent,
        "files": files if isinstance(files, dict) else {},
        "met": available
        and complete
        and line_percent >= minimum_percent
        and function_percent >= minimum_percent
        and branch_percent >= minimum_percent,
    }


def audit_health(
    report: dict[str, Any],
    lcov_records: dict[str, dict[str, dict[str, int | float | bool]]],
    run_manifest: dict[str, Any],
    policy: dict[str, Any],
    supplemental_coverage: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Return strict-health errors and a machine-readable audit document."""
    health = policy.get("health")
    firmware = policy.get("firmware_testability")
    if not isinstance(health, dict) or not isinstance(firmware, dict):
        return ["health policy is incomplete"], {}

    production = _production_entries(report)
    failures = sum(entry.get("status") == "fail" for entry in production)
    warnings = sum(entry.get("status") == "warning" for entry in production)
    raw_failures = sum(
        entry.get("raw_status", entry.get("status")) == "fail"
        for entry in production
    )
    raw_warnings = sum(
        entry.get("raw_status", entry.get("status")) == "warning"
        for entry in production
    )
    source_assessed = sum(
        entry.get("assessment_basis") == "source_complexity"
        for entry in production
    )
    function_count = len(production)
    warning_percent = round(warnings * 100.0 / function_count, 4) if function_count else 0.0

    max_failures = health.get("maximum_production_failures")
    max_warnings = health.get("maximum_production_warnings")
    max_warning_percent = health.get("maximum_production_warning_percent")
    minimum_host_line = health.get("minimum_host_line_coverage_percent")
    minimum_host_function = health.get("minimum_host_function_coverage_percent")
    minimum_host_branch = health.get("minimum_host_branch_coverage_percent")
    minimum_critical = health.get("minimum_critical_domain_coverage_percent")
    minimum_web_mapping = health.get("minimum_web_runtime_mapping_percent")
    max_adapter_cc = health.get("maximum_board_adapter_cc")
    host_roots = health.get("host_production_roots")
    adapter_roots = health.get("board_adapter_roots")
    critical_domains = health.get("critical_domains")
    require_branches = health.get("require_branch_coverage")
    required_values = (
        max_failures,
        max_warnings,
        max_warning_percent,
        minimum_host_line,
        minimum_host_function,
        minimum_host_branch,
        minimum_critical,
        minimum_web_mapping,
        max_adapter_cc,
    )
    if not all(isinstance(value, (int, float)) for value in required_values):
        return ["health numeric limits are incomplete"], {}
    if not isinstance(host_roots, list) or not all(isinstance(root, str) for root in host_roots):
        return ["host-production roots are incomplete"], {}
    if not isinstance(adapter_roots, list) or not all(
        isinstance(root, str) for root in adapter_roots
    ):
        return ["board-adapter roots are incomplete"], {}
    if not isinstance(critical_domains, dict):
        return ["critical-domain policy is incomplete"], {}

    host_paths = sorted(
        path
        for path in lcov_records
        if any(path.startswith(root) for root in host_roots)
        and classify_path(path) == "production"
    )
    host_metrics = _aggregate(lcov_records, host_paths)

    supplemental_coverage = supplemental_coverage or {}
    domain_results: dict[str, Any] = {}
    for name, domain in critical_domains.items():
        if not isinstance(name, str) or not isinstance(domain, dict):
            continue
        patterns = domain.get("paths")
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            continue
        paths = sorted(
            path
            for path in lcov_records
            if classify_path(path) == "production" and _matches(path, patterns)
        )
        metrics = _aggregate(lcov_records, paths)
        line_percent = float(metrics["lines"]["percent"])
        function_percent = float(metrics["functions"]["percent"])
        branch_metrics = metrics["branches"]
        branch_percent = float(branch_metrics["percent"])
        branch_floor = domain.get("minimum_branch_coverage_percent")
        branch_target = domain.get("target_branch_coverage_percent", 90.0)
        if not isinstance(branch_floor, (int, float)) or not isinstance(
            branch_target, (int, float)
        ):
            return [f"critical-domain branch policy is incomplete for {name}"], {}
        branch_met = (
            bool(branch_metrics["available"])
            and int(branch_metrics["found"]) > 0
            and branch_percent >= float(branch_floor)
        )
        rust_met = (
            bool(paths)
            and line_percent >= float(minimum_critical)
            and function_percent >= float(minimum_critical)
            and branch_met
        )
        supplemental_key = domain.get("supplemental_coverage")
        supplemental_result = None
        supplemental_met = True
        if isinstance(supplemental_key, str):
            supplemental_document = supplemental_coverage.get(supplemental_key)
            supplemental_result = _supplemental_domain_result(
                supplemental_key, supplemental_document, float(minimum_critical)
            )
            supplemental_met = bool(supplemental_result["met"])
        domain_results[name] = {
            "label": domain.get("label", name),
            "files": len(paths),
            "metrics": metrics,
            "branch_gate": {
                "actual": branch_percent,
                "minimum": float(branch_floor),
                "target": float(branch_target),
                "met": branch_met,
            },
            "rust_met": rust_met,
            "supplemental": supplemental_result,
            "met": rust_met and supplemental_met,
        }

    model_paths = firmware.get("model_paths")
    if not isinstance(model_paths, list):
        model_paths = []
    required_models = [path for path in model_paths if isinstance(path, str)]
    missing_models = [
        path
        for path in required_models
        if path not in lcov_records
        or not (
            bool(lcov_records[path]["lines"]["available"])
            or bool(lcov_records[path]["functions"]["available"])
        )
    ]

    adapters = [
        entry
        for entry in production
        if isinstance(entry.get("path"), str)
        and any(entry["path"].startswith(root) for root in adapter_roots)
    ]
    adapter_offenders = [
        {
            "path": entry.get("path"),
            "line": entry.get("line"),
            "function": entry.get("function"),
            "cc": entry.get("complexity"),
        }
        for entry in adapters
        if isinstance(entry.get("complexity"), int)
        and entry["complexity"] > int(max_adapter_cc)
    ]
    adapter_offenders.sort(key=lambda entry: (-int(entry["cc"]), str(entry["path"])))

    coverage = run_manifest.get("coverage")
    branch = coverage.get("branches") if isinstance(coverage, dict) else None
    branch_requested = bool(run_manifest.get("branch_coverage_requested"))
    branch_available = bool(branch.get("available")) if isinstance(branch, dict) else False
    branch_found = int(branch.get("found", 0)) if isinstance(branch, dict) else 0
    branch_hit = int(branch.get("hit", 0)) if isinstance(branch, dict) else 0
    branch_percent = float(branch.get("percent", 0.0)) if isinstance(branch, dict) else 0.0
    branch_met = (not bool(require_branches)) or (
        branch_requested and branch_available and branch_found > 0
    )

    web_runtime = supplemental_coverage.get("web_runtime", {}) if supplemental_coverage else {}
    web_files = web_runtime.get("files") if isinstance(web_runtime, dict) else None
    web_mapping = float(web_files.get("mapping_percent", 0.0)) if isinstance(web_files, dict) else 0.0
    web_tests_passed = bool(web_runtime.get("tests_passed")) if isinstance(web_runtime, dict) else False
    web_mapping_met = web_tests_passed and web_mapping >= float(minimum_web_mapping)

    criteria = {
        "web_runtime_trace_mapping": {
            "actual": web_mapping,
            "target": float(minimum_web_mapping),
            "tests_passed": web_tests_passed,
            "met": web_mapping_met,
        },
        "production_crap_failures": _criterion(
            failures, int(max_failures), failures <= int(max_failures)
        ),
        "production_warnings": {
            "actual": warnings,
            "target": int(max_warnings),
            "percent": warning_percent,
            "maximum_percent": float(max_warning_percent),
            "met": warnings <= int(max_warnings)
            and warning_percent <= float(max_warning_percent),
        },
        "host_line_coverage": _criterion(
            float(host_metrics["lines"]["percent"]),
            float(minimum_host_line),
            bool(host_metrics["lines"]["available"])
            and float(host_metrics["lines"]["percent"]) >= float(minimum_host_line),
        ),
        "host_function_coverage": _criterion(
            float(host_metrics["functions"]["percent"]),
            float(minimum_host_function),
            bool(host_metrics["functions"]["available"])
            and float(host_metrics["functions"]["percent"])
            >= float(minimum_host_function),
        ),
        "host_branch_coverage": _criterion(
            float(host_metrics["branches"]["percent"]),
            float(minimum_host_branch),
            branch_requested
            and bool(host_metrics["branches"]["available"])
            and int(host_metrics["branches"]["found"]) > 0
            and float(host_metrics["branches"]["percent"])
            >= float(minimum_host_branch),
        ),
        "pure_firmware_models": {
            "actual": len(required_models) - len(missing_models),
            "target": len(required_models),
            "missing": missing_models,
            "met": not missing_models,
        },
        "board_adapters_above_cc_limit": {
            "actual": len(adapter_offenders),
            "target": 0,
            "maximum_cc": max(
                (int(entry.get("complexity", 0)) for entry in adapters), default=0
            ),
            "cc_limit": int(max_adapter_cc),
            "offenders": adapter_offenders,
            "met": not adapter_offenders,
        },
        "branch_coverage": {
            "requested": branch_requested,
            "available": branch_available,
            "found": branch_found,
            "hit": branch_hit,
            "percent": branch_percent,
            "required": bool(require_branches),
            "met": branch_met,
        },
    }

    errors: list[str] = []
    if not criteria["production_crap_failures"]["met"]:
        errors.append(
            f"production CRAP failures remain: {failures} > {int(max_failures)}"
        )
    if not criteria["production_warnings"]["met"]:
        errors.append(
            "production warning target is not met: "
            f"{warnings} ({warning_percent:.2f}%) > "
            f"{int(max_warnings)} or {float(max_warning_percent):.2f}%"
        )
    if not criteria["host_line_coverage"]["met"]:
        errors.append(
            "host production line coverage is below target: "
            f"{float(host_metrics['lines']['percent']):.2f}% < "
            f"{float(minimum_host_line):.2f}%"
        )
    if not criteria["host_function_coverage"]["met"]:
        errors.append(
            "host production function coverage is below target: "
            f"{float(host_metrics['functions']['percent']):.2f}% < "
            f"{float(minimum_host_function):.2f}%"
        )
    if not criteria["host_branch_coverage"]["met"]:
        errors.append(
            "host production branch coverage is below target: "
            f"{float(host_metrics['branches']['percent']):.2f}% < "
            f"{float(minimum_host_branch):.2f}%"
        )
    for name, domain in domain_results.items():
        if not domain["met"]:
            metrics = domain["metrics"]
            supplemental = domain.get("supplemental")
            branch_gate = domain.get("branch_gate", {})
            detail = (
                f"Rust lines {float(metrics['lines']['percent']):.2f}%, "
                f"Rust functions {float(metrics['functions']['percent']):.2f}%, "
                f"Rust branches {float(metrics['branches']['percent']):.2f}% "
                f"(floor {float(branch_gate.get('minimum', 0.0)):.2f}%, "
                f"target {float(branch_gate.get('target', 90.0)):.2f}%)"
            )
            if isinstance(supplemental, dict):
                detail += (
                    f"; {supplemental.get('name')} lines "
                    f"{float(supplemental.get('line_percent', 0.0)):.2f}%, "
                    f"functions {float(supplemental.get('function_percent', 0.0)):.2f}%"
                )
                if not supplemental.get("complete"):
                    detail += "; source inventory incomplete"
            errors.append(
                f"critical-domain coverage is below target for {name}: "
                f"{detail} < {float(minimum_critical):.2f}%"
            )
    if not web_mapping_met:
        errors.append(
            "web runtime trace mapping is incomplete: "
            f"{web_mapping:.2f}% < {float(minimum_web_mapping):.2f}% or integration tests failed"
        )
    if missing_models:
        errors.append(
            "pure firmware coverage is unavailable for: " + ", ".join(missing_models)
        )
    if adapter_offenders:
        errors.append(
            "board adapter complexity exceeds the limit: "
            f"{len(adapter_offenders)} function(s) above CC {int(max_adapter_cc)}"
        )
    if not branch_met:
        errors.append("branch coverage was not requested, recorded, and persisted")

    document = {
        "schema_version": 1,
        "healthy": not errors,
        "production_functions": function_count,
        "production_assessment": {
            "crap_functions": function_count - source_assessed,
            "source_complexity_functions": source_assessed,
            "raw_pessimistic_failures": raw_failures,
            "raw_pessimistic_warnings": raw_warnings,
            "effective_failures": failures,
            "effective_warnings": warnings,
        },
        "host_production_files": len(host_paths),
        "host_metrics": host_metrics,
        "criteria": criteria,
        "critical_domains": domain_results,
        "supplemental_coverage": supplemental_coverage or {},
    }
    return errors, document


