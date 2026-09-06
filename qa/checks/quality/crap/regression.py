#!/usr/bin/env python3
"""Compare classified CRAP snapshots without treating existing debt as new debt."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

_STATUS_RANK = {"pass": 0, "warning": 1, "fail": 2}
_MEASURED_STATES = {"measured", "zero"}


@dataclass(frozen=True)
class RegressionStats:
    previous_failures: int
    current_failures: int
    new_failures: int
    new_warnings: int
    measured_to_unavailable: int


def _production(document: dict[str, Any]) -> list[dict[str, Any]]:
    functions = document.get("functions", [])
    if not isinstance(functions, list):
        return []
    return [
        entry
        for entry in functions
        if isinstance(entry, dict) and entry.get("scope") == "production"
    ]


def _groups(
    entries: Iterable[dict[str, Any]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        path = entry.get("path")
        function = entry.get("function")
        if isinstance(path, str) and isinstance(function, str):
            grouped[(path, function)].append(entry)
    for values in grouped.values():
        values.sort(key=lambda item: item.get("line") if isinstance(item.get("line"), int) else -1)
    return grouped


def _match_entries(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any] | None, dict[str, Any]]], list[dict[str, Any]]]:
    previous_groups = _groups(previous)
    current_groups = _groups(current)
    matches: list[tuple[dict[str, Any] | None, dict[str, Any]]] = []
    unmatched_previous: list[dict[str, Any]] = []

    for identity, current_values in current_groups.items():
        previous_values = previous_groups.pop(identity, [])
        if len(current_values) == 1 and len(previous_values) == 1:
            matches.append((previous_values[0], current_values[0]))
            continue

        previous_by_line = {
            entry.get("line"): entry
            for entry in previous_values
            if isinstance(entry.get("line"), int)
        }
        consumed: set[int] = set()
        for current_entry in current_values:
            line = current_entry.get("line")
            previous_entry = previous_by_line.get(line) if isinstance(line, int) else None
            if previous_entry is not None:
                consumed.add(id(previous_entry))
            matches.append((previous_entry, current_entry))
        unmatched_previous.extend(
            entry for entry in previous_values if id(entry) not in consumed
        )

    for previous_values in previous_groups.values():
        unmatched_previous.extend(previous_values)
    return matches, unmatched_previous




def _allowed_board_adapter_warning(
    entry: dict[str, Any],
    policy: dict[str, Any],
) -> bool:
    """Allow uncovered board adapters to remain warnings only within the CC <= 4 contract."""
    limit = policy.get("allowed_unavailable_board_adapter_warning_cc")
    roots = policy.get("board_adapter_roots")
    path = entry.get("path")
    complexity = entry.get("complexity")
    return (
        isinstance(limit, int)
        and isinstance(roots, list)
        and all(isinstance(root, str) for root in roots)
        and isinstance(path, str)
        and any(path.startswith(root) for root in roots)
        and entry.get("coverage_state") == "unavailable"
        and isinstance(complexity, int)
        and complexity <= limit
    )

def compare_reports(
    previous: dict[str, Any],
    current: dict[str, Any],
    policy: dict[str, Any],
) -> tuple[list[str], RegressionStats]:
    """Reject newly introduced production failures and lost coverage visibility."""

    previous_entries = _production(previous)
    current_entries = _production(current)
    matches, _ = _match_entries(previous_entries, current_entries)

    reject_new_failures = policy.get("reject_new_failures", True)
    reject_new_warnings = policy.get("reject_new_warnings", True)
    reject_coverage_loss = policy.get("reject_measured_to_unavailable", True)
    reject_failure_count_increase = policy.get("reject_failure_count_increase", True)

    errors: list[str] = []
    new_failures = 0
    new_warnings = 0
    coverage_losses = 0

    for previous_entry, current_entry in matches:
        current_status = current_entry.get("status")
        current_identity = (
            f"{current_entry.get('path')}::{current_entry.get('function')}"
            f":{current_entry.get('line')}"
        )
        if current_status == "fail" and (
            previous_entry is None or previous_entry.get("status") != "fail"
        ):
            new_failures += 1
            if reject_new_failures:
                old_status = "new function" if previous_entry is None else previous_entry.get("status")
                errors.append(
                    f"new production CRAP failure: {current_identity} "
                    f"({old_status} -> fail; CRAP {current_entry.get('crap')})"
                )
        elif current_status == "warning" and (
            previous_entry is None or previous_entry.get("status") == "pass"
        ):
            new_warnings += 1
            allowed_adapter_warning = _allowed_board_adapter_warning(
                current_entry, policy
            )
            if reject_new_warnings and not allowed_adapter_warning:
                old_status = "new function" if previous_entry is None else "pass"
                errors.append(
                    f"new production CRAP warning: {current_identity} "
                    f"({old_status} -> warning; CRAP {current_entry.get('crap')})"
                )

        if previous_entry is not None:
            previous_state = previous_entry.get("coverage_state")
            current_state = current_entry.get("coverage_state")
            if previous_state in _MEASURED_STATES and current_state == "unavailable":
                coverage_losses += 1
                if reject_coverage_loss:
                    errors.append(
                        f"production coverage became unavailable: {current_identity} "
                        f"({previous_state} -> unavailable)"
                    )

    previous_failures = sum(entry.get("status") == "fail" for entry in previous_entries)
    current_failures = sum(entry.get("status") == "fail" for entry in current_entries)
    if reject_failure_count_increase and current_failures > previous_failures:
        errors.append(
            "production CRAP failure count increased: "
            f"{current_failures} > {previous_failures}"
        )

    return errors, RegressionStats(
        previous_failures=previous_failures,
        current_failures=current_failures,
        new_failures=new_failures,
        new_warnings=new_warnings,
        measured_to_unavailable=coverage_losses,
    )


def _coverage_profiles_match(previous: dict[str, Any], current: dict[str, Any]) -> bool:
    """Only compare aggregate percentages produced by the same LLVM coverage profile."""
    previous_profile = previous.get("coverage_profile")
    current_profile = current.get("coverage_profile")
    return (
        isinstance(previous_profile, dict)
        and isinstance(current_profile, dict)
        and previous_profile == current_profile
    )


def compare_coverage_manifests(
    previous: dict[str, Any],
    current: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Reject loss of branch instrumentation across coverage runs.

    Aggregate ``run.json`` percentages include cfg(test) functions and other
    instrumentation-only control flow. They are useful evidence, but are not a
    stable production-coverage ratchet. Production host percentages are
    compared separately from classified ``health_summary.json`` documents.
    """

    del policy  # Regression tolerance applies to classified host metrics below.
    errors: list[str] = []
    old_branches = previous.get("coverage", {}).get("branches")
    new_branches = current.get("coverage", {}).get("branches")
    if isinstance(old_branches, dict) and isinstance(new_branches, dict):
        old_available = bool(old_branches.get("available"))
        new_available = bool(new_branches.get("available"))
        if old_available and not new_available:
            if bool(current.get("branch_coverage_requested")):
                errors.append("branch coverage disappeared from the fresh branch-coverage run")
            else:
                errors.append(
                    "fresh coverage did not request branch instrumentation while the "
                    "persisted baseline contains branch records; rerun the strict QA pipeline"
                )
    return errors


def compare_health_summaries(
    previous: dict[str, Any],
    current: dict[str, Any],
    previous_run: dict[str, Any],
    current_run: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Reject classified host-production coverage regressions.

    Only directly comparable LLVM profiles are ratcheted. Unlike the raw run
    manifest, ``host_metrics`` excludes tests, tools, board-only adapters and
    other non-production records before calculating percentages.
    """

    if not _coverage_profiles_match(previous_run, current_run):
        return []
    previous_metrics = previous.get("host_metrics")
    current_metrics = current.get("host_metrics")
    if not isinstance(previous_metrics, dict) or not isinstance(current_metrics, dict):
        return []

    tolerance = policy.get("coverage_drop_tolerance_percent", 0.05)
    if not isinstance(tolerance, (int, float)) or tolerance < 0:
        tolerance = 0.05

    errors: list[str] = []
    for metric in ("lines", "functions", "branches"):
        old = previous_metrics.get(metric)
        new = current_metrics.get(metric)
        if not isinstance(old, dict) or not isinstance(new, dict):
            continue
        old_percent = old.get("percent")
        new_percent = new.get("percent")
        if not isinstance(old_percent, (int, float)) or not isinstance(new_percent, (int, float)):
            continue
        if new_percent + tolerance < old_percent:
            errors.append(
                f"host production {metric} coverage regressed: "
                f"{new_percent:.2f}% < {old_percent:.2f}% "
                f"(tolerance {tolerance:.2f}%)"
            )
    return errors
