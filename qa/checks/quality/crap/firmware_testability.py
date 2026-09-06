"""Firmware model, adapter, ownership, and host-test contracts."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
CHECK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CHECK_DIR))

from source_complexity import (  # noqa: E402
    FORBIDDEN_EXCEPTIONS,
    function_decisions,
)


def _source(
    root: Path,
    relative: str,
    errors: list[str],
    label: str,
) -> str:
    path = root / relative
    if not path.is_file():
        errors.append(f"{label} is missing: {relative}")
        return ""
    return path.read_text(errors="replace")


def _check_decision_limit(
    source: str,
    relative: str,
    maximum: int,
    errors: list[str],
) -> list[int]:
    counts: list[int] = []
    for exception in FORBIDDEN_EXCEPTIONS:
        if exception in source:
            errors.append(f"complexity exception is forbidden: {relative}: {exception}")
    for record in function_decisions(source, relative):
        counts.append(record.decisions)
        if record.decisions > maximum:
            errors.append(
                f"firmware source exceeds its decision limit: "
                f"{relative}:{record.line} {record.name} "
                f"({record.decisions} > {maximum})"
            )
    return counts


def check_firmware_policy(
    root: Path,
    policy: dict[str, Any],
) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    model_maximum = policy.get("maximum_model_source_decisions")
    adapter_maximum = policy.get("maximum_adapter_source_decisions")
    board_adapter_maximum = policy.get("maximum_board_adapter_source_decisions")
    minimum_tests = policy.get("minimum_host_tests")
    if not all(isinstance(value, int) for value in (
        model_maximum,
        adapter_maximum,
        board_adapter_maximum,
        minimum_tests,
    )):
        return ["firmware-testability limits are incomplete"], {}

    model_counts: list[int] = []
    for relative in policy.get("model_paths", []):
        if not isinstance(relative, str):
            errors.append("firmware model path is invalid")
            continue
        source = _source(root, relative, errors, "firmware model")
        model_counts.extend(
            _check_decision_limit(source, relative, model_maximum, errors)
        )

    adapter_counts: list[int] = []
    for relative_root in policy.get("adapter_roots", []):
        if not isinstance(relative_root, str):
            errors.append("firmware adapter root is invalid")
            continue
        adapter_root = root / relative_root
        if not adapter_root.is_dir():
            errors.append(f"firmware adapter root is missing: {relative_root}")
            continue
        for path in adapter_root.rglob("*.rs"):
            if "unit_tests" in path.parts:
                continue
            relative = path.relative_to(root).as_posix()
            source = path.read_text(errors="replace")
            adapter_counts.extend(
                _check_decision_limit(source, relative, board_adapter_maximum, errors)
            )

    for target in policy.get("adapter_targets", []):
        if not isinstance(target, dict):
            errors.append("firmware adapter target is invalid")
            continue
        relative = target.get("path")
        name = target.get("function")
        fragments = target.get("required_fragments")
        if not isinstance(relative, str) or not isinstance(name, str):
            errors.append("firmware adapter identity is invalid")
            continue
        source = _source(root, relative, errors, "firmware adapter")
        target_maximum = target.get("maximum_source_decisions", adapter_maximum)
        if not isinstance(target_maximum, int):
            errors.append(f"firmware adapter decision limit is invalid: {relative}::{name}")
            target_maximum = adapter_maximum
        records = [
            record for record in function_decisions(source, relative)
            if record.name == name
        ]
        if len(records) != 1:
            errors.append(
                f"firmware adapter must have one implementation: {relative}::{name}"
            )
        else:
            adapter_counts.append(records[0].decisions)
            if records[0].decisions > target_maximum:
                errors.append(
                    "firmware adapter exceeds its decision limit: "
                    f"{relative}::{name} "
                    f"({records[0].decisions} > {target_maximum})"
                )
        if not isinstance(fragments, list) or any(
            not isinstance(fragment, str) or fragment not in source
            for fragment in fragments
        ):
            errors.append(f"firmware adapter contract is incomplete: {relative}::{name}")

    test_count = 0
    for relative in policy.get("test_paths", []):
        if not isinstance(relative, str):
            errors.append("host-test path is invalid")
            continue
        source = _source(root, relative, errors, "host-test source")
        test_count += source.count("#[test]")
    if test_count < minimum_tests:
        errors.append(
            f"firmware host coverage regressed: {test_count} tests < {minimum_tests}"
        )

    for contract in policy.get("ownership_contracts", []):
        if not isinstance(contract, dict):
            errors.append("firmware ownership contract is invalid")
            continue
        relative = contract.get("path")
        fragments = contract.get("required_fragments")
        if not isinstance(relative, str) or not isinstance(fragments, list):
            errors.append("firmware ownership contract is invalid")
            continue
        source = _source(root, relative, errors, "firmware ownership source")
        missing = [
            fragment for fragment in fragments
            if not isinstance(fragment, str) or fragment not in source
        ]
        if missing:
            errors.append(
                f"firmware ownership contract is incomplete: {relative}: {missing}"
            )

    for contract in policy.get("forbidden_owners", []):
        if not isinstance(contract, dict):
            errors.append("firmware forbidden-owner contract is invalid")
            continue
        relative = contract.get("path")
        fragments = contract.get("fragments")
        if not isinstance(relative, str) or not isinstance(fragments, list):
            errors.append("firmware forbidden-owner contract is invalid")
            continue
        source = _source(root, relative, errors, "firmware adapter source")
        present = [
            fragment for fragment in fragments
            if isinstance(fragment, str) and fragment in source
        ]
        if present:
            errors.append(
                f"shared firmware state owner was duplicated: {relative}: {present}"
            )

    return errors, {
        "host_tests": test_count,
        "maximum_model_decisions": max(model_counts, default=0),
        "maximum_adapter_decisions": max(adapter_counts, default=0),
    }
