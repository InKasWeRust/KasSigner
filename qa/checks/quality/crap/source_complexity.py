"""Source-level complexity contracts for first-party production Rust."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
CHECK_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CHECK_DIR))
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.core.common import (  # noqa: E402
    _rust_body_closing,
    _rust_body_opening,
    rust_code_only,
)
from report import classify_path  # noqa: E402

FUNCTION_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:unsafe\s+)?(?:extern\s+\"[^\"]+\"\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)
DECISION_PATTERNS = tuple(
    re.compile(rf"\b{keyword}\b") for keyword in ("if", "for", "while", "loop")
)
FORBIDDEN_EXCEPTIONS = (
    "allow(clippy::cognitive_complexity)",
    "allow(clippy::too_many_lines)",
)
PRODUCTION_ROOTS = (
    "apps/kassee-web/src",
    "apps/signer-firmware/src",
    "crates/kassigner-protocol/src",
    "crates/kassigner-sdk/src",
    "crates/offline-signer/src",
    "crates/online-watcher/src",
    "crates/shared-signer/src",
    "crates/signer-firmware-core/src",
)


@dataclass(frozen=True)
class FunctionDecisionCount:
    path: str
    name: str
    line: int
    decisions: int


def source_decisions(body: str) -> int:
    """Return a conservative source-level decision count for one Rust function."""
    code = rust_code_only(body)
    return (
        1
        + sum(len(pattern.findall(code)) for pattern in DECISION_PATTERNS)
        + code.count("&&")
        + code.count("||")
        + code.count("?")
        + len(re.findall(r"=>", code))
    )


def function_decisions(source: str, path: str = "") -> list[FunctionDecisionCount]:
    records: list[FunctionDecisionCount] = []
    for match in FUNCTION_PATTERN.finditer(source):
        opening = _rust_body_opening(source, match.end())
        if opening is None:
            continue
        closing = _rust_body_closing(source, opening)
        if closing is None:
            continue
        records.append(
            FunctionDecisionCount(
                path=path,
                name=match.group(1),
                line=source.count("\n", 0, match.start()) + 1,
                decisions=source_decisions(source[match.start() : closing + 1]),
            )
        )
    return records


def production_records(root: Path) -> list[FunctionDecisionCount]:
    records: list[FunctionDecisionCount] = []
    for relative_root in PRODUCTION_ROOTS:
        for path in (root / relative_root).rglob("*.rs"):
            relative = path.relative_to(root).as_posix()
            if classify_path(relative) != "production":
                continue
            source = path.read_text(errors="replace")
            records.extend(function_decisions(source, relative))
    return records


def _monitored_records(
    root: Path,
    relative: str,
    errors: list[str],
) -> tuple[str, list[FunctionDecisionCount]]:
    path = root / relative
    if not path.is_file():
        errors.append(f"monitored source is missing: {relative}")
        return "", []
    source = path.read_text(errors="replace")
    for exception in FORBIDDEN_EXCEPTIONS:
        if exception in source:
            errors.append(f"complexity exception is forbidden: {relative}: {exception}")
    return source, function_decisions(source, relative)


def check_source_policy(
    root: Path,
    policy: dict[str, Any],
) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    maximum = policy.get("maximum_production_source_decisions")
    warning_level = policy.get("warning_source_decisions")
    maximum_warnings = policy.get("maximum_warning_functions")
    monitored_maximum = policy.get("maximum_monitored_source_decisions")
    targets = policy.get("targets")
    monitored_paths = policy.get("monitored_paths")
    if not all(isinstance(value, int) for value in (
        maximum,
        warning_level,
        maximum_warnings,
        monitored_maximum,
    )):
        return ["source-complexity limits are incomplete"], {}
    if not isinstance(targets, list) or not isinstance(monitored_paths, list):
        return ["source-complexity contracts are incomplete"], {}

    records = production_records(root)
    excessive = [record for record in records if record.decisions > maximum]
    warnings = [record for record in records if record.decisions > warning_level]
    for record in excessive:
        errors.append(
            "production function exceeds the source-decision limit: "
            f"{record.path}:{record.line} {record.name} "
            f"({record.decisions} > {maximum})"
        )
    if len(warnings) > maximum_warnings:
        errors.append(
            "production source-decision warning count regressed: "
            f"{len(warnings)} > {maximum_warnings}"
        )

    records_by_path: dict[str, list[FunctionDecisionCount]] = {}
    source_by_path: dict[str, str] = {}
    for relative in monitored_paths:
        if not isinstance(relative, str):
            errors.append("monitored source path is invalid")
            continue
        source, path_records = _monitored_records(root, relative, errors)
        source_by_path[relative] = source
        records_by_path[relative] = path_records
        for record in path_records:
            if record.decisions > monitored_maximum:
                errors.append(
                    "monitored helper exceeds the source-decision limit: "
                    f"{relative}:{record.line} {record.name} "
                    f"({record.decisions} > {monitored_maximum})"
                )

    target_counts: list[int] = []
    for target in targets:
        if not isinstance(target, dict):
            errors.append("decomposition target is invalid")
            continue
        relative = target.get("path")
        name = target.get("function")
        previous = target.get("previous_complexity")
        fragments = target.get("required_fragments")
        if not isinstance(relative, str) or not isinstance(name, str):
            errors.append("decomposition target identity is invalid")
            continue
        matches = [
            record for record in records_by_path.get(relative, [])
            if record.name == name
        ]
        if len(matches) != 1:
            errors.append(
                f"decomposition target must have one implementation: {relative}::{name}"
            )
            continue
        record = matches[0]
        target_counts.append(record.decisions)
        if not isinstance(previous, int) or record.decisions >= previous:
            errors.append(
                "decomposition target did not remain below its original complexity: "
                f"{relative}::{name} ({record.decisions} vs original CC {previous})"
            )
        source = source_by_path.get(relative, "")
        if not isinstance(fragments, list) or any(
            not isinstance(fragment, str) or fragment not in source
            for fragment in fragments
        ):
            errors.append(f"decomposition contract is incomplete: {relative}::{name}")

    return errors, {
        "production_functions": len(records),
        "warning_functions": len(warnings),
        "maximum_decisions": max((record.decisions for record in records), default=0),
        "maximum_target_decisions": max(target_counts, default=0),
    }
