"""Parse, classify, and render reports produced by cargo-crap."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from hashlib import sha256
from pathlib import Path
import json
import re
from typing import Any, Iterable

STATUS_BY_SYMBOL = {"✗": "fail", "▲": "warning", "✓": "pass"}
SYMBOL_BY_STATUS = {value: key for key, value in STATUS_BY_SYMBOL.items()}
SCOPES = ("production", "tests", "external", "tools")
SUMMARY_RE = re.compile(
    r"✗\s+(?P<failures>\d+)/(?P<total>\d+) function\(s\) exceed CRAP threshold "
    r"(?P<threshold>\d+(?:\.\d+)?)\."
)
COVERAGE_RE = re.compile(r"(?P<coverage>\d+(?:\.\d+)?)%")


@dataclass(frozen=True)
class CrapEntry:
    status: str
    raw_status: str
    assessment_basis: str
    crap: float
    complexity: int
    coverage_percent: float | None
    coverage_state: str
    function: str
    path: str
    line: int | None
    scope: str

    @property
    def location(self) -> str:
        return f"./{self.path}:{self.line}" if self.line is not None else f"./{self.path}"


@dataclass(frozen=True)
class CrapReport:
    threshold: float
    entries: tuple[CrapEntry, ...]
    source_sha256: str


def split_location(location: str) -> tuple[str, int | None]:
    """Return a normalized repository path and optional source line."""
    normalized = location.removeprefix("./")
    path, separator, line = normalized.rpartition(":")
    if separator and line.isdigit():
        return path, int(line)
    return normalized, None


def classify_path(path: str) -> str:
    """Classify one report path into the enforced quality ownership scopes."""
    parts = Path(path).parts
    if not parts:
        raise ValueError("CRAP report path is empty")
    if parts[0] == "external":
        return "external"
    if parts[0] == "tools":
        return "tools"
    if parts[0] == "qa":
        return "tests" if any(part in {"tests", "benches", "fuzz"} for part in parts) else "tools"
    if any(part in {"unit_tests", "tests", "benches", "fuzz"} for part in parts):
        return "tests"
    if parts[:5] == ("apps", "signer-firmware", "src", "qemu", "validation"):
        return "tests"
    # Developer-only workflow E2E code is compiled only behind the
    # `workflow-tests` feature, which is forbidden in production/silent builds.
    # Keep this harness out of production CRAP/source-complexity ownership while
    # continuing to enforce it in the tests scope.
    if parts[:5] == ("apps", "signer-firmware", "src", "runtime", "workflow_tests"):
        return "tests"
    if parts[:6] == (
        "apps", "signer-firmware", "src", "runtime", "interactions", "workflow_tests.rs"
    ):
        return "tests"
    return "production"


def coverage_state(coverage: float | None) -> str:
    if coverage is None:
        return "unavailable"
    if coverage == 0.0:
        return "zero"
    return "measured"




def status_for_score(score: float, threshold: float) -> str:
    """Map a CRAP score to the repository's fail/warning/pass bands."""
    if score > threshold:
        return "fail"
    if score > 10.0:
        return "warning"
    return "pass"


def normalize_json_path(path: str) -> str:
    """Normalize cargo-crap JSON paths to repository-relative form."""
    normalized = path.replace("\\", "/").removeprefix("./")
    marker = "/kassigner/"
    if marker in normalized:
        normalized = normalized.split(marker, 1)[1]
    return normalized


def parse_report_json(text: str, threshold: float = 30.0) -> CrapReport:
    """Parse cargo-crap's versioned JSON envelope."""
    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"cargo-crap JSON is invalid: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        raise ValueError("cargo-crap JSON must contain an entries array")

    entries: list[CrapEntry] = []
    for item in document["entries"]:
        if not isinstance(item, dict):
            raise ValueError("cargo-crap JSON contains an invalid entry")
        file_name = item.get("file")
        function = item.get("function")
        line = item.get("line")
        complexity = item.get("cyclomatic")
        coverage = item.get("coverage")
        score = item.get("crap")
        if not isinstance(file_name, str) or not isinstance(function, str):
            raise ValueError("cargo-crap JSON contains an invalid function identity")
        if not isinstance(line, int) or not isinstance(complexity, (int, float)):
            raise ValueError(f"cargo-crap JSON has invalid location/complexity: {function}")
        if coverage is not None and not isinstance(coverage, (int, float)):
            raise ValueError(f"cargo-crap JSON has invalid coverage: {function}")
        if not isinstance(score, (int, float)):
            raise ValueError(f"cargo-crap JSON has invalid score: {function}")
        path = normalize_json_path(file_name)
        coverage_value = None if coverage is None else float(coverage)
        score_value = float(score)
        entries.append(
            CrapEntry(
                status=status_for_score(score_value, threshold),
                raw_status=status_for_score(score_value, threshold),
                assessment_basis="crap",
                crap=score_value,
                complexity=int(complexity),
                coverage_percent=coverage_value,
                coverage_state=coverage_state(coverage_value),
                function=function,
                path=path,
                line=line,
                scope=classify_path(path),
            )
        )
    if not entries:
        raise ValueError("cargo-crap JSON contains no function entries")
    return CrapReport(
        threshold=threshold,
        entries=tuple(entries),
        source_sha256=sha256(text.encode()).hexdigest(),
    )


def parse_report_text(text: str) -> CrapReport:
    """Parse the Unicode table while preserving measured/unavailable coverage."""
    entries: list[CrapEntry] = []
    for line in text.splitlines():
        if not line.startswith("│ "):
            continue
        fields = [field.strip() for field in line.strip("│").split("┆")]
        if len(fields) != 6 or fields[0] not in STATUS_BY_SYMBOL:
            continue
        symbol, crap_text, complexity_text, coverage_text, function, location = fields
        coverage_match = COVERAGE_RE.search(coverage_text)
        coverage = float(coverage_match.group("coverage")) if coverage_match else None
        path, source_line = split_location(location)
        entries.append(
            CrapEntry(
                status=STATUS_BY_SYMBOL[symbol],
                raw_status=STATUS_BY_SYMBOL[symbol],
                assessment_basis="crap",
                crap=float(crap_text),
                complexity=int(complexity_text),
                coverage_percent=coverage,
                coverage_state=coverage_state(coverage),
                function=function,
                path=path,
                line=source_line,
                scope=classify_path(path),
            )
        )

    summary_match = SUMMARY_RE.search(text)
    if summary_match is None:
        raise ValueError("CRAP report summary is missing")
    expected_total = int(summary_match.group("total"))
    expected_failures = int(summary_match.group("failures"))
    actual_failures = sum(entry.status == "fail" for entry in entries)
    if len(entries) != expected_total:
        raise ValueError(
            f"CRAP report row count mismatch: parsed {len(entries)}, summary says {expected_total}"
        )
    if actual_failures != expected_failures:
        raise ValueError(
            "CRAP report failure count mismatch: "
            f"parsed {actual_failures}, summary says {expected_failures}"
        )
    return CrapReport(
        threshold=float(summary_match.group("threshold")),
        entries=tuple(entries),
        source_sha256=sha256(text.encode()).hexdigest(),
    )



def apply_coverage_unavailable_source_policy(
    report: CrapReport,
    policy: dict[str, Any],
) -> CrapReport:
    """Use source complexity for embedded production code lacking coverage.

    CRAP requires coverage data. Embedded firmware is built for Xtensa and is not
    part of the host LCOV run, so pessimistic CRAP scores for those functions are
    retained as raw diagnostics but are not used as the effective status. Pure
    firmware decisions remain covered through shared-signer, while embedded
    orchestration is governed by explicit source-complexity and board-adapter
    limits.
    """
    config = policy.get("coverage_unavailable_source_policy")
    if not isinstance(config, dict):
        return report
    roots = config.get("roots")
    warning_limit = config.get("warning_source_decisions")
    failure_limit = config.get("failure_source_decisions")
    if (
        not isinstance(roots, list)
        or not all(isinstance(root, str) for root in roots)
        or not isinstance(warning_limit, int)
        or not isinstance(failure_limit, int)
        or warning_limit < 0
        or failure_limit < warning_limit
    ):
        raise ValueError("coverage-unavailable source policy is invalid")

    entries: list[CrapEntry] = []
    for entry in report.entries:
        governed = (
            entry.scope == "production"
            and entry.coverage_state == "unavailable"
            and any(entry.path.startswith(root) for root in roots)
        )
        if not governed:
            entries.append(entry)
            continue
        if entry.complexity > failure_limit:
            status = "fail"
        elif entry.complexity > warning_limit:
            status = "warning"
        else:
            status = "pass"
        entries.append(
            replace(
                entry,
                status=status,
                assessment_basis="source_complexity",
            )
        )
    return replace(report, entries=tuple(entries))

def parse_report(path: Path) -> CrapReport:
    text = path.read_text(errors="replace")
    if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
        return parse_report_json(text)
    return parse_report_text(text)


def scope_summary(entries: Iterable[CrapEntry]) -> dict[str, object]:
    selected = tuple(entries)
    status_counts = {
        status: sum(entry.status == status for entry in selected)
        for status in ("fail", "warning", "pass")
    }
    raw_status_counts = {
        status: sum(entry.raw_status == status for entry in selected)
        for status in ("fail", "warning", "pass")
    }
    assessment_counts = {
        basis: sum(entry.assessment_basis == basis for entry in selected)
        for basis in ("crap", "source_complexity")
    }
    coverage_counts = {
        state: sum(entry.coverage_state == state for entry in selected)
        for state in ("measured", "zero", "unavailable")
    }
    return {
        "functions": len(selected),
        "status": status_counts,
        "raw_status": raw_status_counts,
        "assessment_basis": assessment_counts,
        "coverage": coverage_counts,
    }


def report_summary(report: CrapReport) -> dict[str, object]:
    scopes = {
        scope: scope_summary(entry for entry in report.entries if entry.scope == scope)
        for scope in SCOPES
    }
    return {
        "threshold": report.threshold,
        "source_sha256": report.source_sha256,
        "all": scope_summary(report.entries),
        "scopes": scopes,
    }


def render_scope_report(report: CrapReport, scope: str) -> str:
    if scope not in SCOPES:
        raise ValueError(f"unknown CRAP report scope: {scope}")
    entries = tuple(entry for entry in report.entries if entry.scope == scope)
    summary = scope_summary(entries)
    lines = [
        f"CRAP report scope: {scope}",
        f"Threshold: {report.threshold:g}",
        f"Source SHA-256: {report.source_sha256}",
        f"Functions: {summary['functions']}",
        (
            "Status: "
            f"{summary['status']['fail']} fail, "
            f"{summary['status']['warning']} warning, "
            f"{summary['status']['pass']} pass"
        ),
        (
            "Raw cargo-crap status: "
            f"{summary['raw_status']['fail']} fail, "
            f"{summary['raw_status']['warning']} warning, "
            f"{summary['raw_status']['pass']} pass"
        ),
        (
            "Assessment basis: "
            f"{summary['assessment_basis']['crap']} CRAP, "
            f"{summary['assessment_basis']['source_complexity']} source complexity"
        ),
        (
            "Coverage: "
            f"{summary['coverage']['measured']} measured, "
            f"{summary['coverage']['zero']} measured-zero, "
            f"{summary['coverage']['unavailable']} unavailable"
        ),
        "",
        "STATUS\tRAW_STATUS\tBASIS\tCRAP\tCC\tCOVERAGE\tFUNCTION\tLOCATION",
    ]
    for entry in entries:
        coverage = (
            "unavailable"
            if entry.coverage_percent is None
            else f"{entry.coverage_percent:.1f}%"
        )
        lines.append(
            "\t".join(
                (
                    SYMBOL_BY_STATUS[entry.status],
                    entry.raw_status,
                    entry.assessment_basis,
                    f"{entry.crap:.1f}",
                    str(entry.complexity),
                    coverage,
                    entry.function,
                    entry.location,
                )
            )
        )
    lines.append("")
    return "\n".join(lines)


def baseline_document(report: CrapReport, source_label: str) -> dict[str, object]:
    """Build a checked-in machine-readable reference snapshot."""
    return {
        "schema_version": 1,
        "source": {
            "label": source_label,
            "report_sha256": report.source_sha256,
            "threshold": report.threshold,
        },
        "summary": report_summary(report),
        "functions": [asdict(entry) for entry in report.entries],
    }


def write_json(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
