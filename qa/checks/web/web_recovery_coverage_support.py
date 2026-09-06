"""Coverage parsing and aggregation for KasSee recovery tests."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[3]
RECOVERY_ROOT = ROOT / "apps/kassee-web/web/js/features/covenants/recovery"
RECOVERY_PREFIX = RECOVERY_ROOT.relative_to(ROOT).as_posix() + "/"
IGNORE_RE = re.compile(r"/\* node:coverage ignore next (?:(?P<count>\d+) )?\*/")
STATUS_RE = re.compile(r"/\* node:coverage (?P<status>enable|disable) \*/")

@dataclass
class CoverageLine:
    number: int
    start_offset: int
    end_offset: int
    ignored: bool
    count: int


@dataclass(frozen=True)
class CoverageTotals:
    total_lines: int = 0
    covered_lines: int = 0
    total_branches: int = 0
    covered_branches: int = 0
    total_functions: int = 0
    covered_functions: int = 0

    def add(self, other: "CoverageTotals") -> "CoverageTotals":
        return CoverageTotals(
            total_lines=self.total_lines + other.total_lines,
            covered_lines=self.covered_lines + other.covered_lines,
            total_branches=self.total_branches + other.total_branches,
            covered_branches=self.covered_branches + other.covered_branches,
            total_functions=self.total_functions + other.total_functions,
            covered_functions=self.covered_functions + other.covered_functions,
        )


def percent(covered: int, total: int) -> float:
    return 100.0 if total == 0 else (covered / total) * 100.0


def _canonical_path_text(value: str | Path) -> str:
    """Return slash-stable absolute/path text without applying host semantics.

    V8 emits ``file:///C:/...`` URLs on Windows, while ``pathlib`` running
    under MSYS/MinGW can reinterpret the leading slash before the drive.  Do
    the repository-membership comparison lexically so coverage collected on
    Windows is compared against the same canonical ``/`` inventory used on
    every host.
    """

    text = str(value).replace("\\", "/")
    if re.match(r"^/[A-Za-z]:/", text):
        text = text[1:]
    return text.rstrip("/")


def relative_file_url(url: str, root: str | Path = ROOT) -> str | None:
    if not url.startswith("file:"):
        return None
    parsed = urlparse(url)
    decoded = unquote(parsed.path).replace("\\", "/")
    if parsed.netloc and parsed.netloc.lower() != "localhost":
        decoded = f"//{parsed.netloc}{decoded}"

    candidate = _canonical_path_text(decoded)
    if isinstance(root, Path):
        root = root.resolve()
    repository = _canonical_path_text(root)

    # Drive-letter and UNC paths are case-insensitive on Windows.  Keep POSIX
    # comparisons case-sensitive so a Linux checkout cannot silently alias two
    # differently-cased source paths.
    windows_style = bool(
        re.match(r"^[A-Za-z]:/", candidate)
        or re.match(r"^[A-Za-z]:/", repository)
        or candidate.startswith("//")
        or repository.startswith("//")
    )
    candidate_key = candidate.casefold() if windows_style else candidate
    repository_key = repository.casefold() if windows_style else repository
    prefix = repository_key + "/"
    if not candidate_key.startswith(prefix):
        return None
    return candidate[len(repository) + 1 :]


def _function_key(function: dict[str, Any]) -> tuple[str, int, int] | None:
    ranges = function.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        return None
    first = ranges[0]
    if not isinstance(first, dict):
        return None
    return (
        str(function.get("functionName", "")),
        int(first.get("startOffset", 0)),
        int(first.get("endOffset", 0)),
    )


def _range_key(item: dict[str, Any]) -> tuple[int, int]:
    return (int(item.get("startOffset", 0)), int(item.get("endOffset", 0)))


def _effective_range_count(ranges: list[dict[str, Any]], start: int, end: int) -> int:
    """Return the most-specific V8 count that governs an interval.

    Precise V8 coverage is hierarchical: the function range supplies the
    default count and nested ranges override portions whose branch count
    differs.  Across independent Node processes V8 may emit different nested
    partitions for the same function.  If a range is absent in one run, that
    interval inherits the closest containing range from that run.
    """

    exact = [item for item in ranges if _range_key(item) == (start, end)]
    if exact:
        return max(int(item.get("count", 0)) for item in exact)
    containers = [
        item for item in ranges
        if int(item.get("startOffset", 0)) <= start
        and int(item.get("endOffset", 0)) >= end
    ]
    if not containers:
        return 0
    most_specific = min(
        containers,
        key=lambda item: (
            int(item.get("endOffset", 0)) - int(item.get("startOffset", 0)),
            -int(item.get("startOffset", 0)),
        ),
    )
    return int(most_specific.get("count", 0))


def _merge_function_ranges(
    current_ranges: list[dict[str, Any]], incoming_ranges: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """OR two precise-coverage range trees without range-order corruption."""

    keys = {_range_key(item) for item in current_ranges + incoming_ranges}
    merged: list[dict[str, Any]] = []
    for start, end in keys:
        merged.append({
            "startOffset": start,
            "endOffset": end,
            "count": max(
                _effective_range_count(current_ranges, start, end),
                _effective_range_count(incoming_ranges, start, end),
            ),
        })
    # V8 range trees are outer-to-inner.  Keeping that ordering is essential
    # because line mapping intentionally lets a more-specific nested range
    # override its containing range.
    merged.sort(key=lambda item: (
        int(item.get("startOffset", 0)),
        -int(item.get("endOffset", 0)),
    ))
    return merged


def _merge_script(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Merge duplicate V8 scripts using true OR-across-runs semantics.

    V8 can emit different nested range partitions for the same function in
    separate processes.  Appending those ranges is incorrect: a late broad
    zero-count range can overwrite a narrower covered range during line
    mapping.  Normalize each function into one ordered range tree and inherit
    parent counts when a partition is absent from one run.
    """

    functions = existing.setdefault("functions", [])
    by_key = {
        key: function
        for function in functions
        if isinstance(function, dict) and (key := _function_key(function)) is not None
    }
    for incoming_function in incoming.get("functions", []):
        if not isinstance(incoming_function, dict):
            continue
        key = _function_key(incoming_function)
        if key is None or key not in by_key:
            functions.append(incoming_function)
            if key is not None:
                by_key[key] = incoming_function
            continue
        current = by_key[key]
        current_ranges = [item for item in current.get("ranges", []) if isinstance(item, dict)]
        incoming_ranges = [item for item in incoming_function.get("ranges", []) if isinstance(item, dict)]
        current["ranges"] = _merge_function_ranges(current_ranges, incoming_ranges)
        current["isBlockCoverage"] = bool(
            current.get("isBlockCoverage") or incoming_function.get("isBlockCoverage")
        )


def merge_v8_coverage(
    raw_dir: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], set[str]]:
    scripts: dict[str, dict[str, Any]] = {}
    sources: list[str] = []
    measured: set[str] = set()
    for source_index, path in enumerate(sorted(raw_dir.glob("coverage-*.json")), start=1):
        sources.append(f"coverage-{source_index}.json")
        document = json.loads(path.read_text(encoding="utf-8"))
        for script in document.get("result", []):
            if not isinstance(script, dict):
                continue
            url = script.get("url")
            if not isinstance(url, str):
                continue
            relative = relative_file_url(url)
            if relative is None:
                continue
            normalized = dict(script)
            normalized.pop("scriptId", None)
            normalized["url"] = relative
            if relative in scripts:
                _merge_script(scripts[relative], normalized)
            else:
                scripts[relative] = normalized
            if relative.startswith(RECOVERY_PREFIX):
                measured.add(relative)
    merged = {
        "schema_version": 1,
        "source_files": sources,
        "result": [scripts[url] for url in sorted(scripts)],
    }
    return merged, scripts, measured


def source_lines(source: str) -> list[CoverageLine]:
    chunks = source.splitlines(keepends=True) or [""]
    lines: list[CoverageLine] = []
    ignore_count = 0
    enabled = True
    offset = 0
    for number, chunk in enumerate(chunks, start=1):
        newline_length = 2 if chunk.endswith("\r\n") else 1 if chunk.endswith("\n") else 0
        start_offset = offset
        end_offset = start_offset + len(chunk) - newline_length
        offset += len(chunk)
        ignored = False
        if ignore_count > 0:
            ignore_count -= 1
            ignored = True
        elif not enabled:
            ignored = True

        if not ignored:
            match = IGNORE_RE.search(chunk)
            if match is not None:
                ignore_count = int(match.group("count") or 1)

        status_match = STATUS_RE.search(chunk)
        if status_match is not None:
            ignore_count = 0
            enabled = status_match.group("status") == "enable"

        lines.append(
            CoverageLine(
                number=number,
                start_offset=start_offset,
                end_offset=end_offset,
                ignored=ignored,
                count=1 if start_offset == end_offset else 0,
            )
        )
    return lines


def map_range_to_lines(
    coverage_range: dict[str, Any], lines: list[CoverageLine]
) -> tuple[list[CoverageLine], int]:
    start_offset = int(coverage_range.get("startOffset", 0))
    end_offset = int(coverage_range.get("endOffset", 0))
    count = int(coverage_range.get("count", 0))
    start_index: int | None = None
    for index, line in enumerate(lines):
        if start_offset >= line.start_offset and start_offset <= line.end_offset:
            start_index = index
            break
    if start_index is None:
        return [], 0

    mapped: list[CoverageLine] = []
    ignored = 0
    index = start_index
    while index < len(lines) and end_offset > lines[index].start_offset:
        line = lines[index]
        if start_offset <= line.start_offset and end_offset >= line.end_offset:
            line.count = count
        mapped.append(line)
        if line.ignored:
            ignored += 1
        index += 1
    return mapped, ignored


def summarize_script(script: dict[str, Any], source: str) -> CoverageTotals:
    lines = source_lines(source)
    total_branches = 0
    covered_branches = 0
    total_functions = 0
    covered_functions = 0

    functions = script.get("functions", [])
    for function_index, function in enumerate(functions):
        if not isinstance(function, dict):
            continue
        mapped_ranges: list[tuple[list[CoverageLine], int]] = []
        ranges = function.get("ranges", [])
        for coverage_range in ranges:
            if not isinstance(coverage_range, dict):
                continue
            mapped, ignored = map_range_to_lines(coverage_range, lines)
            mapped_ranges.append((mapped, ignored))
            if function.get("isBlockCoverage"):
                total_branches += 1
                if int(coverage_range.get("count", 0)) != 0 or ignored == len(mapped):
                    covered_branches += 1

        # Node excludes the synthetic top-level script function at index zero.
        if function_index > 0 and ranges and mapped_ranges:
            total_functions += 1
            first_range = ranges[0]
            mapped, ignored = mapped_ranges[0]
            if int(first_range.get("count", 0)) != 0 or ignored == len(mapped):
                covered_functions += 1

    covered_lines = sum(1 for line in lines if line.count > 0 or line.ignored)
    return CoverageTotals(
        total_lines=len(lines),
        covered_lines=covered_lines,
        total_branches=total_branches,
        covered_branches=covered_branches,
        total_functions=total_functions,
        covered_functions=covered_functions,
    )


def recovery_totals(
    scripts: dict[str, dict[str, Any]], expected: set[str]
) -> tuple[CoverageTotals, list[dict[str, Any]]]:
    totals = CoverageTotals()
    files: list[dict[str, Any]] = []
    for relative in sorted(expected):
        script = scripts.get(relative)
        if script is None:
            continue
        file_totals = summarize_script(script, (ROOT / relative).read_text(encoding="utf-8"))
        totals = totals.add(file_totals)
        files.append(
            {
                "path": relative,
                "lines": percent(file_totals.covered_lines, file_totals.total_lines),
                "branches": percent(
                    file_totals.covered_branches, file_totals.total_branches
                ),
                "functions": percent(
                    file_totals.covered_functions, file_totals.total_functions
                ),
            }
        )
    return totals, files


def coverage_report(test_output: str, files: list[dict[str, Any]], totals: CoverageTotals) -> str:
    rows = [
        test_output.rstrip(),
        "",
        "# browser recovery coverage",
        "# file | line % | branch % | funcs %",
    ]
    rows.extend(
        f"# {item['path']} | {item['lines']:.2f} | {item['branches']:.2f} | "
        f"{item['functions']:.2f}"
        for item in files
    )
    rows.append(
        "# all recovery files | "
        f"{percent(totals.covered_lines, totals.total_lines):.2f} | "
        f"{percent(totals.covered_branches, totals.total_branches):.2f} | "
        f"{percent(totals.covered_functions, totals.total_functions):.2f}"
    )
    return "\n".join(rows).lstrip() + "\n"


