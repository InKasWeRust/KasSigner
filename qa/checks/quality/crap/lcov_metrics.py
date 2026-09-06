"""LCOV parsing and aggregation for CRAP health checks."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

METRICS = ("lines", "functions", "branches")


def _normalize_path(raw: str) -> str:
    normalized = raw.replace("\\", "/").removeprefix("./")
    # LCOV records can be emitted from arbitrary checkout directory names
    # (for example KasSigner-build-... rather than literally /kassigner/).
    # Normalize by stable repository-owned roots, not by the checkout basename.
    for marker in ("/crates/", "/apps/", "/qa/", "/tools/", "/external/"):
        if marker in normalized:
            return marker[1:] + normalized.rsplit(marker, 1)[1]
    legacy_marker = "/kassigner/"
    if legacy_marker in normalized:
        return normalized.split(legacy_marker, 1)[1]
    return normalized


def _empty_metric() -> dict[str, int | float | bool]:
    return {"found": 0, "hit": 0, "percent": 0.0, "available": False}


def _finish_metric(metric: dict[str, int | float | bool]) -> None:
    found = int(metric["found"])
    hit = int(metric["hit"])
    metric["percent"] = round(hit * 100.0 / found, 4) if found else 0.0
    metric["available"] = found > 0


def parse_lcov(path: Path) -> dict[str, dict[str, dict[str, int | float | bool]]]:
    """Parse per-file LCOV totals, deriving totals when summaries are absent."""
    records: dict[str, dict[str, dict[str, int | float | bool]]] = {}
    current_path: str | None = None
    summary: dict[str, int] = {}
    line_hits: dict[int, int] = {}
    functions: set[str] = set()
    function_hits: dict[str, int] = {}
    branches: set[tuple[str, ...]] = set()
    branch_hits: set[tuple[str, ...]] = set()

    def flush() -> None:
        nonlocal current_path, summary, line_hits, functions, function_hits
        nonlocal branches, branch_hits
        if current_path is None:
            return
        metrics = {name: _empty_metric() for name in METRICS}
        derived = {
            "LF": len(line_hits),
            "LH": sum(value > 0 for value in line_hits.values()),
            "FNF": len(functions),
            "FNH": sum(function_hits.get(name, 0) > 0 for name in functions),
            "BRF": len(branches),
            "BRH": len(branch_hits),
        }
        mapping = {
            "LF": ("lines", "found"),
            "LH": ("lines", "hit"),
            "FNF": ("functions", "found"),
            "FNH": ("functions", "hit"),
            "BRF": ("branches", "found"),
            "BRH": ("branches", "hit"),
        }
        for key, (metric_name, field) in mapping.items():
            # LLVM/LCOV producers can emit stale BRH summary counters after
            # merging instrumented Rust monomorphizations even when the concrete
            # BRDA records show every branch was executed. When BRDA exists, the
            # per-branch records are the authoritative evidence. Keep summary
            # fallback only for producers that provide branch totals without
            # concrete branch records.
            if metric_name == "branches" and branches:
                metrics[metric_name][field] = derived[key]
            else:
                metrics[metric_name][field] = summary.get(key, derived[key])
        for metric in metrics.values():
            _finish_metric(metric)
        records[current_path] = metrics
        current_path = None
        summary = {}
        line_hits = {}
        functions = set()
        function_hits = {}
        branches = set()
        branch_hits = set()

    for raw in path.read_text(errors="replace").splitlines():
        if raw.startswith("SF:"):
            flush()
            current_path = _normalize_path(raw[3:])
            continue
        if raw == "end_of_record":
            flush()
            continue
        if current_path is None:
            continue
        prefix, separator, value = raw.partition(":")
        if not separator:
            continue
        if prefix in {"LF", "LH", "FNF", "FNH", "BRF", "BRH"}:
            try:
                summary[prefix] = int(value)
            except ValueError:
                pass
        elif prefix == "DA":
            fields = value.split(",")
            if len(fields) >= 2:
                try:
                    line_hits[int(fields[0])] = int(fields[1])
                except ValueError:
                    pass
        elif prefix == "FN":
            _, separator, name = value.partition(",")
            if separator:
                functions.add(name)
        elif prefix == "FNDA":
            count, separator, name = value.partition(",")
            if separator:
                functions.add(name)
                try:
                    function_hits[name] = function_hits.get(name, 0) + int(float(count))
                except ValueError:
                    pass
        elif prefix == "BRDA":
            fields = tuple(value.split(","))
            if len(fields) >= 4:
                identity = fields[:3]
                branches.add(identity)
                if fields[3] not in {"-", "0"}:
                    branch_hits.add(identity)
    flush()
    return records


def aggregate(
    records: dict[str, dict[str, dict[str, int | float | bool]]],
    paths: list[str],
) -> dict[str, dict[str, int | float | bool]]:
    totals = {name: _empty_metric() for name in METRICS}
    for path in paths:
        record = records.get(path)
        if record is None:
            continue
        for metric_name in METRICS:
            totals[metric_name]["found"] = int(totals[metric_name]["found"]) + int(
                record[metric_name]["found"]
            )
            totals[metric_name]["hit"] = int(totals[metric_name]["hit"]) + int(
                record[metric_name]["hit"]
            )
    for metric in totals.values():
        _finish_metric(metric)
    return totals


def matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch(path, pattern) for pattern in patterns)
