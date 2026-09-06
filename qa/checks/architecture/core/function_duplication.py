"""Advisory function-level duplicate-implementation detection."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path
import re

from architecture.core.common import _rust_body_closing, _rust_body_opening, balanced_body_closing
from architecture.core.source_quality import production_sources

MIN_FUNCTION_LINES = 24
MIN_NORMALIZED_LINES = 18
MIN_MATCHING_LINES = 14
MIN_SIMILARITY = 0.92
MIN_SMALLER_COVERAGE = 0.85

SMALL_MIN_FUNCTION_LINES = 10
SMALL_MAX_FUNCTION_LINES = 23
SMALL_MIN_NORMALIZED_LINES = 8
SMALL_MIN_MATCHING_LINES = 8
SMALL_MIN_SIMILARITY = 0.97
SMALL_MIN_COVERAGE = 0.95


@dataclass(frozen=True)
class Function:
    path: Path
    name: str
    line: int
    lines: tuple[str, ...]


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _normalize(source: str) -> tuple[str, ...]:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"(?m)^\s*//.*$", "", source)
    normalized: list[str] = []
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        line = re.sub(r'"(?:\\.|[^"\\])*"', '"<string>"', line)
        line = re.sub(r"'(?:\\.|[^'\\])*'", "'<char>'", line)
        line = re.sub(r"\b\d+(?:\.\d+)?\b", "<number>", line)
        line = re.sub(r"\s+", " ", line)
        normalized.append(line)
    return tuple(normalized)


def _rust_function_bodies(path: Path, source: str) -> list[tuple[str, int, str]]:
    pattern = re.compile(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?"
        r"(?:unsafe\s+)?(?:extern\s+\"[^\"]+\"\s+)?fn\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)"
    )
    bodies: list[tuple[str, int, str]] = []
    for match in pattern.finditer(source):
        opening = _rust_body_opening(source, match.end())
        if opening is None:
            continue
        closing = _rust_body_closing(source, opening)
        if closing is None:
            continue
        bodies.append((
            match.group(1),
            source.count("\n", 0, match.start()) + 1,
            source[match.start():closing + 1],
        ))
    return bodies


def _javascript_function_bodies(path: Path, source: str) -> list[tuple[str, int, str]]:
    patterns = (
        re.compile(r"(?m)^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
        re.compile(r"(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"),
    )
    matches: dict[int, tuple[str, int]] = {}
    for pattern in patterns:
        for match in pattern.finditer(source):
            matches[match.start()] = (match.group(1), match.end() - 1)
    bodies: list[tuple[str, int, str]] = []
    for start, (name, opening) in sorted(matches.items()):
        closing = balanced_body_closing(source, opening, javascript=True)
        if closing is None:
            continue
        bodies.append((name, source.count("\n", 0, start) + 1, source[start:closing + 1]))
    return bodies


def _function_bodies(path: Path) -> list[tuple[str, int, str]]:
    source = path.read_text(errors="ignore")
    return _rust_function_bodies(path, source) if path.suffix == ".rs" else _javascript_function_bodies(path, source)


def _functions(path: Path, *, small: bool) -> list[Function]:
    functions: list[Function] = []
    for name, line, body in _function_bodies(path):
        physical_lines = body.count("\n") + 1
        normalized = _normalize(body)
        if small:
            if not (SMALL_MIN_FUNCTION_LINES <= physical_lines <= SMALL_MAX_FUNCTION_LINES):
                continue
            if len(normalized) < SMALL_MIN_NORMALIZED_LINES:
                continue
        else:
            if physical_lines < MIN_FUNCTION_LINES or len(normalized) < MIN_NORMALIZED_LINES:
                continue
        functions.append(Function(path, name, line, normalized))
    return functions


def _similar(left: Function, right: Function) -> tuple[float, float, int]:
    matcher = SequenceMatcher(None, left.lines, right.lines, autojunk=False)
    matching = sum(block.size for block in matcher.get_matching_blocks())
    smaller = min(len(left.lines), len(right.lines))
    return matcher.ratio(), matching / smaller, matching


def _subsystem_key(path: Path) -> tuple[str, ...]:
    parts = path.parts
    if "src" in parts:
        index = parts.index("src")
        return parts[: min(len(parts), index + 4)]
    if "js" in parts:
        index = parts.index("js")
        return parts[: min(len(parts), index + 5)]
    return parts[: min(len(parts), 5)]




def _candidate_pairs(functions: list[Function]) -> list[tuple[Function, Function]]:
    """Return plausible duplicate pairs without a global quadratic scan.

    A pair can only satisfy the configured matching-line threshold when it
    shares a meaningful number of normalized source lines.  Build an inverted
    index over informative lines, discard ubiquitous boilerplate, and run the
    expensive sequence comparison only for candidates that share structure
    and have compatible sizes.
    """
    if len(functions) < 2:
        return []

    postings: dict[tuple[str, str], list[int]] = defaultdict(list)
    for index, function in enumerate(functions):
        for line in set(function.lines):
            stripped = line.strip()
            if len(stripped) < 8 or stripped in {"{", "}", "};", "else {"}:
                continue
            postings[(function.path.suffix, stripped)].append(index)

    shared: Counter[tuple[int, int]] = Counter()
    for indices in postings.values():
        # Highly common lines are boilerplate and create quadratic noise.
        if len(indices) > 64:
            continue
        for left, right in combinations(indices, 2):
            shared[(left, right)] += 1

    pairs: list[tuple[Function, Function]] = []
    for (left_index, right_index), common_lines in shared.items():
        if common_lines < 3:
            continue
        left = functions[left_index]
        right = functions[right_index]
        if left.path.suffix != right.path.suffix:
            continue
        smaller = min(len(left.lines), len(right.lines))
        larger = max(len(left.lines), len(right.lines))
        if smaller / larger < 0.75:
            continue
        pairs.append((left, right))
    return pairs

def _warning(root: Path, left: Function, right: Function, similarity: float, coverage: float, code: str) -> str:
    return (
        f"{code} possible duplicate functions: "
        f"{_relative(root, left.path)}:{left.line}::{left.name} <-> "
        f"{_relative(root, right.path)}:{right.line}::{right.name} "
        f"({similarity:.0%} similarity, {coverage:.0%} smaller-function coverage)"
    )


def check(root: Path) -> list[str]:
    paths = list(production_sources(root))
    warnings: list[str] = []

    large_functions = [function for path in paths for function in _functions(path, small=False)]
    for left, right in _candidate_pairs(large_functions):
        if left.name == right.name and left.path == right.path:
            continue
        similarity, coverage, matching = _similar(left, right)
        if similarity < MIN_SIMILARITY or coverage < MIN_SMALLER_COVERAGE or matching < MIN_MATCHING_LINES:
            continue
        warnings.append(_warning(root, left, right, similarity, coverage, "ARCH-W008"))

    # Smaller workflows are compared only inside the same subsystem and with
    # equal normalized length. This catches copy/paste controller lifecycles
    # without turning the global check into an O(n²) scan over tiny helpers.
    buckets: dict[tuple[tuple[str, ...], str, int], list[Function]] = defaultdict(list)
    for path in paths:
        for function in _functions(path, small=True):
            buckets[(_subsystem_key(path), path.suffix, len(function.lines))].append(function)
    for functions in buckets.values():
        for left, right in combinations(functions, 2):
            if left.name == right.name and left.path == right.path:
                continue
            similarity, coverage, matching = _similar(left, right)
            if (
                similarity < SMALL_MIN_SIMILARITY
                or coverage < SMALL_MIN_COVERAGE
                or matching < SMALL_MIN_MATCHING_LINES
            ):
                continue
            warnings.append(_warning(root, left, right, similarity, coverage, "ARCH-W018"))

    return sorted(set(warnings))
