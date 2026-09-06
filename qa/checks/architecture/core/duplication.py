"""Advisory duplicate-implementation similarity detection."""

from __future__ import annotations

from collections import defaultdict
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path
import re

from architecture.core.source_quality import MODULE_SIZE_EXEMPTIONS, production_sources

MIN_NORMALIZED_LINES = 40
MIN_MATCHING_LINES = 32
MIN_SMALLER_FILE_COVERAGE = 0.55
MIN_SIMILARITY = 0.78
SHINGLE_SIZE = 4
MAX_COMMON_SHINGLE_FILES = 12
INTENTIONAL_ADAPTER_PAIRS = {
    frozenset({
        "apps/signer-firmware/src/hw/m5stack/display.rs",
        "apps/signer-firmware/src/hw/waveshare/display.rs",
    }),
}


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    source = re.sub(r"(?m)^\s*//.*$", "", source)
    return source


def _normalized_lines(path: Path) -> list[str]:
    source = _strip_comments(path.read_text(errors="ignore"))
    lines: list[str] = []
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(r"^(?:use|mod|pub\s+mod|import|export\s+\{).*", line):
            continue
        line = re.sub(r'"(?:\\.|[^"\\])*"', '"<string>"', line)
        line = re.sub(r"'(?:\\.|[^'\\])*'", "'<string>'", line)
        line = re.sub(r"\b\d+(?:\.\d+)?\b", "<number>", line)
        line = re.sub(r"\s+", " ", line)
        lines.append(line)
    return lines


def _shingles(lines: list[str]) -> set[tuple[str, ...]]:
    if len(lines) < SHINGLE_SIZE:
        return set()
    return {
        tuple(lines[index:index + SHINGLE_SIZE])
        for index in range(len(lines) - SHINGLE_SIZE + 1)
    }


def _candidate_pairs(normalized: dict[Path, list[str]]) -> set[tuple[Path, Path]]:
    owners: dict[tuple[str, ...], list[Path]] = defaultdict(list)
    for path, lines in normalized.items():
        for shingle in _shingles(lines):
            owners[shingle].append(path)

    shared_counts: dict[tuple[Path, Path], int] = defaultdict(int)
    for paths in owners.values():
        unique_paths = sorted(set(paths))
        if len(unique_paths) > MAX_COMMON_SHINGLE_FILES:
            continue
        for left, right in combinations(unique_paths, 2):
            shared_counts[(left, right)] += 1

    candidates: set[tuple[Path, Path]] = set()
    for pair, shared in shared_counts.items():
        smaller = min(len(normalized[pair[0]]), len(normalized[pair[1]]))
        if shared >= max(6, int(smaller * 0.18)):
            candidates.add(pair)
    return candidates



def _intentional_adapter_pair(root: Path, left: Path, right: Path) -> bool:
    pair = frozenset({_relative(root, left), _relative(root, right)})
    if pair not in INTENTIONAL_ADAPTER_PAIRS:
        return False
    sources = [path.read_text(errors="ignore") for path in (left, right)]
    return (
        "ILI9342C" in sources[0] + sources[1]
        and "ST7789" in sources[0] + sources[1]
        and "PanelDisplay" in sources[0]
        and "PanelDisplay" in sources[1]
    )


def _thin_shared_boundary_pair(left: Path, right: Path) -> bool:
    """Ignore thin family adapters that delegate all planning to shared helpers."""
    sources = [path.read_text(errors="ignore") for path in (left, right)]
    return all(
        "create_withdrawal(" in source
        and "create_topup(" in source
        and "build_withdrawal(" not in source
        and "build_topup(" not in source
        for source in sources
    )

def check(root: Path) -> list[str]:
    normalized = {
        path: lines
        for path in production_sources(root)
        if path.relative_to(root).as_posix() not in MODULE_SIZE_EXEMPTIONS
        and path.name != "registers.rs"
        and len(lines := _normalized_lines(path)) >= MIN_NORMALIZED_LINES
    }
    warnings: list[str] = []
    for left, right in sorted(_candidate_pairs(normalized)):
        if _thin_shared_boundary_pair(left, right) or _intentional_adapter_pair(root, left, right):
            continue
        left_lines = normalized[left]
        right_lines = normalized[right]
        matcher = SequenceMatcher(None, left_lines, right_lines, autojunk=False)
        matching = sum(block.size for block in matcher.get_matching_blocks())
        smaller = min(len(left_lines), len(right_lines))
        coverage = matching / smaller
        similarity = matcher.ratio()
        if (
            matching >= MIN_MATCHING_LINES
            and coverage >= MIN_SMALLER_FILE_COVERAGE
            and similarity >= MIN_SIMILARITY
        ):
            warnings.append(
                "ARCH-W004 possible duplicate implementations: "
                f"{_relative(root, left)} <-> {_relative(root, right)} "
                f"({similarity:.0%} similarity, {coverage:.0%} smaller-file coverage)"
            )
    return warnings
