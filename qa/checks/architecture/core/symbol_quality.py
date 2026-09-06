"""Advisory internal-symbol and transitional-compatibility warnings."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from architecture.core.source_quality import production_sources


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


INTERNAL_SYMBOL_RE = re.compile(
    r"(?m)^(?P<visibility>pub(?:\((?:crate|super|self)\))?\s+)?"
    r"(?:const\s+|static\s+|struct\s+|enum\s+|(?:async\s+)?fn\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
INTERNAL_SYMBOL_EXEMPTIONS = {
    "main", "new", "default", "fmt", "drop", "from", "as_ref", "as_mut",
    "poll", "handle", "check", "clone", "eq", "cmp", "next", "into",
    "generate_constraints",
}
INTERNAL_SYMBOL_PATH_EXEMPTIONS = {
    "apps/signer-firmware/src/ui/prop_fonts.rs",
    "crates/offline-signer/src/derivation/bip39_wordlist.rs",
    # The covenant sweep adapter module is declared behind #[cfg(test)] in
    # wasm_api/contracts/covenant.rs; its helpers are intentionally test-only.
    "crates/online-watcher/src/wasm_api/contracts/covenant/sweep.rs",
}


def _is_internal_visibility(path: Path, visibility: str | None) -> bool:
    if visibility is None or "(" in visibility:
        return True
    return "apps/signer-firmware/src" in path.as_posix()


def _is_cfg_test_definition(source: str, start: int) -> bool:
    prefix = source[max(0, start - 160):start]
    return re.search(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*$", prefix) is not None


def _unused_internal_symbol_warnings(root: Path, paths: list[Path]) -> list[str]:
    rust_paths = [path for path in paths if path.suffix == ".rs"]
    combined_parts = [path.read_text(errors="ignore") for path in rust_paths]
    dockerfile = root / "Dockerfile"
    if dockerfile.is_file():
        combined_parts.append(dockerfile.read_text(errors="ignore"))
    combined = "\n".join(combined_parts)
    occurrences = Counter(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", combined))
    warnings: list[str] = []
    for path in rust_paths:
        if _relative(root, path) in INTERNAL_SYMBOL_PATH_EXEMPTIONS:
            continue
        source = path.read_text(errors="ignore")
        for match in INTERNAL_SYMBOL_RE.finditer(source):
            if _is_cfg_test_definition(source, match.start()):
                continue
            name = match.group("name")
            if name.startswith("_") or name in INTERNAL_SYMBOL_EXEMPTIONS:
                continue
            if not _is_internal_visibility(path, match.group("visibility")):
                continue
            if occurrences[name] != 1:
                continue
            line_number = source.count("\n", 0, match.start()) + 1
            warnings.append(
                f"ARCH-W009 possible unused internal Rust symbol: "
                f"{_relative(root, path)}:{line_number}::{name}"
            )
    return warnings


def _unused_javascript_symbol_warnings(root: Path, paths: list[Path]) -> list[str]:
    javascript_paths = [path for path in paths if path.suffix == ".js"]
    combined = "\n".join(path.read_text(errors="ignore") for path in javascript_paths)
    occurrences = Counter(re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", combined))
    patterns = (
        re.compile(r"(?m)^[ \t]*(?!export\s)(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\("),
        re.compile(
            r"(?m)^[ \t]*(?!export\s)(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>"
        ),
    )
    warnings: list[str] = []
    for path in javascript_paths:
        source = path.read_text(errors="ignore")
        for pattern in patterns:
            for match in pattern.finditer(source):
                name = match.group(1)
                if occurrences[name] != 1:
                    continue
                line_number = source.count("\n", 0, match.start()) + 1
                warnings.append(
                    f"ARCH-W009 possible unused internal JavaScript symbol: "
                    f"{_relative(root, path)}:{line_number}::{name}"
                )
    return warnings


def _temporary_compatibility_warnings(root: Path, paths: list[Path]) -> list[str]:
    warnings: list[str] = []
    phrases = re.compile(
        r"(?i)(?:temporary|transitional|legacy)\s+(?:compatibility\s+)?(?:alias|fallback)|"
        r"compatibility aliases used throughout"
    )
    exempt: set[str] = set()
    for path in paths:
        relative = _relative(root, path)
        if relative in exempt:
            continue
        source = path.read_text(errors="ignore")
        for match in phrases.finditer(source):
            line_number = source.count("\n", 0, match.start()) + 1
            warnings.append(
                f"ARCH-W010 temporary compatibility path requires removal plan: "
                f"{relative}:{line_number}"
            )
    return warnings



def _unused_registered_capability_warnings(root: Path) -> list[str]:
    """ARCH-W013 is retired because capability registries are forbidden by hard checks."""
    del root
    return []


def _balanced_block(source: str, opening: int) -> tuple[str, int] | None:
    depth = 0
    index = opening
    while index < len(source):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index], index
        index += 1
    return None


def _top_level_entries(body: str) -> list[str]:
    entries: list[str] = []
    current: list[str] = []
    depth = 0
    for char in body:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            entries.append("".join(current))
            current = []
        else:
            current.append(char)
    entries.append("".join(current))
    return entries


def _internal_enum_variant_warnings(root: Path, paths: list[Path]) -> list[str]:
    rust_paths = [path for path in paths if path.suffix == ".rs"]
    combined = "\n".join(path.read_text(errors="ignore") for path in rust_paths)
    counts = Counter(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", combined))
    enum_re = re.compile(r"(?m)^(?P<visibility>pub(?:\([^)]*\))?\s+)?enum\s+(?P<name>\w+)\s*\{")
    warnings: list[str] = []
    for path in rust_paths:
        source = path.read_text(errors="ignore")
        for match in enum_re.finditer(source):
            visibility = match.group("visibility") or ""
            if visibility == "pub " and "apps/signer-firmware/src" not in path.as_posix():
                continue
            parsed = _balanced_block(source, source.find("{", match.start(), match.end()))
            if parsed is None:
                continue
            body, _ = parsed
            for entry in _top_level_entries(body):
                lines = [
                    line for line in entry.splitlines()
                    if not line.strip().startswith(("///", "//!", "#["))
                ]
                variant = re.match(r"\s*([A-Z][A-Za-z0-9_]*)\b", "\n".join(lines))
                if variant is None or counts[variant.group(1)] != 1:
                    continue
                line = source.count("\n", 0, match.start()) + 1
                warnings.append(
                    "ARCH-W014 possible unused internal enum variant: "
                    f"{_relative(root, path)}:{line}::{match.group('name')}::{variant.group(1)}"
                )
    return warnings


def _initialized_unread_field_warnings(root: Path, paths: list[Path]) -> list[str]:
    rust_paths = [path for path in paths if path.suffix == ".rs"]
    combined = "\n".join(path.read_text(errors="ignore") for path in rust_paths)
    counts = Counter(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", combined))
    struct_re = re.compile(r"(?m)^(?P<visibility>pub(?:\([^)]*\))?\s+)?struct\s+(?P<name>\w+)(?:<[^>{}]*>)?\s*\{")
    warnings: list[str] = []
    for path in rust_paths:
        source = path.read_text(errors="ignore")
        for match in struct_re.finditer(source):
            visibility = match.group("visibility") or ""
            if visibility == "pub " and "apps/signer-firmware/src" not in path.as_posix():
                continue
            parsed = _balanced_block(source, source.find("{", match.start(), match.end()))
            if parsed is None:
                continue
            body, _ = parsed
            for field in re.finditer(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?([a-z_][A-Za-z0-9_]*)\s*:", body):
                name = field.group(1)
                if name.startswith("_") or counts[name] > 2 or re.search(rf"\.{re.escape(name)}\b", combined):
                    continue
                line = source.count("\n", 0, match.start()) + body.count("\n", 0, field.start()) + 1
                warnings.append(
                    "ARCH-W015 possible initialized-but-unread internal field: "
                    f"{_relative(root, path)}:{line}::{match.group('name')}::{name}"
                )
    return warnings


def _unreachable_app_state_warnings(root: Path, paths: list[Path]) -> list[str]:
    """ARCH-W016 retired: hard production-root graph validation owns reachability."""
    del root, paths
    return []


def check(root: Path) -> list[str]:
    paths = production_sources(root)
    return sorted([
        *_unused_internal_symbol_warnings(root, paths),
        *_unused_javascript_symbol_warnings(root, paths),
        *_temporary_compatibility_warnings(root, paths),
        *_unused_registered_capability_warnings(root),
        *_internal_enum_variant_warnings(root, paths),
        *_initialized_unread_field_warnings(root, paths),
        *_unreachable_app_state_warnings(root, paths),
    ])
