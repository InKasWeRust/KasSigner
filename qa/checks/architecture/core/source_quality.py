"""Blocking source-quality limits for production modules and folders."""

from __future__ import annotations

from pathlib import Path
import re

from architecture.core.common import balanced_body_closing, is_generated_tree, rust_function_lengths

MAX_FUNCTION_LINES = 200
MAX_MODULE_LINES = 450
MAX_FILES_PER_DIRECTORY = 12
SOURCE_SUFFIXES = {".rs", ".js"}
MODULE_SOURCE_SUFFIXES = {".rs", ".js", ".py", ".sh"}
DIRECTORY_SOURCE_SUFFIXES = {".rs", ".js", ".html", ".css", ".py", ".sh"}
MODULE_SIZE_EXEMPTIONS = {
    "apps/kassee-web/web/lib/jsQR.js",
    "apps/kassee-web/web/constellation/js/main.js",
    "apps/signer-firmware/src/ui/prop_fonts.rs",
    "crates/offline-signer/src/derivation/bip39_wordlist.rs",
}
EXCLUDED_PARTS = {
    ".git",
    "node_modules",
    "target",
    "external",
    "vendor",
    "generated",
    "dist",
}

def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()

def _is_excluded(path: Path, root: Path) -> bool:
    return is_generated_tree(path, root) or any(part in EXCLUDED_PARTS for part in path.parts)

def production_sources(root: Path) -> list[Path]:
    """Return authored production Rust and JavaScript sources."""
    roots = [
        root / "apps/signer-firmware/src",
        root / "crates",
        root / "apps/kassee-web/web/js",
        root / "apps/kassee-web/web/constellation/js/source",
    ]
    paths: set[Path] = set()
    for source_root in roots:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            if (
                path.is_file()
                and path.suffix in SOURCE_SUFFIXES
                and not _is_excluded(path, root)
                and "unit_tests" not in path.parts
                and "tests" not in path.parts
            ):
                paths.add(path)
    return sorted(paths)

def _javascript_function_lengths(source: str) -> list[tuple[str, int]]:
    patterns = (
        re.compile(
            r"(?m)^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+"
            r"([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"
        ),
        re.compile(
            r"(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*="
            r"\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{"
        ),
        re.compile(
            r"(?m)^[ \t]*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*\{"
        ),
    )
    matches: dict[int, tuple[str, int]] = {}
    reserved = {"catch", "for", "if", "switch", "while", "with"}
    for pattern in patterns:
        for match in pattern.finditer(source):
            if match.group(1) in reserved:
                continue
            opening = source.find("{", match.start(), match.end() + 1)
            closing = balanced_body_closing(source, opening, javascript=True)
            if closing is not None:
                matches.setdefault(
                    match.start(),
                    (match.group(1), source[match.start():closing + 1].count("\n") + 1),
                )
    return list(matches.values())

def _large_function_warnings(root: Path, paths: list[Path]) -> list[str]:
    warnings: list[str] = []
    for path in paths:
        source = path.read_text(errors="ignore")
        functions = (
            rust_function_lengths(source, include_indented=True)
            if path.suffix == ".rs"
            else _javascript_function_lengths(source)
        )
        for name, lines in functions:
            if lines > MAX_FUNCTION_LINES:
                warnings.append(
                    f"ARCH-E001 production function exceeds {MAX_FUNCTION_LINES} lines: "
                    f"{_relative(root, path)}::{name} ({lines} lines)"
                )
    return warnings

def production_module_sources(root: Path) -> list[Path]:
    """Return authored production modules across application and tooling languages."""
    roots = [root / "apps", root / "crates", root / "tools", root / "scripts"]
    paths: set[Path] = set()
    for source_root in roots:
        if not source_root.exists():
            continue
        for path in source_root.rglob("*"):
            if (
                path.is_file()
                and path.suffix in MODULE_SOURCE_SUFFIXES
                and not _is_excluded(path, root)
                and "unit_tests" not in path.parts
                and "tests" not in path.parts
            ):
                paths.add(path)
    installer = root / "install.sh"
    if installer.is_file():
        paths.add(installer)
    return sorted(paths)

def _is_declarative_module(path: Path, source: str) -> bool:
    """Exempt data-heavy modules that intentionally contain little executable flow."""
    if path.name in {"registers.rs", "icon_data.rs", "bip39_wordlist.rs", "prop_fonts.rs"}:
        return True
    lines = [line.strip() for line in source.splitlines() if line.strip()]
    if len(lines) < 80:
        return False
    declarations = sum(
        line.startswith(("pub const ", "const ", "static ", "export const "))
        or line.startswith(("0x", "[", "]", "{", "}"))
        for line in lines
    )
    control = sum(bool(re.search(r"\b(?:if|for|while|match|switch|loop)\b", line)) for line in lines)
    return declarations / len(lines) >= 0.55 and control <= 3

def _large_module_warnings(root: Path, paths: list[Path]) -> list[str]:
    warnings: list[str] = []
    for path in paths:
        relative = _relative(root, path)
        source = path.read_text(errors="ignore")
        if relative in MODULE_SIZE_EXEMPTIONS or _is_declarative_module(path, source):
            continue
        line_count = len(source.splitlines())
        if line_count > MAX_MODULE_LINES:
            warnings.append(
                f"ARCH-E002 production module exceeds {MAX_MODULE_LINES} lines: "
                f"{relative} ({line_count} lines)"
            )
    return warnings

LINT_ATTRIBUTE_RE = re.compile(
    r"#(?P<inner>!)?\s*\[\s*(?P<kind>allow|expect)\s*\("
    r"(?P<body>.*?)\)\s*\]",
    re.S,
)

def _lint_attributes(source: str) -> list[tuple[re.Match[str], int, str]]:
    attributes: list[tuple[re.Match[str], int, str]] = []
    for match in LINT_ATTRIBUTE_RE.finditer(source):
        line_number = source.count("\n", 0, match.start()) + 1
        snippet = re.sub(r"\s+", " ", match.group(0)).strip()
        attributes.append((match, line_number, snippet))
    return attributes

def _crate_lint_warnings(root: Path, paths: list[Path]) -> list[str]:
    warnings: list[str] = []
    firmware_root = root / "apps/signer-firmware"
    for path in paths:
        if path.suffix != ".rs" or firmware_root in path.parents:
            continue
        source = path.read_text(errors="ignore")
        for match, line_number, snippet in _lint_attributes(source):
            if match.group("inner"):
                warnings.append(
                    f"ARCH-E003 crate-wide lint suppression outside firmware: "
                    f"{_relative(root, path)}:{line_number}: {snippet}"
                )
    return warnings

def _directory_sources(root: Path) -> list[Path]:
    roots = [
        root / "apps",
        root / "crates",
        root / "qa/checks/architecture",
    ]
    paths: list[Path] = []
    for source_root in roots:
        if not source_root.exists():
            continue
        paths.extend(
            path for path in source_root.rglob("*")
            if path.is_file()
            and path.suffix in DIRECTORY_SOURCE_SUFFIXES
            and not _is_excluded(path, root)
            and "unit_tests" not in path.parts
            and "tests" not in path.parts
        )
    return sorted(set(paths))

def _crowded_directory_warnings(root: Path) -> list[str]:
    counts: dict[Path, int] = {}
    for path in _directory_sources(root):
        counts[path.parent] = counts.get(path.parent, 0) + 1
    return [
        f"ARCH-E005 directory contains more than {MAX_FILES_PER_DIRECTORY} direct source files: "
        f"{_relative(root, directory)} ({count} files)"
        for directory, count in sorted(counts.items(), key=lambda item: item[0].as_posix())
        if count > MAX_FILES_PER_DIRECTORY
    ]

def _deprecated_suppression_warnings(root: Path, paths: list[Path]) -> list[str]:
    warnings: list[str] = []
    for path in paths:
        if path.suffix != ".rs":
            continue
        source = path.read_text(errors="ignore")
        for match, line_number, snippet in _lint_attributes(source):
            if re.search(r"\bdeprecated\b", match.group("body")):
                warnings.append(
                    f"ARCH-E007 deprecated API suppression requires migration: "
                    f"{_relative(root, path)}:{line_number}: {snippet}"
                )
    return warnings


def _ignored_function_parameters(root: Path, paths: list[Path]) -> list[str]:
    """Reject underscore-prefixed function parameters in production Rust."""
    errors: list[str] = []
    function_pattern = re.compile(
        r"(?ms)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{}]*>)?\s*"
        r"\((?P<params>.*?)\)\s*(?:->[^\{]+)?\{"
    )
    ignored_pattern = re.compile(r"(?<![A-Za-z0-9_])(_[A-Za-z][A-Za-z0-9_]*)\s*:")
    for path in paths:
        if path.suffix != ".rs":
            continue
        source = path.read_text(errors="ignore")
        for function in function_pattern.finditer(source):
            for parameter in ignored_pattern.findall(function.group("params")):
                errors.append(
                    "production function parameter is ignored instead of removed: "
                    f"{_relative(root, path)}::{function.group('name')}::{parameter}"
                )
    return errors


def _unused_value_sink_warnings(root: Path, paths: list[Path]) -> list[str]:
    """Reject tuple sinks used to hide oversized production interfaces."""
    errors: list[str] = []
    sink_pattern = re.compile(r"(?m)^\s*let\s+_\s*=\s*\(")
    for path in paths:
        if path.suffix != ".rs":
            continue
        source = path.read_text(errors="ignore")
        for match in sink_pattern.finditer(source):
            line_number = source.count("\n", 0, match.start()) + 1
            errors.append(
                "production interface hides unused values with a tuple sink: "
                f"{_relative(root, path)}:{line_number}"
            )
    return errors


def _migration_residue_warnings(root: Path, paths: list[Path]) -> list[str]:
    """Reject comments that describe superseded source locations."""
    errors: list[str] = []
    residue_pattern = re.compile(r"(?im)^\s*(?://|/\*|\*)[^\n]*\bmoved out of\b")
    for path in paths:
        source = path.read_text(errors="ignore")
        for match in residue_pattern.finditer(source):
            line_number = source.count("\n", 0, match.start()) + 1
            errors.append(
                "production comment retains migration-history residue: "
                f"{_relative(root, path)}:{line_number}"
            )
    return errors



def check(root: Path) -> list[str]:
    paths = production_sources(root)
    module_paths = production_module_sources(root)
    warnings = [
        *_large_function_warnings(root, paths),
        *_large_module_warnings(root, module_paths),
        *_crate_lint_warnings(root, paths),
        *_crowded_directory_warnings(root),
        *_deprecated_suppression_warnings(root, paths),
        *_ignored_function_parameters(root, paths),
        *_unused_value_sink_warnings(root, paths),
        *_migration_residue_warnings(root, paths),
    ]
    return sorted(warnings)
