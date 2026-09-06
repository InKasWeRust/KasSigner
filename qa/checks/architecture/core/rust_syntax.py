"""Lightweight Rust lexical integrity checks used before an equipped Cargo build."""

from __future__ import annotations

from pathlib import Path
import re

EXCLUDED_PARTS = {".git", "target", "external", "vendor", "generated", "node_modules"}
DELIMITER_PAIRS = {")": "(", "]": "[", "}": "{"}
OPEN_DELIMITERS = set(DELIMITER_PAIRS.values())


def _location(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    previous_newline = source.rfind("\n", 0, offset)
    return line, offset - previous_newline


def _raw_string_start(source: str, offset: int) -> tuple[int, int] | None:
    """Return the opening quote offset and hash count for an r###" string."""
    if source[offset] != "r":
        return None
    cursor = offset + 1
    while cursor < len(source) and source[cursor] == "#":
        cursor += 1
    if cursor >= len(source) or source[cursor] != '"':
        return None
    return cursor, cursor - offset - 1


def _is_character_literal(source: str, offset: int) -> bool:
    """Distinguish short character literals from Rust lifetime apostrophes."""
    cursor = offset + 1
    if cursor >= len(source) or source[cursor] in "\r\n":
        return False
    if source[cursor] == "\\":
        cursor += 2
        if cursor < len(source) and source[cursor] == "u" and cursor + 1 < len(source):
            if source[cursor + 1] == "{":
                closing = source.find("}", cursor + 2)
                if closing < 0:
                    return False
                cursor = closing + 1
    else:
        cursor += 1
    return cursor < len(source) and source[cursor] == "'"


def _delimiter_error(source: str) -> tuple[str, int, int] | None:
    stack: list[tuple[str, int]] = []
    offset = 0
    block_comment_depth = 0
    state = "code"
    raw_hashes = 0

    while offset < len(source):
        char = source[offset]
        if state == "line-comment":
            if char == "\n":
                state = "code"
            offset += 1
            continue
        if state == "block-comment":
            if source.startswith("/*", offset):
                block_comment_depth += 1
                offset += 2
            elif source.startswith("*/", offset):
                block_comment_depth -= 1
                offset += 2
                if block_comment_depth == 0:
                    state = "code"
            else:
                offset += 1
            continue
        if state in {"string", "character"}:
            terminator = '"' if state == "string" else "'"
            if char == "\\":
                offset += 2
            else:
                if char == terminator:
                    state = "code"
                offset += 1
            continue
        if state == "raw-string":
            terminator = '"' + "#" * raw_hashes
            closing = source.find(terminator, offset)
            if closing < 0:
                line, column = _location(source, offset)
                return "unclosed raw string", line, column
            offset = closing + len(terminator)
            state = "code"
            continue

        if source.startswith("//", offset):
            state = "line-comment"
            offset += 2
            continue
        if source.startswith("/*", offset):
            state = "block-comment"
            block_comment_depth = 1
            offset += 2
            continue
        raw_start = _raw_string_start(source, offset)
        if raw_start is not None:
            quote_offset, raw_hashes = raw_start
            state = "raw-string"
            offset = quote_offset + 1
            continue
        if char == '"':
            state = "string"
            offset += 1
            continue
        if char == "'" and _is_character_literal(source, offset):
            state = "character"
            offset += 1
            continue
        if char in OPEN_DELIMITERS:
            stack.append((char, offset))
        elif char in DELIMITER_PAIRS:
            if not stack:
                line, column = _location(source, offset)
                return f"unmatched {char}", line, column
            opening, opening_offset = stack.pop()
            if opening != DELIMITER_PAIRS[char]:
                line, column = _location(source, opening_offset)
                return f"mismatched {opening} and {char}", line, column
        offset += 1

    if state == "block-comment":
        line, column = _location(source, max(0, len(source) - 1))
        return "unclosed block comment", line, column
    if state == "string":
        line, column = _location(source, max(0, len(source) - 1))
        return "unclosed string literal", line, column
    if state == "character":
        line, column = _location(source, max(0, len(source) - 1))
        return "unclosed character literal", line, column
    if stack:
        opening, opening_offset = stack[-1]
        line, column = _location(source, opening_offset)
        return f"unclosed {opening}", line, column
    return None



def _function_declaration_errors(path: Path, source: str, root: Path) -> list[str]:
    """Reject malformed Rust function names before Cargo is available.

    A Rust function name is one identifier.  A stray prose token between that
    identifier and the parameter list (for example ``fn foo APIs()``) is a
    syntax error that balanced-delimiter checks cannot detect.
    """
    errors: list[str] = []
    malformed = re.compile(
        r"(?m)^\s*(?:(?:pub(?:\([^)]*\))?|async|const|unsafe|extern(?:\s+\"[^\"]+\")?)\s+)*"
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()"
    )
    for match in malformed.finditer(source):
        line, column = _location(source, match.start(2))
        errors.append(
            f"Rust malformed function declaration: {path.relative_to(root)}:{line}:{column}: "
            f"unexpected token '{match.group(2)}' after function name '{match.group(1)}'"
        )
    return errors


def _module_import_errors(path: Path, source: str, root: Path) -> list[str]:
    errors: list[str] = []
    relative = path.relative_to(root)

    # A child module importing super::<its own stem> resolves to itself rather
    # than the sibling subsystem that was usually intended.
    stem = path.stem
    if stem != "mod":
        direct = re.compile(rf"(?m)^\s*use\s+super::{re.escape(stem)}\s*;")
        grouped = re.compile(rf"(?m)^\s*use\s+super::\{{[^}}]*\b{re.escape(stem)}\b[^}}]*\}}\s*;")
        if direct.search(source) or grouped.search(source):
            errors.append(
                f"Rust child module imports its own name through super: {relative} ({stem})"
            )

    # Parent modules may import child functions only when the child exposes
    # deliberate parent visibility.
    child_modules = set(re.findall(r"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", source))
    for child in child_modules:
        child_path = path.parent / f"{child}.rs"
        if not child_path.exists():
            child_path = path.parent / child / "mod.rs"
        if not child_path.exists():
            continue
        child_source = child_path.read_text(errors="replace")
        patterns = (
            rf"(?m)^\s*use\s+(?:self::)?{re.escape(child)}::([A-Za-z_][A-Za-z0-9_]*)\s*;",
            rf"(?m)^\s*use\s+(?:self::)?{re.escape(child)}::\{{([^}}]+)\}}\s*;",
        )
        symbols: set[str] = set()
        for match in re.finditer(patterns[0], source):
            symbols.add(match.group(1))
        for match in re.finditer(patterns[1], source):
            for item in match.group(1).split(','):
                name = item.strip().split(' as ')[0].strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    symbols.add(name)
        for symbol in symbols:
            private_fn = re.search(
                rf"(?m)^\s*fn\s+{re.escape(symbol)}\s*\(", child_source
            )
            if private_fn:
                errors.append(
                    f"parent imports private child function: {relative} -> "
                    f"{child_path.relative_to(root)}::{symbol}"
                )
    return errors

def check(root: Path) -> list[str]:
    errors: list[str] = []
    for source_root in (root / "apps", root / "crates", root / "tools", root / "qa"):
        if not source_root.exists():
            continue
        for path in source_root.rglob("*.rs"):
            if any(part in EXCLUDED_PARTS for part in path.parts):
                continue
            source = path.read_text(errors="replace")
            errors.extend(_module_import_errors(path, source, root))
            errors.extend(_function_declaration_errors(path, source, root))
            error = _delimiter_error(source)
            if error is not None:
                description, line, column = error
                errors.append(
                    f"Rust lexical integrity failure: {path.relative_to(root)}:{line}:{column}: "
                    f"{description}"
                )
    return errors
