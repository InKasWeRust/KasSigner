"""Shared parsers used by multiple architecture checks."""

from __future__ import annotations

import re
from pathlib import Path, PurePath


IGNORED_TREE_PARTS = {
    ".git",
    "node_modules",
    "target",
    "vendor",
    "generated",
    "dist",
}


def relative_posix(path: PurePath, root: PurePath) -> str:
    """Return a repository-relative path with stable POSIX separators."""
    return path.relative_to(root).as_posix()


def has_exact_child(directory: Path, name: str) -> bool:
    """Return whether a directory contains an entry with exactly this spelling."""
    try:
        return any(entry.name == name for entry in directory.iterdir())
    except OSError:
        return False


GENERATED_PREFIXES = (
    Path("apps/kassee-web/web/pkg"),
    Path("apps/kassee-android/.kotlin"),
    Path("apps/kassee-android/build"),
    Path("apps/kassee-android/app/build"),
)


def is_generated_tree(path: Path, root: Path) -> bool:
    """Return whether a path is generated or dependency-owned build output."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    if any(relative == prefix or prefix in relative.parents for prefix in GENERATED_PREFIXES):
        return True
    return any(part in IGNORED_TREE_PARTS for part in relative.parts)

def _rust_char_literal_end(source: str, index: int) -> int | None:
    """Return a char literal's closing quote, without mistaking lifetimes for chars."""
    cursor = index + 1
    if cursor >= len(source) or source[cursor] in "\r\n'":
        return None
    if source[cursor] == "\\":
        cursor += 1
        if cursor >= len(source):
            return None
        escape = source[cursor]
        if escape == "x":
            cursor += 3
        elif escape == "u" and cursor + 1 < len(source) and source[cursor + 1] == "{":
            closing = source.find("}", cursor + 2)
            if closing == -1:
                return None
            cursor = closing + 1
        else:
            cursor += 1
    else:
        cursor += 1
    return cursor if cursor < len(source) and source[cursor] == "'" else None

def _rust_raw_string_start(source: str, index: int) -> tuple[int, int] | None:
    """Return `(opening_quote, hash_count)` for `r#"..."#` and byte variants."""
    cursor = index
    if source.startswith("br", cursor):
        cursor += 1
    if cursor >= len(source) or source[cursor] != "r":
        return None
    cursor += 1
    hash_start = cursor
    while cursor < len(source) and source[cursor] == "#":
        cursor += 1
    if cursor < len(source) and source[cursor] == '"':
        return cursor, cursor - hash_start
    return None

def _rust_body_opening(source: str, start: int) -> int | None:
    """Find a Rust function body without treating `[T; N]` as a declaration end."""
    parens = brackets = 0
    mode = "code"
    escaped = False
    block_depth = 0
    raw_hashes = 0
    index = start
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if mode == "code":
            raw = _rust_raw_string_start(source, index)
            if raw is not None:
                opening_quote, raw_hashes = raw
                mode = "raw_string"
                index = opening_quote
            elif char == '"':
                mode = "string"
            elif char == "'" and _rust_char_literal_end(source, index) is not None:
                mode = "char"
            elif char == "/" and following == "/":
                mode = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                mode = "block_comment"
                block_depth = 1
                index += 1
            elif char == "(":
                parens += 1
            elif char == ")":
                parens = max(0, parens - 1)
            elif char == "[":
                brackets += 1
            elif char == "]":
                brackets = max(0, brackets - 1)
            elif char == "{" and parens == 0 and brackets == 0:
                return index
            elif char == ";" and parens == 0 and brackets == 0:
                return None
        elif mode in {"string", "char"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (mode == "string" and char == '"') or (mode == "char" and char == "'"):
                mode = "code"
        elif mode == "raw_string":
            terminator = '"' + "#" * raw_hashes
            if source.startswith(terminator, index):
                index += len(terminator) - 1
                mode = "code"
        elif mode == "line_comment":
            if char == "\n":
                mode = "code"
        elif mode == "block_comment":
            if char == "/" and following == "*":
                block_depth += 1
                index += 1
            elif char == "*" and following == "/":
                block_depth -= 1
                index += 1
                if block_depth == 0:
                    mode = "code"
        index += 1
    return None

def balanced_body_closing(
    source: str,
    opening: int,
    *,
    javascript: bool = False,
    rust: bool = False,
) -> int | None:
    """Return a balanced body's closing brace for supported source languages."""
    depth = 0
    mode = "code"
    escaped = False
    block_depth = 0
    raw_hashes = 0
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if mode == "code":
            raw = _rust_raw_string_start(source, index) if rust else None
            if raw is not None:
                opening_quote, raw_hashes = raw
                mode = "raw_string"
                index = opening_quote
            elif char == '"':
                mode = "double"
            elif char == "'" and (javascript or (rust and _rust_char_literal_end(source, index) is not None)):
                mode = "single"
            elif javascript and char == "`":
                mode = "template"
            elif char == "/" and following == "/":
                mode = "line_comment"
                index += 1
            elif char == "/" and following == "*":
                mode = "block_comment"
                block_depth = 1
                index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
        elif mode in {"double", "single", "template"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (
                (mode == "double" and char == '"')
                or (mode == "single" and char == "'")
                or (mode == "template" and char == "`")
            ):
                mode = "code"
        elif mode == "raw_string":
            terminator = '"' + "#" * raw_hashes
            if source.startswith(terminator, index):
                index += len(terminator) - 1
                mode = "code"
        elif mode == "line_comment":
            if char == "\n":
                mode = "code"
        elif mode == "block_comment":
            if char == "/" and following == "*":
                block_depth += 1
                index += 1
            elif char == "*" and following == "/":
                block_depth -= 1
                index += 1
                if block_depth == 0:
                    mode = "code"
        index += 1
    return None

def rust_code_only(source: str) -> str:
    """Mask Rust comments and literals while preserving code positions and lines."""
    output = list(source)
    mode = "code"
    escaped = False
    block_depth = 0
    raw_hashes = 0
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if mode == "code":
            raw = _rust_raw_string_start(source, index)
            if raw is not None:
                opening_quote, raw_hashes = raw
                for cursor in range(index, opening_quote + 1):
                    output[cursor] = " "
                index = opening_quote
                mode = "raw_string"
            elif char == '"':
                output[index] = " "
                mode = "string"
            elif char == "'" and _rust_char_literal_end(source, index) is not None:
                output[index] = " "
                mode = "char"
            elif char == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 1
                mode = "line_comment"
            elif char == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 1
                block_depth = 1
                mode = "block_comment"
        elif mode in {"string", "char"}:
            if char != "\n":
                output[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (mode == "string" and char == '"') or (mode == "char" and char == "'"):
                mode = "code"
        elif mode == "raw_string":
            terminator = '"' + "#" * raw_hashes
            if char != "\n":
                output[index] = " "
            if source.startswith(terminator, index):
                for cursor in range(index, min(len(source), index + len(terminator))):
                    output[cursor] = " "
                index += len(terminator) - 1
                mode = "code"
        elif mode == "line_comment":
            if char == "\n":
                mode = "code"
            else:
                output[index] = " "
        elif mode == "block_comment":
            if char != "\n":
                output[index] = " "
            if char == "/" and following == "*":
                output[index + 1] = " "
                index += 1
                block_depth += 1
            elif char == "*" and following == "/":
                output[index + 1] = " "
                index += 1
                block_depth -= 1
                if block_depth == 0:
                    mode = "code"
        index += 1
    return "".join(output)

def _top_level_parts(source: str) -> list[str]:
    """Split a Rust use-tree group on commas outside nested groups."""
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(source):
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(source[start:index].strip())
            start = index + 1
    tail = source[start:].strip()
    if tail:
        parts.append(tail)
    return parts

def _use_group_bounds(tree: str) -> tuple[int, int] | None:
    opening = tree.find("{")
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(tree)):
        if tree[index] == "{":
            depth += 1
        elif tree[index] == "}":
            depth -= 1
            if depth == 0:
                return opening, index
    return None

def _join_rust_path(prefix: str, suffix: str) -> str:
    left = prefix.strip().strip(":")
    right = suffix.strip().strip(":")
    if right == "self":
        return left
    if not left:
        return right
    if not right:
        return left
    return f"{left}::{right}"

def _expand_rust_use_tree(tree: str, prefix: str = "") -> set[str]:
    tree = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*\s*$", "", tree.strip())
    bounds = _use_group_bounds(tree)
    if bounds is None:
        path = _join_rust_path(prefix, tree)
        return {path} if path else set()
    opening, closing = bounds
    base = tree[:opening].rstrip().removesuffix("::")
    group_prefix = _join_rust_path(prefix, base)
    paths: set[str] = set()
    for member in _top_level_parts(tree[opening + 1:closing]):
        paths.update(_expand_rust_use_tree(member, group_prefix))
    suffix = tree[closing + 1:].strip()
    if suffix:
        paths = {_join_rust_path(path, suffix) for path in paths}
    return paths

def rust_use_paths(source: str) -> set[str]:
    """Expand direct and grouped Rust `use` declarations into full paths."""
    code = rust_code_only(source)
    paths: set[str] = set()
    for match in re.finditer(r"\buse\s+(?P<tree>[^;]+);", code, re.DOTALL):
        paths.update(_expand_rust_use_tree(match.group("tree")))
    return paths

def _rust_body_closing(source: str, opening: int) -> int | None:
    return balanced_body_closing(source, opening, rust=True)

def rust_function_lengths(
    source: str,
    *,
    include_indented: bool = False,
) -> list[tuple[str, int]]:
    """Return Rust function names and source lengths using balanced signatures/bodies."""
    indent = r"[ \t]*" if include_indented else ""
    pattern = re.compile(
        rf"(?m)^{indent}(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?"
        r"(?:unsafe\s+)?(?:extern\s+\"[^\"]+\"\s+)?fn\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)"
    )
    functions: list[tuple[str, int]] = []
    for match in pattern.finditer(source):
        opening = _rust_body_opening(source, match.end())
        if opening is None:
            continue
        closing = _rust_body_closing(source, opening)
        if closing is not None:
            functions.append(
                (match.group(1), source[match.start():closing + 1].count("\n") + 1)
            )
    return functions
