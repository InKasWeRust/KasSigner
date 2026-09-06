"""Repository source-inventory regression gate.

Tracks the expected repository path inventory without hashing file contents.
Generated/runtime trees are intentionally excluded so normal builds do not
change the baseline.
"""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path

INVENTORY_RELATIVE = Path("qa/baselines/repository_inventory.txt")
EXCLUDED_TOP_LEVEL = {".git", "release", "target"}

FORBIDDEN_LOCAL_DIRS = {".idea", ".vscode"}
FORBIDDEN_LOCAL_FILE_NAMES = {"local.properties"}
FORBIDDEN_LOCAL_SUFFIXES = {".iml", ".ipr", ".iws"}
ANDROID_LOCAL_ROOT = Path("apps/kassee-android")


def _generated_top_level(name: str) -> bool:
    """Return True for runner-owned top-level scratch directories.

    The reproducible build historically staged default output as
    ``release.tmp.<pid>``. Interrupted/concurrent builds must never look like
    source additions to the repository inventory gate. Keep the match narrow
    so a real source directory such as ``release.tmp.docs`` is still reviewed.
    """
    for prefix in ("release.tmp.", ".release.tmp."):
        if name.startswith(prefix) and name[len(prefix):].isdigit():
            return True
    return False
EXCLUDED_ANYWHERE = {"__pycache__", ".pytest_cache", ".build", ".swiftpm", "node_modules", "target"}
EXCLUDED_PREFIXES = (
    Path("apps/kassee-web/web/pkg"),
    Path("apps/kassee-android/.gradle"),
    Path("apps/kassee-android/.kotlin"),
    Path("apps/kassee-android/build"),
    Path("apps/kassee-android/app/build"),
)
EXCLUDED_FILES = {Path("qa/fuzz/Cargo.lock")}

Decision = Callable[[str, str], int]


def _android_machine_local(relative: Path) -> bool:
    if relative != ANDROID_LOCAL_ROOT and ANDROID_LOCAL_ROOT not in relative.parents:
        return False
    return (
        any(part in FORBIDDEN_LOCAL_DIRS for part in relative.parts[len(ANDROID_LOCAL_ROOT.parts):])
        or relative.name in FORBIDDEN_LOCAL_FILE_NAMES
        or relative.suffix in FORBIDDEN_LOCAL_SUFFIXES
    )


def _excluded(relative: Path) -> bool:
    if _android_machine_local(relative):
        return True
    if relative.parts and (
        relative.parts[0] in EXCLUDED_TOP_LEVEL
        or _generated_top_level(relative.parts[0])
    ):
        return True
    if any(part in EXCLUDED_ANYWHERE for part in relative.parts):
        return True
    if relative in EXCLUDED_FILES:
        return True
    return any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES)


def _forbidden_local_paths(root: Path) -> tuple[Path, ...]:
    """Return IDE/machine-local state that must never enter a source archive."""
    forbidden: set[Path] = set()
    for current, directories, filenames in os.walk(root):
        current_path = Path(current)
        relative_parent = current_path.relative_to(root)
        retained_directories = []
        for name in directories:
            relative = relative_parent / name
            if name in FORBIDDEN_LOCAL_DIRS:
                if not _android_machine_local(relative):
                    forbidden.add(relative)
            elif not _excluded(relative):
                retained_directories.append(name)
        directories[:] = retained_directories
        for name in filenames:
            relative = relative_parent / name
            path = current_path / name
            if _excluded(relative):
                continue
            if name in FORBIDDEN_LOCAL_FILE_NAMES or path.suffix in FORBIDDEN_LOCAL_SUFFIXES:
                forbidden.add(relative)
    return tuple(sorted(forbidden, key=lambda value: (len(value.parts), value.as_posix())))


def _forbidden_errors(root: Path) -> list[str]:
    paths = _forbidden_local_paths(root)
    if not paths:
        return []
    roots: list[Path] = []
    for relative in paths:
        if any(parent == relative or parent in relative.parents for parent in roots):
            continue
        roots.append(relative)
    return [
        f"forbidden local-development state {relative.as_posix()}; remove it before running QA"
        for relative in roots
    ]


def _entry(relative: Path, path: Path) -> str:
    if path.is_symlink():
        kind = "L"
    elif path.is_dir():
        kind = "D"
    elif path.is_file():
        kind = "F"
    else:
        kind = "O"
    return f"{kind}\t{relative.as_posix()}"


def scan(root: Path) -> tuple[str, ...]:
    entries = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if not _excluded(relative):
            entries.append(_entry(relative, path))
    return tuple(sorted(entries))


def _load(inventory_path: Path) -> tuple[str, ...]:
    if not inventory_path.is_file():
        return ()
    return tuple(
        line for line in inventory_path.read_text(errors="strict").splitlines()
        if line.strip()
    )


def _differences(root: Path) -> tuple[Path, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    inventory_path = root / INVENTORY_RELATIVE
    expected = _load(inventory_path)
    current = scan(root)
    expected_set = set(expected)
    current_set = set(current)
    missing = tuple(sorted(expected_set - current_set))
    added = tuple(sorted(current_set - expected_set))
    return inventory_path, expected, missing, added


def _parts(entry: str) -> tuple[str, Path]:
    kind, relative = entry.split("\t", 1)
    return kind, Path(relative)


def _describe(entry: str) -> str:
    kind, relative = _parts(entry)
    label = {"D": "directory", "F": "file", "L": "symlink", "O": "path"}.get(kind, "path")
    return f"{label} {relative.as_posix()}"


def _ordered(entries: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(entries, key=lambda entry: (len(_parts(entry)[1].parts), _parts(entry)[0] != "D", entry)))


def _covered(relative: Path, handled_directories: list[Path]) -> bool:
    return any(relative == directory or directory in relative.parents for directory in handled_directories)


def check(root: Path) -> list[str]:
    forbidden = _forbidden_errors(root)
    if forbidden:
        return forbidden
    inventory_path, expected, missing, added = _differences(root)
    if not inventory_path.is_file():
        return [f"repository inventory baseline is missing: {INVENTORY_RELATIVE.as_posix()}"]
    errors = [f"repository inventory missing tracked {_describe(entry)}" for entry in missing]
    errors.extend(f"repository inventory found untracked {_describe(entry)}" for entry in added)
    if not expected:
        errors.append("repository inventory baseline is empty")
    return errors


def reconcile(root: Path, decide: Decision) -> list[str]:
    forbidden = _forbidden_errors(root)
    if forbidden:
        return forbidden
    inventory_path, expected, missing, added = _differences(root)
    if not inventory_path.is_file():
        return [f"repository inventory baseline is missing: {INVENTORY_RELATIVE.as_posix()}"]

    updated = set(expected)
    changed = False
    handled_missing: list[Path] = []
    for entry in _ordered(missing):
        kind, relative = _parts(entry)
        if _covered(relative, handled_missing):
            continue
        decision = decide("missing", _describe(entry))
        if decision == 0:
            updated = {
                candidate for candidate in updated
                if not _covered(_parts(candidate)[1], [relative])
            }
            changed = True
        elif decision != 1:
            return [f"invalid repository inventory decision for {_describe(entry)}"]
        if kind == "D":
            handled_missing.append(relative)

    handled_added: list[Path] = []
    added_set = set(added)
    for entry in _ordered(added):
        kind, relative = _parts(entry)
        if _covered(relative, handled_added):
            continue
        decision = decide("new", _describe(entry))
        if decision == 0:
            updated.update(
                candidate for candidate in added_set
                if _covered(_parts(candidate)[1], [relative])
            )
            changed = True
        elif decision != 1:
            return [f"invalid repository inventory decision for {_describe(entry)}"]
        if kind == "D":
            handled_added.append(relative)

    if changed:
        inventory_path.write_text("\n".join(sorted(updated)) + "\n")
    return []
