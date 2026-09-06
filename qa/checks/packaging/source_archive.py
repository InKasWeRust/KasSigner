#!/usr/bin/env python3
"""Build and validate flat KasSigner source archives from the tracked inventory.

The repository inventory is the source allowlist. This deliberately avoids broad
archive exclusions such as ``*/build/*`` because KasSigner has source-controlled
build tooling under ``scripts/*/build`` and ``tools/build``.
"""
from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[3]
CHECKS = ROOT / "qa" / "checks"
if str(CHECKS) not in sys.path:
    sys.path.insert(0, str(CHECKS))

from architecture.core.inventory import repository_inventory  # noqa: E402

ARCHIVE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

PLATFORM_SPECS = (
    ("linux", ".sh"),
    ("windows", ".ps1"),
)


def _inventory_entries(root: Path) -> tuple[str, ...]:
    inventory = root / repository_inventory.INVENTORY_RELATIVE
    if not inventory.is_file():
        raise ValueError(
            f"repository inventory baseline is missing: {repository_inventory.INVENTORY_RELATIVE}"
        )
    entries = tuple(line for line in inventory.read_text(encoding="utf-8").splitlines() if line.strip())
    if not entries:
        raise ValueError("repository inventory baseline is empty")
    return entries


def _split(entry: str) -> tuple[str, PurePosixPath]:
    kind, relative = entry.split("\t", 1)
    return kind, PurePosixPath(relative)


def _entrypoints_from_source(source: str, label: str) -> dict[str, str]:
    tree = ast.parse(source, filename=label)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "ENTRYPOINTS":
                    value = ast.literal_eval(node.value)
                    if not isinstance(value, dict) or not all(
                        isinstance(key, str) and isinstance(item, str)
                        for key, item in value.items()
                    ):
                        raise ValueError(f"{label}: ENTRYPOINTS must be a literal str->str mapping")
                    return value
    raise ValueError(f"{label}: ENTRYPOINTS mapping not found")


def _string_set_from_source(source: str, label: str, name: str) -> set[str]:
    tree = ast.parse(source, filename=label)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    value = ast.literal_eval(node.value)
                    if not isinstance(value, set) or not all(isinstance(item, str) for item in value):
                        raise ValueError(f"{label}: {name} must be a literal string set")
                    return value
    raise ValueError(f"{label}: {name} mapping not found")


def required_native_entrypoints(root: Path) -> set[PurePosixPath]:
    required: set[PurePosixPath] = set()
    relative = PurePosixPath("scripts/common/lib/make_tasks.py")
    source = (root / Path(relative)).read_text(encoding="utf-8")
    mapping = _entrypoints_from_source(source, relative.as_posix())
    for platform, suffix in PLATFORM_SPECS:
        for target in mapping.values():
            required.add(PurePosixPath(f"scripts/{platform}/{target}{suffix}"))
    for entry in _string_set_from_source(source, relative.as_posix(), "MAC_NATIVE_ENTRYPOINTS"):
        target = mapping.get(entry)
        if target is None:
            raise ValueError(f"{relative}: unknown macOS native entrypoint {entry}")
        required.add(PurePosixPath(f"scripts/mac/{target}.sh"))
    return required


def _zip_mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _write_directory(archive: zipfile.ZipFile, relative: PurePosixPath, path: Path) -> None:
    info = zipfile.ZipInfo(relative.as_posix().rstrip("/") + "/", date_time=ARCHIVE_TIMESTAMP)
    info.external_attr = (_zip_mode(path) | stat.S_IFDIR) << 16
    archive.writestr(info, b"")


def _write_symlink(archive: zipfile.ZipFile, relative: PurePosixPath, path: Path) -> None:
    info = zipfile.ZipInfo(relative.as_posix(), date_time=ARCHIVE_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | _zip_mode(path)) << 16
    archive.writestr(info, os.readlink(path).encode("utf-8"))


def _write_file(archive: zipfile.ZipFile, relative: PurePosixPath, path: Path) -> None:
    # Do not call ZipInfo.from_file() here. It converts the filesystem mtime
    # before callers can normalize it, so a source file with a pre-1980 mtime
    # raises ValueError even though every archive entry is intentionally stamped
    # at the deterministic DOS epoch below. Construct the entry from normalized
    # metadata first and preserve only the Unix file type/permission bits. This
    # keeps the existing timezone/clock-skew guarantee even when the extracted
    # filesystem reports an mtime outside the ZIP representable range.
    info = zipfile.ZipInfo(relative.as_posix(), date_time=ARCHIVE_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | _zip_mode(path)) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def _add_path(archive: zipfile.ZipFile, root: Path, kind: str, relative: PurePosixPath) -> None:
    path = root / Path(relative)
    if kind == "D":
        if not path.is_dir():
            raise ValueError(f"tracked source directory is missing before packaging: {relative}")
        _write_directory(archive, relative, path)
    elif kind == "F":
        if not path.is_file():
            raise ValueError(f"tracked source file is missing before packaging: {relative}")
        _write_file(archive, relative, path)
    elif kind == "L":
        if not path.is_symlink():
            raise ValueError(f"tracked source symlink is missing before packaging: {relative}")
        _write_symlink(archive, relative, path)
    else:
        raise ValueError(f"unsupported repository-inventory entry kind {kind!r}: {relative}")


def build_archive(root: Path, archive_path: Path) -> None:
    inventory_errors = repository_inventory.check(root)
    if inventory_errors:
        raise ValueError("working-tree inventory is not clean:\n" + "\n".join(inventory_errors))
    entries = _inventory_entries(root)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive_path.with_suffix(archive_path.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for entry in entries:
            kind, relative = _split(entry)
            _add_path(archive, root, kind, relative)
    temporary.replace(archive_path)


def validate_archive(root: Path, archive_path: Path) -> list[str]:
    errors: list[str] = []
    expected_entries = _inventory_entries(root)
    expected_files: set[PurePosixPath] = set()
    expected_dirs: set[PurePosixPath] = set()
    for entry in expected_entries:
        kind, relative = _split(entry)
        if kind == "D":
            expected_dirs.add(relative)
        elif kind in {"F", "L"}:
            expected_files.add(relative)

    if not archive_path.is_file():
        return [f"source archive is missing: {archive_path}"]

    try:
        with zipfile.ZipFile(archive_path) as archive:
            bad = archive.testzip()
            if bad is not None:
                errors.append(f"source archive CRC failure: {bad}")
            names = archive.namelist()
            files = {PurePosixPath(name.rstrip("/")) for name in names if not name.endswith("/")}
            dirs = {PurePosixPath(name.rstrip("/")) for name in names if name.endswith("/")}
            all_paths = files | dirs

            missing_files = sorted(expected_files - files, key=lambda item: item.as_posix())
            missing_dirs = sorted(expected_dirs - dirs, key=lambda item: item.as_posix())
            errors.extend(f"source archive missing tracked file {item}" for item in missing_files)
            errors.extend(f"source archive missing tracked directory {item}" for item in missing_dirs)

            expected_all = expected_files | expected_dirs
            extras = sorted(all_paths - expected_all, key=lambda item: item.as_posix())
            errors.extend(f"source archive contains untracked path {item}" for item in extras)

            for required in sorted(required_native_entrypoints(root), key=lambda item: item.as_posix()):
                if required not in files:
                    errors.append(f"source archive missing native Make entrypoint {required}")

            for critical in (
                PurePosixPath("scripts/linux/build/firmware-build.sh"),
                PurePosixPath("scripts/windows/build/firmware-build.ps1"),
                PurePosixPath("tools/build/firmware/build_with_hash.sh"),
            ):
                if critical not in files:
                    errors.append(f"source archive missing critical build source {critical}")

            top_level_names = {path.parts[0] for path in all_paths if path.parts}
            if "Makefile" not in top_level_names:
                errors.append("source archive is not flat: root Makefile is absent")
    except zipfile.BadZipFile as error:
        errors.append(f"source archive is not a valid ZIP: {error}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--write", action="store_true", help="build the archive from the repository inventory")
    args = parser.parse_args()
    archive = args.archive if args.archive.is_absolute() else ROOT / args.archive
    try:
        if args.write:
            build_archive(ROOT, archive)
        errors = validate_archive(ROOT, archive)
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(
        "PASS: flat source archive matches tracked repository inventory and all native Make entrypoints are present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
