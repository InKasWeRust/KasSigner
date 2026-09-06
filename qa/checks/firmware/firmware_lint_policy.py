#!/usr/bin/env python3
"""Static policy for firmware lint exceptions.

The firmware intentionally compiles for several mutually exclusive ESP32-S3
boards and modes. Rust/Clippy exceptions are therefore permitted only on the
exact item that needs one, with a reviewable justification and a locked
registry entry. Crate- or file-wide suppression is forbidden.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE_SRC = ROOT / "apps/signer-firmware/src"
REGISTRY = ROOT / "qa/checks/firmware/firmware_lint_exceptions.json"

ALLOWED_LINTS = {
    "unused_variables",
    "unused_assignments",
    "unused_mut",
    "unused_unsafe",
    "clippy::too_many_arguments",
    "clippy::type_complexity",
    "clippy::too_many_lines",
    "clippy::cognitive_complexity",
    "clippy::struct_excessive_bools",
}
FORBIDDEN_LINTS = {"dead_code", "unused_imports"}
ALLOW_RE = re.compile(r"(?m)^(?P<indent>[ \t]*)#\[allow\((?P<lints>[^)]*)\)\]")
INNER_ALLOW_RE = re.compile(r"(?m)^\s*#!\[allow\(")
ITEM_RE = re.compile(
    r"^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)\b"
    r"|^let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\b"
)


@dataclass(frozen=True)
class ExceptionEntry:
    path: str
    item: str
    lints: tuple[str, ...]
    reason: str


def _previous_nonempty_line(source: str, offset: int) -> str:
    prefix = source[:offset].splitlines()
    for line in reversed(prefix):
        if line.strip():
            return line.strip()
    return ""


def _target_item(source: str, offset: int) -> str | None:
    """Return the item name immediately governed by an allow attribute."""
    lines = source[offset:].splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("///") or stripped.startswith("//!"):
            continue
        if stripped.startswith("#["):
            continue
        match = ITEM_RE.match(stripped)
        if not match:
            return None
        return next(group for group in match.groups() if group is not None)
    return None


def scan_exceptions(root: Path = ROOT) -> tuple[list[ExceptionEntry], list[str]]:
    firmware_src = root / "apps/signer-firmware/src"
    entries: list[ExceptionEntry] = []
    errors: list[str] = []

    for path in sorted(firmware_src.rglob("*.rs")):
        source = path.read_text(errors="ignore")
        relative = path.relative_to(root).as_posix()

        if INNER_ALLOW_RE.search(source):
            errors.append(f"crate/file-wide lint suppression is forbidden: {relative}")

        for match in ALLOW_RE.finditer(source):
            raw_lints = [part.strip() for part in match.group("lints").split(",") if part.strip()]
            lint_set = set(raw_lints)
            forbidden = sorted(lint_set & FORBIDDEN_LINTS)
            unknown = sorted(lint_set - ALLOWED_LINTS)
            if forbidden:
                errors.append(
                    f"dead/unused-import suppression is forbidden in {relative}: {forbidden}"
                )
            if unknown:
                errors.append(f"unregistered lint exception in {relative}: {unknown}")

            previous = _previous_nonempty_line(source, match.start())
            marker = "// LINT-JUSTIFICATION:"
            if not previous.startswith(marker):
                errors.append(
                    f"lint exception lacks immediate LINT-JUSTIFICATION in {relative}: "
                    f"{raw_lints}"
                )
                reason = ""
            else:
                reason = previous[len(marker):].strip()
                if len(reason) < 24:
                    errors.append(f"lint justification is too vague in {relative}: {reason!r}")

            item = _target_item(source, match.end())
            if item is None:
                errors.append(
                    f"lint exception must target one function, struct, or local binding: {relative}"
                )
                item = "<unknown>"

            entries.append(
                ExceptionEntry(
                    path=relative,
                    item=item,
                    lints=tuple(sorted(raw_lints)),
                    reason=reason,
                )
            )

    duplicate_keys: dict[tuple[str, str], int] = {}
    for entry in entries:
        key = (entry.path, entry.item)
        duplicate_keys[key] = duplicate_keys.get(key, 0) + 1
    for key, count in sorted(duplicate_keys.items()):
        if count > 1:
            errors.append(f"multiple lint exception attributes target {key[0]}::{key[1]}")

    return entries, errors


def check_policy(root: Path = ROOT) -> list[str]:
    entries, errors = scan_exceptions(root)
    main_source = (root / "apps/signer-firmware/src/main.rs").read_text(errors="ignore")
    if "#![deny(unused_imports)]" not in main_source:
        errors.append("firmware crate must deny unused_imports in every feature set")
    if "#![warn(dead_code)]" not in main_source:
        errors.append("firmware crate must retain dead-code diagnostics in every feature set")
    hil_dead_code_allow = '#![cfg_attr(feature = "hardware-tests", allow(dead_code))]'
    if hil_dead_code_allow in main_source:
        errors.append("hardware-tests dead-code suppression must not be crate-wide")
    scoped_hil_modules = (
        "boot/mod.rs", "controllers.rs", "crypto/mod.rs", "hw/mod.rs",
        "runtime/mod.rs", "services/mod.rs", "ui/mod.rs", "wallet/mod.rs",
    )
    firmware_src = root / "apps/signer-firmware/src"
    for relative in scoped_hil_modules:
        module_source = (firmware_src / relative).read_text(errors="ignore")
        if hil_dead_code_allow not in module_source:
            errors.append(f"hardware-tests dead-code suppression is missing from root module {relative}")
    if re.search(r"#!\s*\[.*allow\s*\(\s*dead_code\s*\).*\]", main_source):
        errors.append("firmware crate must not allow dead_code at crate scope")
    if "allow(unused_imports)" in main_source:
        errors.append("firmware crate must never allow unused_imports")

    clippy_config = root / "apps/signer-firmware/clippy.toml"
    if not clippy_config.exists():
        errors.append("firmware clippy.toml is missing")
    else:
        clippy_source = clippy_config.read_text(errors="ignore")
        for required in (
            "too-many-lines-threshold = 300",
            "cognitive-complexity-threshold = 80",
        ):
            if required not in clippy_source:
                errors.append(f"firmware clippy policy changed: missing {required}")

    matrix_path = root / "tools/build/firmware/build_matrix.py"
    required_features = (
        '"waveshare"',
        '"waveshare,silent"',
        '"waveshare,production"',
        '"waveshare,ov5640-af"',
        '"m5stack"',
        '"m5stack,silent"',
        '"m5stack,production"',
    )
    if not matrix_path.exists():
        errors.append("canonical firmware build matrix is missing")
    else:
        matrix_source = matrix_path.read_text(errors="ignore")
        for feature_set in required_features:
            if feature_set not in matrix_source:
                errors.append(f"firmware build matrix lost {feature_set}")

    build_runner = root / "qa/checks/firmware/check_firmware_builds.py"
    if not build_runner.exists():
        errors.append("firmware cargo-check matrix runner is missing")
    else:
        runner_source = build_runner.read_text(errors="ignore")
        if "from tools.build.firmware.matrix_runner import run_firmware_matrix" not in runner_source:
            errors.append("firmware build runner must reuse the shared matrix runner")
        if 'run_firmware_matrix(\n        "check"' not in runner_source:
            errors.append("firmware build matrix runner must invoke cargo check")

    lint_runner = root / "qa/checks/firmware/check_firmware_lints.py"
    if not lint_runner.exists():
        errors.append("firmware lint matrix runner is missing")
    else:
        runner_source = lint_runner.read_text(errors="ignore")
        if "from tools.build.firmware.matrix_runner import run_firmware_matrix" not in runner_source:
            errors.append("firmware lint runner must reuse the shared matrix runner")
        for enforced_lint in (
            '"unused_imports"',
            '"clippy::too_many_lines"',
            '"clippy::cognitive_complexity"',
            '"clippy::struct_excessive_bools"',
        ):
            if enforced_lint not in runner_source:
                errors.append(f"firmware lint runner no longer enforces {enforced_lint}")

    shared_runner = root / "tools/build/firmware/matrix_runner.py"
    if not shared_runner.exists():
        errors.append("shared firmware matrix runner is missing")
    else:
        shared_source = shared_runner.read_text(errors="ignore")
        if "from .build_matrix import FEATURE_MATRIX" not in shared_source:
            errors.append("shared firmware runner must use the canonical build matrix")
        if '"cargo",\n            operation' not in shared_source:
            errors.append("shared firmware runner must invoke the selected cargo operation")

    registry_path = root / "qa/checks/firmware/firmware_lint_exceptions.json"
    if not registry_path.exists():
        errors.append("firmware lint exception registry is missing")
        return errors

    registry_data = json.loads(registry_path.read_text())
    expected = {
        (
            item["path"],
            item["item"],
            tuple(sorted(item["lints"])),
            item["reason"],
        )
        for item in registry_data.get("exceptions", [])
    }
    actual = {(e.path, e.item, e.lints, e.reason) for e in entries}

    for missing in sorted(expected - actual):
        errors.append(f"registered firmware lint exception disappeared or changed: {missing}")
    for added in sorted(actual - expected):
        errors.append(f"unreviewed firmware lint exception added: {added}")

    if len(actual) != len(entries):
        errors.append("firmware lint registry contains duplicate exception records")

    return errors


def main() -> int:
    errors = check_policy(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    entries, _ = scan_exceptions(ROOT)
    print(
        "PASS: firmware denies unused imports, keeps dead-code diagnostics enabled in every feature set, and has "
        f"{len(entries)} item-scoped lint exceptions"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
