#!/usr/bin/env python3
"""Merge scope-aligned cargo-crap legs into one repository report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")


def _load(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read cargo-crap report {path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        raise ValueError(f"cargo-crap report has no entries array: {path}")
    version = document.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"cargo-crap report has no version: {path}")
    return document


def _normalize_file(value: str, prefix: str | None) -> str:
    normalized = value.replace("\\", "/").removeprefix("./")
    if prefix is None:
        return normalized
    prefix = prefix.strip("/")
    if (
        normalized.startswith("/")
        or _WINDOWS_ABSOLUTE.match(normalized)
        or normalized == prefix
        or normalized.startswith(prefix + "/")
    ):
        return normalized
    return f"{prefix}/{normalized}"


def _validate_scope(document: dict[str, Any], label: str) -> None:
    diagnostics = document.get("diagnostics")
    if not isinstance(diagnostics, dict):
        raise ValueError(f"{label} CRAP report is missing LCOV scope diagnostics")
    source_only = diagnostics.get("source_only")
    lcov_only = diagnostics.get("lcov_only")
    if not isinstance(source_only, dict) or not isinstance(lcov_only, dict):
        raise ValueError(f"{label} CRAP scope diagnostics are incomplete")
    source_count = source_only.get("count")
    lcov_count = lcov_only.get("count")
    if source_count != 0 or lcov_count != 0:
        raise ValueError(
            f"{label} CRAP/LCOV scopes do not match exactly: "
            f"source_only={source_count!r}, lcov_only={lcov_count!r}"
        )


def merge_reports(
    host: dict[str, Any],
    firmware: dict[str, Any],
    kassee_web: dict[str, Any],
) -> dict[str, Any]:
    """Return one cargo-crap-compatible envelope for repository classification."""
    versions = {host.get("version"), firmware.get("version"), kassee_web.get("version")}
    if len(versions) != 1:
        raise ValueError(f"cargo-crap report versions differ: {sorted(str(v) for v in versions)}")

    _validate_scope(host, "root workspace")
    _validate_scope(kassee_web, "KasSee Web")
    if firmware.get("diagnostics") is not None:
        raise ValueError("firmware CRAP leg must be complexity-only and must not carry LCOV diagnostics")

    combined: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for document, prefix in (
        (host, None),
        (kassee_web, "apps/kassee-web"),
        (firmware, "apps/signer-firmware"),
    ):
        for raw in document["entries"]:
            if not isinstance(raw, dict):
                raise ValueError("cargo-crap report contains a non-object entry")
            item = dict(raw)
            file_name = item.get("file")
            function = item.get("function")
            line = item.get("line")
            if not isinstance(file_name, str) or not isinstance(function, str) or not isinstance(line, int):
                raise ValueError("cargo-crap entry has an invalid identity")
            item["file"] = _normalize_file(file_name, prefix)
            identity = (item["file"], function, line)
            if identity in seen:
                raise ValueError(f"duplicate cargo-crap function identity after merge: {identity}")
            seen.add(identity)
            combined.append(item)

    combined.sort(
        key=lambda entry: (
            -float(entry.get("crap", 0.0)),
            str(entry.get("file", "")),
            str(entry.get("function", "")),
            int(entry.get("line", 0)),
        )
    )
    result: dict[str, Any] = {"version": host["version"], "entries": combined}
    schema = host.get("$schema")
    if isinstance(schema, str):
        result["$schema"] = schema
    return result


def _write_human(output: Path, sections: list[tuple[str, Path]]) -> None:
    chunks = [
        "KasSigner CRAP report\n",
        "Coverage-backed scopes are scored only against their matching LCOV runs.\n"
        "ESP32-S3 firmware is complexity-only here because host LCOV cannot instrument Xtensa firmware; "
        "the repository firmware source-complexity/testability policy supplies its effective gate.\n",
    ]
    for label, path in sections:
        try:
            body = path.read_text(encoding="utf-8", errors="replace").rstrip()
        except OSError as error:
            raise ValueError(f"cannot read human CRAP report {path}: {error}") from error
        chunks.append(f"\n================================================================================\n{label}\n================================================================================\n{body}\n")
    output.write_text("\n".join(chunks), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-json", type=Path, required=True)
    parser.add_argument("--firmware-json", type=Path, required=True)
    parser.add_argument("--kassee-web-json", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--host-human", type=Path)
    parser.add_argument("--firmware-human", type=Path)
    parser.add_argument("--kassee-web-human", type=Path)
    parser.add_argument("--output-human", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        host = _load(args.host_json)
        firmware = _load(args.firmware_json)
        kassee_web = _load(args.kassee_web_json)
        merged = merge_reports(host, firmware, kassee_web)
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        human_values = (args.host_human, args.firmware_human, args.kassee_web_human, args.output_human)
        if any(value is not None for value in human_values):
            if not all(value is not None for value in human_values):
                raise ValueError("all human report arguments must be supplied together")
            assert args.host_human is not None
            assert args.firmware_human is not None
            assert args.kassee_web_human is not None
            assert args.output_human is not None
            _write_human(
                args.output_human,
                [
                    ("Root Cargo workspace (coverage-backed CRAP)", args.host_human),
                    ("KasSee Web Rust shell (coverage-backed CRAP)", args.kassee_web_human),
                    ("Signer firmware (complexity-only CRAP)", args.firmware_human),
                ],
            )
    except ValueError as error:
        print(f"ERROR: {error}")
        return 1
    print(f"PASS: merged {len(merged['entries'])} CRAP rows from aligned repository scopes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
