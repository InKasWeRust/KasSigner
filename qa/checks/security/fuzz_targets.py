#!/usr/bin/env python3
"""Read and validate the authoritative fuzz-target registry in qa/fuzz/Cargo.toml."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "qa/fuzz/Cargo.toml"
FUZZ_ROOT = ROOT / "qa/fuzz"
SURFACE_REGISTRY = ROOT / "qa/contracts/security/firmware_external_input_surfaces.json"


def registered_targets(manifest: Path = MANIFEST) -> tuple[str, ...]:
    document = tomllib.loads(manifest.read_text())
    names: list[str] = []
    for binary in document.get("bin", []):
        name = binary.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    if len(names) != len(set(names)):
        raise ValueError("qa/fuzz/Cargo.toml contains duplicate fuzz target names")
    return tuple(names)


def validate_targets() -> list[str]:
    errors: list[str] = []
    targets = registered_targets()
    if not targets:
        return ["qa/fuzz/Cargo.toml registers no fuzz targets"]
    sources: dict[str, str] = {}
    for target in targets:
        source = FUZZ_ROOT / f"{target}.rs"
        corpus = FUZZ_ROOT / "seeds" / target
        if not source.is_file():
            errors.append(f"fuzz target source is missing: {source.relative_to(ROOT)}")
        else:
            sources[target] = source.read_text(errors="replace")
        if not corpus.is_dir():
            errors.append(f"fuzz seed corpus is missing: {corpus.relative_to(ROOT)}")
        elif not any(path.is_file() for path in corpus.iterdir()):
            errors.append(f"fuzz seed corpus is empty: {corpus.relative_to(ROOT)}")

    if not SURFACE_REGISTRY.is_file():
        errors.append("external-input fuzz surface registry is missing")
        return errors
    try:
        registry = json.loads(SURFACE_REGISTRY.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"external-input fuzz surface registry is invalid: {exc}")
        return errors
    surfaces = registry.get("surfaces", [])
    names: set[str] = set()
    for surface in surfaces:
        name = surface.get("name")
        target = surface.get("target")
        token = surface.get("token")
        if not all(isinstance(value, str) and value for value in (name, target, token)):
            errors.append("external-input fuzz surface entry has missing name/target/token")
            continue
        if name in names:
            errors.append(f"duplicate external-input fuzz surface: {name}")
        names.add(name)
        if target not in targets:
            errors.append(f"external-input surface {name} references unregistered target {target}")
            continue
        if token not in sources.get(target, ""):
            errors.append(f"external-input surface {name} token {token!r} is absent from {target}.rs")
    if len(surfaces) < 20:
        errors.append("external-input fuzz surface registry is unexpectedly incomplete (<20 surfaces)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    if args.validate:
        errors = validate_targets()
        if errors:
            for error in errors:
                print(f"ERROR: {error}")
            return 1
    for target in registered_targets():
        print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
