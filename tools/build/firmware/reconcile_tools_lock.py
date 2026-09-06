#!/usr/bin/env python3
"""Safely reconcile a stale Cargo lockfile for firmware build tooling.

The firmware hash pipeline must remain locked and offline.  A stale tools lock
may be pruned/re-resolved only when Cargo can do so offline and every external
package identity in the repaired graph already existed in the supplied lock.
This prevents a firmware build from silently introducing a new registry/git
package, version, source, or checksum while repairing dependency-edge drift.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tomllib
from pathlib import Path


def _load_lock(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"cannot parse Cargo lockfile {path}: {exc}") from exc


def _external_identities(lock: dict) -> set[tuple[str, str, str, str]]:
    identities: set[tuple[str, str, str, str]] = set()
    for package in lock.get("package", []):
        source = package.get("source")
        if not source:
            continue
        identities.add(
            (
                str(package.get("name", "")),
                str(package.get("version", "")),
                str(source),
                str(package.get("checksum", "")),
            )
        )
    return identities


def _metadata_command(manifest: Path, *, locked: bool, offline: bool) -> list[str]:
    command = [
        "cargo",
        "metadata",
        "--manifest-path",
        str(manifest),
        "--format-version",
        "1",
    ]
    if locked:
        command.append("--locked")
    if offline:
        command.append("--offline")
    return command


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )


def reconcile(workspace: Path) -> bool:
    workspace = workspace.resolve()
    manifest = workspace / "Cargo.toml"
    lock_path = workspace / "Cargo.lock"
    if not manifest.is_file() or not lock_path.is_file():
        raise RuntimeError(f"tools workspace is missing Cargo.toml/Cargo.lock: {workspace}")

    original_bytes = lock_path.read_bytes()
    original = _load_lock(lock_path)
    original_lock_version = original.get("version")
    original_external = _external_identities(original)
    original_count = len(original.get("package", []))

    locked = _run(_metadata_command(manifest, locked=True, offline=False), workspace)
    if locked.returncode == 0:
        print(f"tools Cargo.lock: locked graph already valid ({original_count} packages)")
        return False

    print("tools Cargo.lock: stale; performing offline graph-only reconciliation", file=sys.stderr)
    try:
        refresh = _run(_metadata_command(manifest, locked=False, offline=True), workspace)
        if refresh.returncode != 0:
            detail = refresh.stderr.strip() or "cargo metadata --offline failed"
            raise RuntimeError(
                "offline tools lock reconciliation failed; network fallback is forbidden in the firmware hash build: "
                + detail
            )

        repaired = _load_lock(lock_path)
        if repaired.get("version") != original_lock_version:
            raise RuntimeError(
                "offline tools lock reconciliation changed the Cargo.lock format version"
            )

        repaired_external = _external_identities(repaired)
        introduced = sorted(repaired_external - original_external)
        if introduced:
            details = "; ".join(
                f"{name} {version} {source} checksum={checksum or '<none>'}"
                for name, version, source, checksum in introduced[:8]
            )
            raise RuntimeError(
                "offline tools lock reconciliation introduced external package identities absent from the pinned lock: "
                + details
            )

        verify = _run(_metadata_command(manifest, locked=True, offline=False), workspace)
        if verify.returncode != 0:
            detail = verify.stderr.strip() or "cargo metadata --locked failed"
            raise RuntimeError("repaired tools Cargo.lock is still not locked-valid: " + detail)

        repaired_count = len(repaired.get("package", []))
        print(
            f"tools Cargo.lock: offline reconciliation verified "
            f"({original_count} -> {repaired_count} packages; no new external identities)"
        )
        return True
    except Exception:
        lock_path.write_bytes(original_bytes)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args()
    try:
        reconcile(args.workspace)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
