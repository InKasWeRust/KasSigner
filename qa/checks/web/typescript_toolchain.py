#!/usr/bin/env python3
"""Resolve the pinned TypeScript compiler used by browser source checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
import os
import shutil
import subprocess
import sys

TYPESCRIPT_VERSION = "5.8.3"
NPM_REGISTRY = "https://registry.npmjs.org"
ROOT = Path(__file__).resolve().parents[3]

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
CommandLookup = Callable[[str], str | None]


class TypeScriptToolchainError(RuntimeError):
    """Raised when the pinned compiler cannot be resolved or installed."""


def _compiler_version(
    command: list[str],
    *,
    run: CommandRunner,
) -> str | None:
    try:
        result = run(
            [*command, "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    output = (result.stdout or result.stderr).strip()
    prefix = "Version "
    return output[len(prefix) :] if output.startswith(prefix) else None


def _cached_compiler(root: Path, node: str) -> list[str]:
    compiler = (
        root
        / "target"
        / "development-tools"
        / f"typescript-{TYPESCRIPT_VERSION}"
        / "node_modules"
        / "typescript"
        / "lib"
        / "tsc.js"
    )
    return [node, str(compiler)]


def _install_cached_compiler(
    *,
    root: Path,
    npm: str,
    run: CommandRunner,
) -> None:
    install_root = (
        root
        / "target"
        / "development-tools"
        / f"typescript-{TYPESCRIPT_VERSION}"
    )
    install_root.mkdir(parents=True, exist_ok=True)
    print(
        f"INFO: installing pinned TypeScript {TYPESCRIPT_VERSION} "
        f"under {install_root.relative_to(root)}"
    )
    result = run(
        [
            npm,
            "install",
            "--prefix",
            str(install_root),
            f"--registry={NPM_REGISTRY}",
            "--no-audit",
            "--no-fund",
            "--ignore-scripts",
            "--no-save",
            f"typescript@{TYPESCRIPT_VERSION}",
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return
    details = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    raise TypeScriptToolchainError(
        f"npm could not install TypeScript {TYPESCRIPT_VERSION}."
        + (f"\n{details}" if details else "")
    )


def resolve_typescript_command(
    *,
    root: Path = ROOT,
    environ: Mapping[str, str] | None = None,
    which: CommandLookup = shutil.which,
    run: CommandRunner = subprocess.run,
) -> list[str]:
    """Return an argv prefix for the exact compiler version required by the repo."""

    environment = os.environ if environ is None else environ
    override = environment.get("KASSIGNER_TSC")
    candidates: list[list[str]] = []
    if override:
        candidates.append([override])
    system_tsc = which("tsc")
    if system_tsc and (not override or system_tsc != override):
        candidates.append([system_tsc])

    for command in candidates:
        if _compiler_version(command, run=run) == TYPESCRIPT_VERSION:
            return command

    node = which("node")
    if not node:
        raise TypeScriptToolchainError(
            "Node.js is required to run the pinned TypeScript compiler."
        )

    cached = _cached_compiler(root, node)
    if Path(cached[1]).is_file():
        if _compiler_version(cached, run=run) == TYPESCRIPT_VERSION:
            return cached

    npm = which("npm")
    if not npm:
        raise TypeScriptToolchainError(
            "npm is required to install the pinned TypeScript compiler."
        )

    _install_cached_compiler(root=root, npm=npm, run=run)
    if not Path(cached[1]).is_file():
        raise TypeScriptToolchainError(
            "npm completed without producing the TypeScript compiler entry point."
        )
    if _compiler_version(cached, run=run) != TYPESCRIPT_VERSION:
        raise TypeScriptToolchainError(
            f"installed TypeScript compiler is not version {TYPESCRIPT_VERSION}."
        )
    return cached


def main() -> int:
    try:
        command = resolve_typescript_command()
    except TypeScriptToolchainError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(" ".join(command))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
