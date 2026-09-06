#!/usr/bin/env python3
"""Public Make-facade orchestration over platform implementation entrypoints."""
from __future__ import annotations

from collections.abc import Callable
from typing import Optional

PlatformRunner = Callable[[str, Optional[list[str]]], int]


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def run_all_profile(
    platform: PlatformRunner,
    profile: str,
    fuzz_passes: str,
    strict_lockfiles: str,
    resume_from: str = "",
) -> int:
    args = ["--profile", profile]
    if profile == "full":
        args.extend(["--fuzz-passes", fuzz_passes])
    if _truthy(strict_lockfiles):
        args.append("--strict-lockfiles")
    if resume_from.strip():
        args.extend(["--resume-from", resume_from.strip()])
    return platform("run-all", args)


def test_hardware(
    platform: PlatformRunner,
    board: str,
    port: str,
    timeout: str,
    strict_lockfiles: str,
) -> int:
    args = ["--category", "hardware", "--hardware", board, "--hardware-timeout", timeout]
    if port.strip():
        args.extend(["--hardware-port", port.strip()])
    if _truthy(strict_lockfiles):
        args.append("--strict-lockfiles")
    return platform("run-all", args)


def release_build(
    platform: PlatformRunner,
    is_windows: bool,
    output_dir: str,
    signing_key: str,
    refresh_inputs: str,
) -> int:
    args = ["-OutputDir" if is_windows else "--output-dir", output_dir]
    if signing_key.strip():
        args.extend(["-SigningKey" if is_windows else "--signing-key", signing_key.strip()])
    if _truthy(refresh_inputs):
        args.append("-RefreshInputs" if is_windows else "--refresh-inputs")
    result = platform("reproducible-build", args)
    if result != 0:
        return result
    print(
        "Reproducible release artifacts built and manifest-verified.\n"
        "External release-readiness evidence was not evaluated by this build step.\n"
        "Before publishing a production release, run `make release-readiness` with the "
        "operator-controlled evidence bindings documented in qa/release/README.md."
    )
    return 0
