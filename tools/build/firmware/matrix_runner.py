"""Shared execution primitive for firmware feature matrices."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .build_matrix import FEATURE_MATRIX

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE = ROOT / "apps/signer-firmware"


def run_firmware_matrix(
    operation: str,
    *,
    trailing_args: Sequence[str] = (),
    success_message: str,
) -> int:
    """Run one Cargo operation for every supported firmware feature set."""
    if shutil.which("cargo") is None:
        print(
            "ERROR: cargo is required. Install the ESP Rust toolchain selected by "
            "apps/signer-firmware/rust-toolchain.toml before running this check."
        )
        return 2

    for build in FEATURE_MATRIX:
        environment = os.environ.copy()
        environment.update(build.env_overrides())
        if operation == "check":
            rustflags = environment.get("RUSTFLAGS", "").strip()
            if "-Dwarnings" not in rustflags.split():
                environment["RUSTFLAGS"] = f"{rustflags} -Dwarnings".strip()
        command = [
            "cargo",
            operation,
            "--locked",
            "--no-default-features",
            "--features",
            build.features,
            "--bin",
            "kassigner-firmware",
        ]
        if trailing_args:
            command.extend(("--", *trailing_args))
        print(f"==> firmware {operation}: {build.features}")
        result = subprocess.run(command, cwd=FIRMWARE, env=environment, check=False)
        if result.returncode != 0:
            return result.returncode

    print(success_message)
    return 0
