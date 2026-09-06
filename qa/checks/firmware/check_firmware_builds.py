#!/usr/bin/env python3
"""Compile every supported firmware board and production feature combination."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tools.build.firmware.matrix_runner import run_firmware_matrix  # noqa: E402
from firmware_lint_policy import check_policy  # noqa: E402


def main() -> int:
    policy_errors = check_policy(ROOT)
    if policy_errors:
        for error in policy_errors:
            print(f"ERROR: {error}")
        return 1
    return run_firmware_matrix(
        "check",
        success_message=(
            "PASS: firmware build matrix compiles for all hardware and QEMU modes"
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
