#!/usr/bin/env python3
"""Run the enforced firmware lint profile across supported board modes."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tools.build.firmware.matrix_runner import run_firmware_matrix  # noqa: E402
from firmware_lint_policy import check_policy  # noqa: E402

# Clippy's style and pedantic groups are intentionally not suppressed in source.
# The project lint target explicitly enforces correctness, suspicious/performance
# defects, dead/unused code, and the architectural complexity limits selected by
# this repository. Item-level exceptions remain visible and review-locked.
LINT_ARGS = (
    "-A", "clippy::all",
    "-D", "clippy::correctness",
    "-D", "clippy::suspicious",
    "-D", "clippy::perf",
    "-D", "clippy::too_many_lines",
    "-D", "clippy::cognitive_complexity",
    "-D", "clippy::struct_excessive_bools",
    "-D", "dead_code",
    "-D", "unused_imports",
    "-D", "unused_variables",
    "-D", "unused_mut",
    "-D", "unused_assignments",
    "-D", "unused_unsafe",
)


def main() -> int:
    policy_errors = check_policy(ROOT)
    if policy_errors:
        for error in policy_errors:
            print(f"ERROR: {error}")
        return 1
    return run_firmware_matrix(
        "clippy",
        trailing_args=LINT_ARGS,
        success_message=(
            "PASS: firmware lint matrix is clean for hardware and QEMU modes"
        ),
    )


if __name__ == "__main__":
    sys.exit(main())
