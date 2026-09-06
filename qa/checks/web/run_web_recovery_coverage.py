#!/usr/bin/env python3
"""Run KasSee browser recovery tests with persisted Node/V8 coverage.

The runner intentionally relies only on NODE_V8_COVERAGE plus ``node --test``.
Older supported Node releases do not understand the newer
newer built-in coverage filtering and threshold flags, so coverage filtering and
threshold enforcement happen here from the raw V8 coverage records.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
TEST_FILE = ROOT / "qa/checks/web/web_recovery_coverage.test.mjs"
DEFAULT_OUTPUT = ROOT / "target/qa/browser-recovery"
MINIMUM_LINE = 90.0
MINIMUM_FUNCTION = 90.0
MINIMUM_BRANCH = 90.0

_WEB_CHECK_DIR = Path(__file__).resolve().parent
if str(_WEB_CHECK_DIR) not in sys.path:
    sys.path.insert(0, str(_WEB_CHECK_DIR))
from web_recovery_coverage_support import (  # noqa: E402
    RECOVERY_PREFIX, RECOVERY_ROOT, coverage_report, merge_v8_coverage, percent,
    recovery_totals,
)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--minimum-line", type=float, default=MINIMUM_LINE)
    parser.add_argument("--minimum-function", type=float, default=MINIMUM_FUNCTION)
    parser.add_argument("--minimum-branch", type=float, default=MINIMUM_BRANCH)
    return parser.parse_args()



def main() -> int:
    args = parse_args()
    node = shutil.which("node")
    if node is None:
        print("ERROR: node is required for browser recovery coverage", file=sys.stderr)
        return 127

    output = args.output_dir.resolve()
    raw_dir = output / "raw"
    if output.exists():
        shutil.rmtree(output)
    raw_dir.mkdir(parents=True)

    # NODE_V8_COVERAGE has been supported much longer than Node's newer
    # built-in coverage filtering and threshold flags. Keep the test command
    # portable and enforce the recovery-only thresholds from the raw records.
    command = [node, "--test", str(TEST_FILE.relative_to(ROOT))]
    environment = os.environ.copy()
    environment["NODE_V8_COVERAGE"] = str(raw_dir)
    environment["NODE_NO_WARNINGS"] = "1"
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    test_output = (result.stdout + result.stderr).replace(str(ROOT), ".")

    raw_files = sorted(raw_dir.glob("coverage-*.json"))
    if not raw_files:
        (output / "report.txt").write_text(test_output, encoding="utf-8")
        print(test_output, end="")
        print("ERROR: Node did not emit raw V8 coverage records", file=sys.stderr)
        return result.returncode or 1

    merged, scripts, measured = merge_v8_coverage(raw_dir)
    (output / "v8-coverage.json").write_text(
        json.dumps(merged, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    shutil.rmtree(raw_dir)

    expected = {
        path.relative_to(ROOT).as_posix()
        for path in RECOVERY_ROOT.rglob("*.js")
        if path.is_file()
    }
    missing = sorted(expected - measured)
    unexpected = sorted(measured - expected)
    totals, file_reports = recovery_totals(scripts, expected)
    line_percent = percent(totals.covered_lines, totals.total_lines)
    branch_percent = percent(totals.covered_branches, totals.total_branches)
    function_percent = percent(totals.covered_functions, totals.total_functions)
    report_text = coverage_report(test_output, file_reports, totals)
    (output / "report.txt").write_text(report_text, encoding="utf-8")

    met = (
        result.returncode == 0
        and not missing
        and line_percent >= args.minimum_line
        and function_percent >= args.minimum_function
        and branch_percent >= args.minimum_branch
    )
    summary = {
        "schema_version": 1,
        "domain": "browser_recovery",
        "source_root": RECOVERY_PREFIX,
        "tests": {
            "path": TEST_FILE.relative_to(ROOT).as_posix(),
            "passed": result.returncode == 0,
        },
        "files": {
            "expected": len(expected),
            "measured": len(measured),
            "missing": missing,
            "unexpected": unexpected,
        },
        "coverage": {
            "lines": {
                "percent": round(line_percent, 2),
                "available": True,
                "target": args.minimum_line,
                "met": line_percent >= args.minimum_line,
            },
            "functions": {
                "percent": round(function_percent, 2),
                "available": True,
                "target": args.minimum_function,
                "met": function_percent >= args.minimum_function,
            },
            "branches": {
                "percent": round(branch_percent, 2),
                "available": True,
                "target": args.minimum_branch,
                "met": branch_percent >= args.minimum_branch,
            },
        },
        "artifacts": {
            "report": "report.txt",
            "v8_coverage": "v8-coverage.json",
        },
        "runtime": {
            "collection": "NODE_V8_COVERAGE",
            "thresholds_enforced_by": "qa/checks/web/run_web_recovery_coverage.py",
        },
        "met": met,
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if not met:
        print(report_text, end="")
        if missing:
            print(
                "ERROR: browser recovery coverage omitted source files: "
                + ", ".join(missing),
                file=sys.stderr,
            )
        if line_percent < args.minimum_line:
            print(
                f"ERROR: browser recovery line coverage {line_percent:.2f}% "
                f"is below {args.minimum_line:.2f}%",
                file=sys.stderr,
            )
        if function_percent < args.minimum_function:
            print(
                f"ERROR: browser recovery function coverage {function_percent:.2f}% "
                f"is below {args.minimum_function:.2f}%",
                file=sys.stderr,
            )
        if branch_percent < args.minimum_branch:
            print(
                f"ERROR: browser recovery branch coverage {branch_percent:.2f}% "
                f"is below {args.minimum_branch:.2f}%",
                file=sys.stderr,
            )
        return result.returncode or 1

    print(
        "PASS: browser recovery coverage "
        f"({len(measured)}/{len(expected)} files; "
        f"lines {line_percent:.2f}%; functions {function_percent:.2f}%; "
        f"branches {branch_percent:.2f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
