#!/usr/bin/env python3
"""Split one full CRAP report into enforced ownership scopes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from report import (
    SCOPES,
    apply_coverage_unavailable_source_policy,
    baseline_document,
    parse_report,
    render_scope_report,
    report_summary,
    write_json,
)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--input", required=True, type=Path, help="full CRAP text report")
    command.add_argument("--output-dir", required=True, type=Path, help="classified report directory")
    command.add_argument("--source-label", default="unspecified", help="revision/archive label for a baseline")
    command.add_argument("--display-report", type=Path, help="optional human report copied as crap_report_full.txt")
    command.add_argument(
        "--policy",
        type=Path,
        default=Path(__file__).resolve().with_name("policy.json"),
        help="coverage-unavailable source assessment policy",
    )
    return command


def main() -> int:
    arguments = parser().parse_args()
    report = parse_report(arguments.input)
    try:
        policy = json.loads(arguments.policy.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"ERROR: cannot read CRAP policy {arguments.policy}: {error}") from error
    report = apply_coverage_unavailable_source_policy(report, policy)
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    full_output = arguments.output_dir / "crap_report_full.txt"
    display_report = arguments.display_report
    if display_report is not None:
        if not display_report.is_file():
            raise SystemExit(f"ERROR: display report does not exist: {display_report}")
        if display_report.resolve() != full_output.resolve():
            shutil.copyfile(display_report, full_output)
    elif arguments.input.suffix.lower() != ".json":
        if arguments.input.resolve() != full_output.resolve():
            shutil.copyfile(arguments.input, full_output)
    else:
        full_output.write_text("CRAP JSON source: " + str(arguments.input) + "\n")
    for scope in SCOPES:
        filename = "crap_report_prod.txt" if scope == "production" else f"crap_report_{scope}.txt"
        (arguments.output_dir / filename).write_text(render_scope_report(report, scope))
    write_json(arguments.output_dir / "crap_summary.json", report_summary(report))
    source_label = (
        arguments.source_label
        if arguments.source_label != "unspecified"
        else arguments.input.name
    )
    write_json(
        arguments.output_dir / "current.json",
        baseline_document(report, source_label),
    )
    summary = report_summary(report)
    source_assessed = summary["scopes"]["production"]["assessment_basis"][
        "source_complexity"
    ]
    print(
        "PASS: classified "
        f"{summary['all']['functions']} CRAP rows into production, tests, external, and tools; "
        f"{source_assessed} coverage-unavailable production rows use source complexity"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
