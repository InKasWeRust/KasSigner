#!/usr/bin/env python3
"""Measure every reachable KasSee runtime module with merged Node/V8 integration coverage."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
JS_ROOT = ROOT / "apps/kassee-web/web/js"
ENTRY = JS_ROOT / "main.js"
DEFAULT_OUTPUT = ROOT / "target/qa/web-runtime"
IMPORT_RE = re.compile(r"(?:from\s+|import\s*\()\s*['\"]([^'\"]+)['\"]|^\s*import\s*['\"]([^'\"]+)['\"]", re.M)

MIN_LINE_COVERAGE_PERCENT = 92.72
MIN_FUNCTION_COVERAGE_PERCENT = 91.01
MIN_BRANCH_COVERAGE_PERCENT = 90.0

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_recovery_coverage_support import merge_v8_coverage, recovery_totals, percent  # noqa: E402

TEST_COMMANDS = (
    ("runtime", ["node", "qa/checks/web/check_web_runtime.mjs"]),
    ("critical", ["node", "qa/checks/web/check_web_critical_paths.mjs"]),
    ("covenants", ["node", "qa/checks/web/check_web_covenant_interactions.mjs"]),
    ("recovery", ["node", "--test", "qa/checks/web/web_recovery_coverage.test.mjs"]),
    ("wallet_success", ["node", "--test", "qa/checks/web/web_wallet_success_paths.test.mjs"]),
    ("transaction_success", ["node", "--test", "qa/checks/web/web_transaction_success_paths.test.mjs"]),
    ("covenant_spending_success", ["node", "--test", "qa/checks/web/web_covenant_spending_success_paths.test.mjs"]),
    ("covenant_builder_success", ["node", "--test", "qa/checks/web/web_covenant_builder_success_paths.test.mjs"]),
    ("stealth_success", ["node", "--test", "qa/checks/web/web_stealth_success_paths.test.mjs"]),
    ("valid_boundary", ["node", "--test", "qa/checks/web/web_runtime_valid_boundary.test.mjs"]),
    ("kpub_deep", ["node", "--test", "qa/checks/web/web_kpub_manager_deep_paths.test.mjs"]),
    ("scanning_deep", ["node", "--test", "qa/checks/web/web_scanning_deep_paths.test.mjs"]),
    ("transaction_deep", ["node", "--test", "qa/checks/web/web_transaction_deep_paths.test.mjs"]),
    ("transaction_ui_deep", ["node", "--test", "qa/checks/web/web_transaction_ui_deep_paths.test.mjs"]),
    ("wallet_deep", ["node", "--test", "qa/checks/web/web_wallet_deep_paths.test.mjs"]),
    ("portfolio", ["node", "--test", "qa/checks/web/web_portfolio_paths.test.mjs"]),
    ("covenant_event_deep", ["node", "--test", "qa/checks/web/web_covenant_event_deep_paths.test.mjs"]),
    ("covenant_runtime_deep", ["node", "--test", "qa/checks/web/web_covenant_runtime_deep_paths.test.mjs"]),
    ("covenant_claims_deep", ["node", "--test", "qa/checks/web/web_covenant_claims_deep_paths.test.mjs"]),
    ("generation_vault_deep", ["node", "--test", "qa/checks/web/web_generation_vault_deep_paths.test.mjs"]),
    ("oracle_model_b_deep", ["node", "--test", "qa/checks/web/web_oracle_model_b_deep_paths.test.mjs"]),
    ("crowdfund_deep", ["node", "--test", "qa/checks/web/web_crowdfund_deep_paths.test.mjs"]),
    ("private_swap_deep", ["node", "--test", "qa/checks/web/web_private_swap_deep_paths.test.mjs"]),
    ("private_swap_controller_deep", ["node", "--test", "qa/checks/web/web_private_swap_controller_paths.test.mjs"]),
    ("covenant_sign_protocol", ["node", "qa/checks/web/covenant_sign_protocol.test.mjs"]),
    ("covenant_sign_binding_deep", ["node", "--test", "qa/checks/web/web_covenant_sign_binding_deep_paths.test.mjs"]),
    ("covenant_result_actions_deep", ["node", "--test", "qa/checks/web/web_covenant_result_actions_deep_paths.test.mjs"]),
    ("remaining_edge_deep", ["node", "--test", "qa/checks/web/web_remaining_edge_deep_paths.test.mjs"]),
    ("branch_hardening", ["node", "--test", "qa/checks/web/web_branch_hardening.test.mjs"]),
    ("branch_hardening_ui", ["node", "--test", "qa/checks/web/web_branch_hardening_ui.test.mjs"]),
    ("branch_hardening_final", ["node", "--test", "qa/checks/web/web_branch_hardening_final.test.mjs"]),
    ("branch_ratchet_core", ["node", "--test", "qa/checks/web/web_branch_ratchet_core.test.mjs"]),
    ("branch_ratchet_extended", ["node", "--test", "qa/checks/web/web_branch_ratchet_extended.test.mjs"]),
    ("stealth_send_deep", ["node", "--test", "qa/checks/web/web_stealth_send_deep_paths.test.mjs"]),
    ("stealth_live_deep", ["node", "--test", "qa/checks/web/web_stealth_live_deep_paths.test.mjs"]),
    ("fail_closed", ["node", "qa/checks/web/web_runtime_fail_closed.test.mjs"]),
)


def reachable_modules() -> set[str]:
    seen: set[Path] = set()
    stack = [ENTRY]
    while stack:
        path = stack.pop().resolve()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        text = path.read_text(encoding="utf-8")
        for match in IMPORT_RE.finditer(text):
            spec = match.group(1) or match.group(2)
            if not spec or not spec.startswith("."):
                continue
            target = (path.parent / spec).resolve()
            if target.suffix == "":
                target = target.with_suffix(".js")
            try:
                target.relative_to(JS_ROOT.resolve())
            except ValueError:
                continue
            stack.append(target)
    return {path.relative_to(ROOT).as_posix() for path in seen}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    node = shutil.which("node")
    if not node:
        print("ERROR: node is required for web runtime coverage", file=sys.stderr)
        return 127
    output = args.output_dir.resolve()
    raw = output / "raw"
    if output.exists(): shutil.rmtree(output)
    raw.mkdir(parents=True)
    env = os.environ.copy(); env["NODE_V8_COVERAGE"] = str(raw); env["NODE_NO_WARNINGS"] = "1"
    logs: list[str] = []
    passed = True
    for name, command in TEST_COMMANDS:
        command = [node if item == "node" else item for item in command]
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
        logs.append(f"## {name}\n{result.stdout}{result.stderr}")
        passed = passed and result.returncode == 0
    merged, scripts, _ = merge_v8_coverage(raw)
    (output / "v8-coverage.json").write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(raw)
    expected = reachable_modules()
    all_js = {p.relative_to(ROOT).as_posix() for p in JS_ROOT.rglob("*.js")}
    if expected != all_js:
        missing_from_graph = sorted(all_js - expected)
        print(f"ERROR: main.js graph does not reach all JS modules: {missing_from_graph}", file=sys.stderr)
        return 1
    measured = {path for path in scripts if path in expected}
    missing = sorted(expected - measured)
    totals, file_reports = recovery_totals(scripts, expected)
    line = percent(totals.covered_lines, totals.total_lines)
    funcs = percent(totals.covered_functions, totals.total_functions)
    branches = percent(totals.covered_branches, totals.total_branches)
    line_rounded = round(line, 2)
    funcs_rounded = round(funcs, 2)
    branches_rounded = round(branches, 2)
    summary = {
        "schema_version": 1,
        "domain": "web_runtime",
        "entry": ENTRY.relative_to(ROOT).as_posix(),
        "files": {"reachable": len(expected), "measured": len(measured), "missing": missing, "mapping_percent": round(percent(len(measured), len(expected)), 2)},
        "coverage": {"lines": line_rounded, "functions": funcs_rounded, "branches": branches_rounded},
        "requirements": {
            "mapping_percent": 100.0,
            "lines_percent": MIN_LINE_COVERAGE_PERCENT,
            "functions_percent": MIN_FUNCTION_COVERAGE_PERCENT,
            "branches_percent": MIN_BRANCH_COVERAGE_PERCENT,
            "integration_tests_pass": True,
        },
        "tests_passed": passed,
        "met": (
            passed
            and not missing
            and len(measured) == len(expected)
            and line_rounded >= MIN_LINE_COVERAGE_PERCENT
            and funcs_rounded >= MIN_FUNCTION_COVERAGE_PERCENT
            and branches_rounded >= MIN_BRANCH_COVERAGE_PERCENT
        ),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (output / "report.txt").write_text("\n".join(logs) + f"\n# web runtime coverage\n# files {len(measured)}/{len(expected)}; lines {line:.2f}%; functions {funcs:.2f}%; branches {branches:.2f}%\n")
    if not summary["met"]:
        print((output / "report.txt").read_text(), end="")
        if missing:
            print("ERROR: web runtime V8 mapping omitted: " + ", ".join(missing), file=sys.stderr)
        if line_rounded < MIN_LINE_COVERAGE_PERCENT:
            print(
                f"ERROR: web runtime line coverage {line:.2f}% is below "
                f"{MIN_LINE_COVERAGE_PERCENT:.2f}%",
                file=sys.stderr,
            )
        if funcs_rounded < MIN_FUNCTION_COVERAGE_PERCENT:
            print(
                f"ERROR: web runtime function coverage {funcs:.2f}% is below "
                f"{MIN_FUNCTION_COVERAGE_PERCENT:.2f}%",
                file=sys.stderr,
            )
        if branches_rounded < MIN_BRANCH_COVERAGE_PERCENT:
            print(
                f"ERROR: web runtime branch coverage {branches:.2f}% is below "
                f"{MIN_BRANCH_COVERAGE_PERCENT:.2f}%",
                file=sys.stderr,
            )
        return 1
    print(f"PASS: web runtime V8 mapping ({len(measured)}/{len(expected)} modules; lines {line:.2f}%; functions {funcs:.2f}%; branches {branches:.2f}%)")
    return 0

if __name__ == "__main__": raise SystemExit(main())
