#!/usr/bin/env python3
"""Stable entry point for focused repository architecture checks."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from architecture.core import (  # noqa: E402
    checker_structure, comment_quality, dependency_boundaries, duplication,
    function_duplication, rust_syntax, source_quality, symbol_quality, workspace,
)
from architecture.core.inventory import repository_inventory  # noqa: E402
from architecture.firmware import (  # noqa: E402
    firmware_controllers, firmware_display, firmware_navigation, firmware_presentation, firmware_runtime, firmware_screens,
    firmware_services, firmware_state, firmware_workflows,
)
from architecture.firmware.guards import account_key, source_integrity, wallet_session  # noqa: E402
from architecture.firmware.subsystems import (  # noqa: E402
    firmware_backup, firmware_boot, firmware_media, firmware_storage,
)
from architecture.protocols import (  # noqa: E402
    offline_portability, offline_protocols, online, online_paths, wasm_api,
)
from architecture.tooling import native_entrypoints, toolchain_policy  # noqa: E402
from architecture.web import (  # noqa: E402
    advisory_quality, web_constellation, web_css, web_html, web_js,
)

CHECKS = (
    repository_inventory, native_entrypoints, toolchain_policy, workspace, dependency_boundaries, rust_syntax,
    source_quality, offline_protocols, offline_portability, wasm_api, online,
    online_paths, firmware_screens, firmware_controllers, source_integrity,
    account_key, wallet_session, firmware_workflows, firmware_display,
    firmware_navigation, firmware_presentation, firmware_runtime, firmware_state, firmware_boot, firmware_services,
    firmware_backup, firmware_storage, firmware_media, web_html,
    web_constellation, web_css, web_js, checker_structure,
)
WARNING_CHECKS = (
    comment_quality, symbol_quality, duplication, function_duplication,
    advisory_quality,
)

def _inventory_decision(change: str, description: str) -> int:
    if change == "missing":
        prompt = f"MISSING: {description}\n0=remove from checks, 1=ignore for this run: "
    else:
        prompt = f"NEW: {description}\n0=add to checks, 1=ignore for this run: "
    while True:
        try:
            choice = input(prompt).strip()
        except EOFError:
            return -1
        if choice in {"0", "1"}:
            return int(choice)
        print("Please enter 0 or 1.")

def _run_check(module) -> list[str]:
    if module is repository_inventory and sys.stdin.isatty():
        return module.reconcile(ROOT, _inventory_decision)
    return module.check(ROOT)

def main() -> int:
    errors = [error for module in CHECKS for error in _run_check(module)]
    warnings = [warning for module in WARNING_CHECKS for warning in module.check(ROOT)]
    for warning in sorted(warnings):
        print(f"WARNING: {warning}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(
        "PASS: repository inventory, workspace layout, QA consolidation, explicit "
        f"boundaries, and scoped business facades ({len(warnings)} advisory warnings)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
