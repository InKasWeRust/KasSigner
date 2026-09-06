#!/usr/bin/env python3
"""Generate and enforce the production CoreS3 E2E coverage ratchet.

The committed production-surface baseline is a versionless continuous-integration
ratchet. Every checkbox in the canonical QA requirements specification has a stable
item ID; item coverage is the authoritative release-qualification unit. New
production surface still requires implemented E2E immediately, while release
qualification rejects all remaining item or surface backlog.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECKS_DIR = Path(__file__).resolve().parent
if str(CHECKS_DIR) not in sys.path:
    sys.path.insert(0, str(CHECKS_DIR))
import production_ui_graph as ui_graph
REQUIREMENTS_SPEC = Path("qa/specs/production_e2e_requirements.md")
BASELINE = Path("qa/baselines/workflow/production_surface_baseline.json")
BASELINE_STATE_OPERATION_MIGRATIONS = {
    "ConnectKasSeeLoading": "ConnectKasSee",
    "MultisigKpubLoading": "DeriveMultisigKpub",
    "Signing": "SignTransaction",
}
BASELINE_STATE_MIGRATIONS = {
    "WalletBackupMenu": "WalletBackupMethodsMenu",
    "ShowQrFrameChoice": "ShowQR",
    "ShowQrDensityChoice": "ShowQrModeChoice",
    "FwUpdateResult": "FirmwareUpdateReady",
}
BASELINE_MENU_ITEM_MIGRATIONS = {
    "Connect KasSee": "Connect",
    "Backup / Recovery": "Backup",
    "Enter Words": "Words",
    "Scan SeedQR": "SeedQR",
    "Restore from SD": "SD",
    "Advanced Restore": "Advanced",
    "Export xprv": "XPrv Backup",
}
SCENARIOS = Path("qa/config/workflow/production_e2e_scenarios.json")
MANIFEST = Path("qa/config/workflow/production_e2e_manifest.json")
STATE_FILE = Path("apps/signer-firmware/src/runtime/input/state.rs")
NAV_FILE = Path("apps/signer-firmware/src/runtime/navigation/production.rs")
UI_GRAPH_FILE = ui_graph.GRAPH_FILE
NAV_DATA_FILE = Path("apps/signer-firmware/src/runtime/data/navigation.rs")
CATALOG_DIR = Path("apps/signer-firmware/src/runtime/workflow_tests/catalog")
CONTROLLERS = Path("apps/signer-firmware/src/runtime/interactions")

LEVELS = {"backlog": 0, "catalog": 1, "connected": 2, "qa": 2, "hil": 3, "manual-hil": 4}
EXCLUDED_STATE_CFG = ("developer-ui", "workflow-tests", "waveshare", "qemu")
EXCLUDED_ACTION_CFG = ("developer-ui", "workflow-tests", "workflow-test-auto", "waveshare", "qemu")
ACTION_PREFIX = r"(?:handle|route|open|step|confirm|append|clear|leave)_"

BASELINE_ACTION_PREFIX = "apps/signer-firmware/src/controllers/"
CURRENT_ACTION_PREFIX = "apps/signer-firmware/src/runtime/interactions/"
BASELINE_ACTION_MIGRATIONS = {
    "apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs::route_wallet_backup":
        "apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs::route_wallet",
    "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs::handle_finalize_choice":
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/finalize.rs::handle_finalize_choice",
    "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs::handle_recovery_acknowledgement":
        "apps/signer-firmware/src/runtime/interactions/persistence/onboarding/recovery.rs::handle_recovery_acknowledgement",
}


def _migrate_baseline_action(action: str) -> str:
    if action.startswith(BASELINE_ACTION_PREFIX):
        action = CURRENT_ACTION_PREFIX + action[len(BASELINE_ACTION_PREFIX):]
    return BASELINE_ACTION_MIGRATIONS.get(action, action)


EXCLUDED_BASELINE_ACTIONS = {
    "apps/signer-firmware/src/runtime/interactions/workflow_tests.rs::handle_category",
    "apps/signer-firmware/src/runtime/interactions/workflow_tests.rs::handle_result",
    "apps/signer-firmware/src/runtime/interactions/workflow_tests.rs::handle_root",
    "apps/signer-firmware/src/runtime/interactions/workflow_tests.rs::open_category",
}


def _read(root: Path, relative: Path) -> str:
    return (root / relative).read_text(errors="strict")


def requirement_ids(root: Path) -> set[str]:
    return set(re.findall(r"^## (E2E-\d{3})\b", _read(root, REQUIREMENTS_SPEC), re.M))


def requirement_items(root: Path) -> dict[str, dict[str, str]]:
    items: dict[str, dict[str, str]] = {}
    section: str | None = None
    for line in _read(root, REQUIREMENTS_SPEC).splitlines():
        heading = re.match(r"^## (E2E-\d{3})\b", line)
        if heading:
            section = heading.group(1)
            continue
        if line.startswith("## Definition of Done"):
            section = None
            continue
        checkbox = re.match(r"^- \[ \] \*\*(E2E-\d{3}-\d{2})\*\* — (.+)$", line)
        if not checkbox:
            continue
        item_id, text = checkbox.groups()
        parent = item_id.rsplit("-", 1)[0]
        if section != parent:
            raise ValueError(f"requirement item {item_id} is under {section}, expected {parent}")
        if item_id in items:
            raise ValueError(f"duplicate requirement item ID: {item_id}")
        items[item_id] = {"section": parent, "text": text}
    return items


def definition_of_done_items(root: Path) -> dict[str, str]:
    return {
        item_id: text
        for item_id, text in re.findall(
            r"^- \[ \] \*\*(DOD-\d{2})\*\* — (.+)$",
            _read(root, REQUIREMENTS_SPEC),
            re.M,
        )
    }


def production_states(root: Path) -> list[str]:
    """Production state inventory is graph-owned; AppState parity is checked separately."""
    graph = ui_graph.parse_graph(root)
    return sorted({row["state"] for row in graph["states"]})


def _array_values(source: str, name: str) -> list[str]:
    values: list[str] = []
    for match in re.finditer(rf"\b{name}\b[^=]*=\s*&?\[(.*?)\];", source, re.S):
        values.extend(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', match.group(1)))
    return values


def production_menu_items(root: Path) -> list[str]:
    """Frozen production menu-label surface, sourced only from the UI graph."""
    graph = ui_graph.parse_graph(root)
    return sorted({item["label"] for items in graph["menus"].values() for item in items})


def production_actions(root: Path) -> list[str]:
    actions: set[str] = set()
    for path in sorted((root / CONTROLLERS).rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        # Developer/workflow-test controller surfaces are explicitly outside the
        # frozen production E2E inventory even when the module itself is always
        # compiled and individual functions are feature-gated elsewhere.
        if relative == "apps/signer-firmware/src/runtime/interactions/workflow_tests.rs":
            continue
        pending: list[str] = []
        lines = path.read_text(errors="ignore").splitlines()
        for index, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#["):
                pending.append(stripped)
                continue
            if not stripped or stripped.startswith(("//", "///")):
                continue
            # Signatures are generally one-line through the function name/open paren.
            match = re.search(rf"\bfn\s+({ACTION_PREFIX}[A-Za-z0-9_]+)\s*\(", stripped)
            if match:
                attrs = " ".join(pending)
                pending.clear()
                if any(token in attrs for token in EXCLUDED_ACTION_CFG):
                    continue
                actions.add(f"{relative}::{match.group(1)}")
                continue
            # Attributes apply only to the immediately following declaration. A cfg-gated
            # re-export/struct must never leak its cfg into a later production action.
            pending.clear()
    return sorted(actions)


def discover_surface(root: Path) -> dict[str, list[str]]:
    return {
        "states": production_states(root),
        "menu_items": production_menu_items(root),
        "actions": production_actions(root),
    }


def catalog_state_coverage(root: Path) -> dict[str, list[str]]:
    coverage: dict[str, set[str]] = defaultdict(set)
    known_states = set(production_states(root))
    for path in sorted((root / CATALOG_DIR).glob("*.rs")):
        if path.name == "mod.rs":
            continue
        source = path.read_text(errors="ignore")
        starts = list(re.finditer(r"WorkflowSpec\s*\{", source))
        for index, start in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
            body = source[start.start():end]
            id_match = re.search(r'id\s*:\s*"([a-z0-9-]+)"', body)
            if not id_match:
                continue
            workflow_id = id_match.group(1)
            for state in re.findall(r"\b([A-Z][A-Za-z0-9_]*)\b", body):
                if state in known_states:
                    coverage[state].add(workflow_id)
    return {key: sorted(value) for key, value in sorted(coverage.items())}


def _load_json(root: Path, relative: Path) -> dict:
    return json.loads(_read(root, relative))


def _scenario_index(scenarios: list[dict], field: str) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = defaultdict(list)
    for scenario in scenarios:
        if scenario.get("status") != "implemented":
            continue
        for item in scenario.get(field, []):
            index[item].append(scenario)
    return index


def _highest_level(items: list[dict], catalog: bool = False) -> str:
    candidates = [item["level"] for item in items]
    if catalog:
        candidates.append("catalog")
    return max(candidates, key=lambda value: LEVELS[value], default="backlog")


def build_manifest(root: Path) -> tuple[dict, list[str]]:
    errors: list[str] = []
    errors.extend(ui_graph.validate_graph(root))
    requirements = requirement_ids(root)
    if requirements != {f"E2E-{value:03d}" for value in range(1, 101)}:
        errors.append("production E2E checklist must contain stable E2E-001..E2E-100 sections")
    try:
        items = requirement_items(root)
        dod_items = definition_of_done_items(root)
    except ValueError as error:
        errors.append(str(error))
        items = {}
        dod_items = {}
    checkbox_count = len(re.findall(r"^- \[ \] ", _read(root, REQUIREMENTS_SPEC), re.M))
    if checkbox_count != len(items) + len(dod_items):
        errors.append("every production E2E/Definition-of-Done checkbox requires a stable item ID")

    baseline = _load_json(root, BASELINE)
    scenario_doc = _load_json(root, SCENARIOS)
    scenarios = scenario_doc.get("scenarios", [])
    current = discover_surface(root)
    baseline_surface = baseline.get("surface", {})

    for scenario in scenarios:
        sid = scenario.get("id", "<missing>")
        if scenario.get("level") not in LEVELS or scenario.get("level") == "backlog":
            errors.append(f"E2E scenario {sid}: invalid level")
        scenario_requirements = set(scenario.get("requirements", []))
        for req in scenario_requirements:
            if req not in requirements:
                errors.append(f"E2E scenario {sid}: unknown requirement {req}")
        scenario_items = scenario.get("items", [])
        if scenario.get("status") == "implemented" and scenario.get("level") != "catalog" and not scenario_items:
            errors.append(f"E2E scenario {sid}: implemented connected/HIL scenarios require exact item IDs")
        for item_id in scenario_items:
            item = items.get(item_id)
            if item is None:
                errors.append(f"E2E scenario {sid}: unknown requirement item {item_id}")
            elif item["section"] not in scenario_requirements:
                errors.append(
                    f"E2E scenario {sid}: item {item_id} parent {item['section']} is missing from requirements"
                )
        for field in ("states", "menu_items", "actions"):
            unknown = sorted(set(scenario.get(field, [])) - set(current[field]))
            if unknown:
                errors.append(f"E2E scenario {sid}: unknown {field}: {', '.join(unknown)}")
        if scenario.get("status") == "implemented" and scenario.get("level") == "manual-hil":
            checkpoints = scenario.get("operator_checkpoints", [])
            if not checkpoints:
                errors.append(f"E2E scenario {sid}: manual-hil scenarios require operator_checkpoints")
            checkpoint_ids = [checkpoint.get("id") for checkpoint in checkpoints]
            if any(not value for value in checkpoint_ids) or len(checkpoint_ids) != len(set(checkpoint_ids)):
                errors.append(f"E2E scenario {sid}: operator checkpoint IDs must be non-empty and unique")
            if scenario.get("serial_markers"):
                errors.append(f"E2E scenario {sid}: manual-hil evidence must not use serial_markers")
        elif scenario.get("status") == "implemented" and scenario.get("level") not in {"catalog", "qa"} and not scenario.get("serial_markers"):
            errors.append(f"E2E scenario {sid}: implemented device scenarios require serial_markers")
        hil_only_markers = set(scenario.get("hil_only_serial_markers", []))
        serial_markers = set(scenario.get("serial_markers", []))
        if hil_only_markers - serial_markers:
            errors.append(f"E2E scenario {sid}: hil_only_serial_markers must be a subset of serial_markers")
        if hil_only_markers and scenario.get("level") != "connected":
            errors.append(f"E2E scenario {sid}: hil_only_serial_markers are valid only on connected scenarios")

    indexes = {field: _scenario_index(scenarios, field) for field in ("states", "menu_items", "actions")}
    item_index = _scenario_index(scenarios, "items")
    catalog = catalog_state_coverage(root)

    # Frozen-backlog ratchet. New surface is forbidden without implemented E2E.
    for field in ("states", "menu_items", "actions"):
        baseline_set = set(baseline_surface.get(field, []))
        if field == "actions":
            baseline_set = {_migrate_baseline_action(item) for item in baseline_set}
            baseline_set -= EXCLUDED_BASELINE_ACTIONS
        elif field == "menu_items":
            baseline_set = {BASELINE_MENU_ITEM_MIGRATIONS.get(item, item) for item in baseline_set}
        current_set = set(current[field])
        for item in sorted(current_set - baseline_set):
            if not indexes[field].get(item):
                errors.append(f"new production {field[:-1]} lacks implemented E2E scenario: {item}")
        removed_set = baseline_set - current_set
        if field == "states":
            declared_operations = set(ui_graph.build_document(root).get("operation_kinds", []))
            migrated = {
                state for state, operation in BASELINE_STATE_OPERATION_MIGRATIONS.items()
                if operation in declared_operations
            }
            removed_set -= migrated
            removed_set -= {
                old for old, new in BASELINE_STATE_MIGRATIONS.items()
                if new in current_set
            }
        removed = sorted(removed_set)
        if removed:
            errors.append(
                f"frozen production baseline {field} changed/removed without baseline migration: {', '.join(removed)}"
            )

    harness_sources = "\n".join(
        path.read_text(errors="ignore")
        for path in sorted((root / "apps/signer-firmware/src/runtime/workflow_tests").rglob("*.rs"))
    )
    for scenario in scenarios:
        if scenario.get("status") != "implemented" or scenario.get("level") in {"catalog", "qa"}:
            continue
        for marker in scenario.get("serial_markers", []):
            if marker not in harness_sources:
                errors.append(f"E2E scenario {scenario['id']}: serial marker not emitted by harness: {marker}")

    surface_manifest: dict[str, dict[str, dict]] = {}
    for field in ("states", "menu_items", "actions"):
        entries: dict[str, dict] = {}
        for item in current[field]:
            implemented = indexes[field].get(item, [])
            catalog_ids = catalog.get(item, []) if field == "states" else []
            entries[item] = {
                "baseline": item in (
                    ({_migrate_baseline_action(value) for value in baseline_surface.get(field, [])}
                     if field == "actions" else
                     {BASELINE_MENU_ITEM_MIGRATIONS.get(value, value) for value in baseline_surface.get(field, [])}
                     if field == "menu_items" else
                     set(baseline_surface.get(field, [])))
                    - (EXCLUDED_BASELINE_ACTIONS if field == "actions" else set())
                ),
                "catalog_workflows": catalog_ids,
                "implemented_scenarios": sorted(s["id"] for s in implemented),
                "highest_level": _highest_level(implemented, bool(catalog_ids)),
            }
        surface_manifest[field] = entries

    summary = {}
    for field, entries in surface_manifest.items():
        counts = {level: 0 for level in LEVELS}
        for entry in entries.values():
            counts[entry["highest_level"]] += 1
        summary[field] = {"total": len(entries), **counts}

    item_manifest: dict[str, dict] = {}
    item_counts = {level: 0 for level in LEVELS}
    for item_id, item in sorted(items.items()):
        implemented = item_index.get(item_id, [])
        highest = _highest_level(implemented)
        item_counts[highest] += 1
        item_manifest[item_id] = {
            "section": item["section"],
            "text": item["text"],
            "implemented_scenarios": sorted(s["id"] for s in implemented),
            "highest_level": highest,
        }

    surface_incomplete = {
        field: sorted(
            item for item, entry in surface_manifest[field].items()
            if LEVELS[entry["highest_level"]] < LEVELS["connected"]
        )
        for field in ("states", "menu_items", "actions")
    }
    item_incomplete = sorted(
        item_id for item_id, entry in item_manifest.items()
        if LEVELS[entry["highest_level"]] < LEVELS["connected"]
    )
    qualification_ready = not item_incomplete and not any(surface_incomplete.values())

    manifest = {
        "schema": 2,
        "requirements_document": REQUIREMENTS_SPEC.as_posix(),
        "scenario_registry": SCENARIOS.as_posix(),
        "policy": "the frozen production surface is a CI ratchet; stable item IDs are authoritative for release qualification",
        "coverage_summary": summary,
        "item_coverage_summary": {"total": len(item_manifest), **item_counts},
        "requirement_items": item_manifest,
        "definition_of_done_items": dod_items,
        "release_qualification": {
            "ready": qualification_ready,
            "incomplete_item_count": len(item_incomplete),
            "incomplete_items": item_incomplete,
            "incomplete_surface": surface_incomplete,
        },
        "surface": surface_manifest,
        "scenarios": scenarios,
    }
    return manifest, errors


def release_qualification_errors(manifest: dict) -> list[str]:
    qualification = manifest["release_qualification"]
    if qualification["ready"]:
        return []
    errors = []
    if qualification["incomplete_item_count"]:
        errors.append(
            f"release qualification has {qualification['incomplete_item_count']} E2E item(s) below connected coverage"
        )
    for field, values in qualification["incomplete_surface"].items():
        if values:
            errors.append(f"release qualification has {len(values)} uncovered production {field}")
    return errors


def check(root: Path = ROOT) -> list[str]:
    manifest, errors = build_manifest(root)
    errors.extend(ui_graph.stale_outputs(root))
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        errors.append(f"generated E2E coverage manifest missing: {MANIFEST.as_posix()}")
        return errors
    expected = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if manifest_path.read_text(errors="strict") != expected:
        errors.append(
            "generated E2E coverage manifest is stale; run "
            "python3 qa/checks/firmware/production_e2e_coverage.py --write"
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate the committed coverage manifest")
    parser.add_argument("--write-baseline", action="store_true", help="write the frozen production source-surface baseline")
    parser.add_argument(
        "--release-qualification",
        action="store_true",
        help="fail unless every stable E2E item and production surface has connected-or-better evidence",
    )
    args = parser.parse_args()

    if args.write_baseline:
        payload = {"schema": 1, "board": "m5stack-cores3", "surface": discover_surface(ROOT)}
        (ROOT / BASELINE).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / BASELINE).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(f"WROTE: {BASELINE}")

    manifest, errors = build_manifest(ROOT)
    if args.write:
        ui_graph.write_outputs(ROOT)
        (ROOT / MANIFEST).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"WROTE: {MANIFEST}")
    else:
        errors.extend(ui_graph.stale_outputs(ROOT))
    if args.release_qualification:
        errors.extend(release_qualification_errors(manifest))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    summary = manifest["coverage_summary"]
    print(
        "PASS: production E2E coverage ratchet "
        f"states={summary['states']['total']} menus={summary['menu_items']['total']} "
        f"actions={summary['actions']['total']} "
        f"items={manifest['item_coverage_summary']['total']} "
        f"item-backlog={manifest['item_coverage_summary']['backlog']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
