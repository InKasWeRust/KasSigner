#!/usr/bin/env python3
"""Validate/generate graph-derived production runtime qualification requirements."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import production_ui_graph as ui_graph  # noqa: E402

MANIFEST = Path("qa/config/workflow/production_e2e_manifest.json")
SCENARIOS = Path("qa/config/workflow/production_e2e_scenarios.json")
OUTPUT = Path("qa/config/workflow/production_runtime_qualification.json")
ROUTING = Path("apps/signer-firmware/src/runtime/input/routing.rs")
REDRAW_ROOT = Path("apps/signer-firmware/src/ui/redraw")
REDRAW_DISPATCH = Path("apps/signer-firmware/src/ui/redraw.rs")
RUNTIME_EVIDENCE = Path("apps/signer-firmware/src/ui/runtime_evidence.rs")
MENU_CATALOG = Path("apps/signer-firmware/src/runtime/navigation/menu_reducer/catalog.rs")
MENU_ROUTES = Path("apps/signer-firmware/src/runtime/navigation/menu_reducer/routes.rs")
MENU_REDUCER = Path("apps/signer-firmware/src/runtime/navigation/menu_reducer.rs")
RUNTIME_GUI = Path("apps/signer-firmware/src/runtime/workflow_tests/connected/runtime_gui.rs")
OPERATIONS = Path("apps/signer-firmware/src/runtime/event_loop/operation_engine/mod.rs")
STAGE5_TEST = Path("qa/tests/regression/test_bounded_operation_liveness.py")

RENDER_PREFIX = "KASSIGNER_UI_RUNTIME: RENDER "
RENDER_MISS_PREFIX = "KASSIGNER_UI_RUNTIME: RENDER-MISS "
FAULT_ACTION = "recoverable-operation-timeout"
RETIRED_DESTRUCTIVE_NORMAL_ACTIONS = ("PopItConfirm",)


def read(root: Path, relative: Path) -> str:
    return (root / relative).read_text(encoding="utf-8", errors="strict")


def manifest(root: Path) -> dict:
    return json.loads(read(root, MANIFEST))


def connected_states(document: dict) -> list[str]:
    surface = document.get("surface", {}).get("states", {})
    return sorted(name for name, evidence in surface.items() if evidence.get("highest_level") == "connected")


def workflow_e2e_physical_states(root: Path) -> list[str]:
    document = json.loads(read(root, SCENARIOS))
    states = document.get("workflow_e2e_physical_render_states", [])
    if not isinstance(states, list) or not all(isinstance(state, str) and state for state in states):
        return []
    return states


def parse_route_pairs(source: str) -> dict[tuple[str, int], set[str]]:
    pairs: dict[tuple[str, int], set[str]] = {}
    pattern = re.compile(
        r"\(\s*([A-Z][A-Za-z0-9_]*)\s*,\s*(\d+)\s*\)\s*=>\s*"
        r"(?:(?:return\s+None)|([A-Z][A-Za-z0-9_]*))"
    )
    for state, index, destination in pattern.findall(source):
        if not destination:
            continue
        pairs.setdefault((state, int(index)), set()).add(destination)
    return pairs


def guard_vocabulary(source: str) -> set[str]:
    body = source.split("fn guard_allows", 1)[1]
    return set(re.findall(r'"([a-z0-9_]+)"', body))


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    graph_errors = ui_graph.validate_graph(root)
    errors.extend(f"UI graph: {error}" for error in graph_errors)
    if graph_errors:
        return errors

    graph = ui_graph.parse_graph(root)
    state_names = sorted(row["state"] for row in graph["states"])
    state_set = set(state_names)
    doc = manifest(root)
    expected_connected = connected_states(doc)
    if len(expected_connected) != doc.get("coverage_summary", {}).get("states", {}).get("connected"):
        errors.append("connected stable-state count disagrees with E2E coverage summary")
    if not expected_connected:
        errors.append("runtime qualification has no connected stable-screen families")
    unknown_connected = sorted(set(expected_connected) - state_set)
    if unknown_connected:
        errors.append("runtime qualification references unknown stable states: " + ", ".join(unknown_connected))

    physical_states = workflow_e2e_physical_states(root)
    if not physical_states:
        errors.append("workflow-e2e physical-render scope is empty or malformed")
    if physical_states != sorted(set(physical_states)):
        errors.append("workflow-e2e physical-render scope must be unique and sorted")
    unknown_physical = sorted(set(physical_states) - state_set)
    if unknown_physical:
        errors.append("workflow-e2e physical-render scope references unknown states: " + ", ".join(unknown_physical))
    nonconnected_physical = sorted(set(physical_states) - set(expected_connected))
    if nonconnected_physical:
        errors.append("workflow-e2e physical-render scope must be connected states: " + ", ".join(nonconnected_physical))
    connected_scenario_states = {
        state
        for scenario in json.loads(read(root, SCENARIOS)).get("scenarios", [])
        if scenario.get("status") == "implemented" and scenario.get("level") == "connected"
        for state in scenario.get("states", [])
    }
    unclaimed_physical = sorted(set(physical_states) - connected_scenario_states)
    if unclaimed_physical:
        errors.append("workflow-e2e physical-render states lack an implemented connected scenario: " + ", ".join(unclaimed_physical))

    routing = read(root, ROUTING)
    renderers = "\n".join(path.read_text(encoding="utf-8") for path in sorted((root / REDRAW_ROOT).rglob("*.rs")))
    missing_handler = [state for state in state_names if not re.search(rf"\b{re.escape(state)}\b", routing)]
    missing_renderer = [state for state in state_names if not re.search(rf"\b{re.escape(state)}\b", renderers)]
    if missing_handler:
        errors.append("stable states missing touch-handler ownership: " + ", ".join(missing_handler))
    if missing_renderer:
        errors.append("stable states missing redraw ownership: " + ", ".join(missing_renderer))

    catalog = read(root, MENU_CATALOG)
    if ".get(usize::from(index))" not in catalog:
        errors.append("formal menu reducer no longer rejects out-of-range indexes via slice get")

    reducer = read(root, MENU_REDUCER)
    guards = guard_vocabulary(reducer)
    declared_guards = {item["guard"] for items in graph["menus"].values() for item in items}
    missing_guards = sorted(declared_guards - guards)
    if missing_guards:
        errors.append("UI graph guards missing reducer implementations: " + ", ".join(missing_guards))

    route_pairs = parse_route_pairs(read(root, MENU_ROUTES))
    for menu, items in graph["menus"].items():
        for item in items:
            pair = (menu, item["index"])
            destinations = route_pairs.get(pair, set())
            if item["destination"] not in destinations:
                errors.append(
                    f"graph menu route {menu}[{item['index']}] -> {item['destination']} "
                    "has no matching reducer destination"
                )

    redraw = read(root, REDRAW_DISPATCH)
    evidence = read(root, RUNTIME_EVIDENCE)
    if "super::runtime_evidence::record(ad.navigation.app.state, handled);" not in redraw:
        errors.append("workflow runtime redraw no longer records physical-render evidence")
    if RENDER_PREFIX not in evidence or RENDER_MISS_PREFIX not in evidence:
        errors.append("workflow runtime evidence helper does not emit success/miss physical-render evidence")
    if "if handled {" not in evidence:
        errors.append("physical-render evidence is not gated on a successful redraw handler")

    runtime_gui = read(root, RUNTIME_GUI)
    operations = read(root, OPERATIONS)
    if FAULT_ACTION not in runtime_gui:
        errors.append("runtime HIL lacks recoverable cooperative-operation timeout fault injection")
    if "workflow_inject_timeout" not in operations or "cancel_stepped(ad, kind)" not in operations or "fail_recoverable_spec(ad, error)" not in operations:
        errors.append("runtime timeout fault injection does not execute the production cancellation/recovery boundary")
    for token in ("OP-TIMEOUT-01", "ModalState::RecoverableError", "handle_tap"):
        if token not in runtime_gui:
            errors.append(f"runtime timeout fault probe missing {token} recovery assertion")
    if not (root / STAGE5_TEST).is_file():
        errors.append("Stage-5 bounded operation liveness regression is missing")

    # Connected E2E may exercise Pop It controller confirmation states with a
    # synthetic fixture, but the physical runtime probe must stop at the prompt
    # and must never invoke the irreversible provisioning/confirmation action.
    pop_probe = runtime_gui.split("fn probe_pop_it", 1)[1].split("fn probe_receive_change", 1)[0]
    if "Never advance to explanation/confirmation or burn eFuses" not in pop_probe:
        errors.append("Pop It runtime probe no longer documents its non-destructive boundary")
    if "workflow_advanced_select(ad, 3)" not in pop_probe:
        errors.append("Pop It runtime probe no longer reaches the production prompt route")

    return errors


def build_document(root: Path) -> dict:
    errors = validate(root)
    if errors:
        raise ValueError("; ".join(errors))
    e2e = manifest(root)
    graph = ui_graph.parse_graph(root)
    connected = connected_states(e2e)
    physical = workflow_e2e_physical_states(root)
    return {
        "schema": 2,
        "render_marker_prefix": RENDER_PREFIX,
        "render_miss_marker_prefix": RENDER_MISS_PREFIX,
        "stable_state_count": len(graph["states"]),
        "connected_stable_state_count": len(connected),
        "connected_stable_states": connected,
        "workflow_e2e_physical_render_count": len(physical),
        "workflow_e2e_physical_render_states": physical,
        "formal_menu_count": len(graph["menus"]),
        "formal_menu_row_count": sum(len(items) for items in graph["menus"].values()),
        "qualification_contracts": {
            "all_stable_states_have_handler_ownership": True,
            "all_stable_states_have_renderer_ownership": True,
            "all_formal_menu_rows_match_graph_reducer": True,
            "invalid_menu_indexes_fail_closed": True,
            "all_declared_guards_have_reducer_implementation": True,
            "recoverable_operation_timeout_fault_injection": FAULT_ACTION,
            "destructive_sd_and_efuse_remain_explicit_hil": True,
            "all_connected_stable_states_have_static_renderer_ownership": True,
            "full_connected_run_requires_declared_physical_render_states": True,
            "workflow_e2e_is_not_exhaustive_display_burn_in": True,
            "resume_runs_are_not_credited_as_full_physical_qualification": True,
        },
    }


def check(root: Path) -> list[str]:
    errors = validate(root)
    if errors:
        return errors
    expected = build_document(root)
    path = root / OUTPUT
    if not path.is_file():
        return [f"generated runtime qualification manifest missing: {OUTPUT}"]
    actual = json.loads(path.read_text(encoding="utf-8"))
    if actual != expected:
        return ["generated runtime qualification manifest is stale; run production_runtime_qualification.py --write"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        try:
            document = build_document(ROOT)
        except ValueError as error:
            print(f"ERROR: {error}")
            return 1
        path = ROOT / OUTPUT
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            "Production runtime qualification generated: "
            f"stable={document['stable_state_count']} connected-stable={document['connected_stable_state_count']} "
            f"physical-renders={document['workflow_e2e_physical_render_count']} "
            f"menus={document['formal_menu_count']} rows={document['formal_menu_row_count']}"
        )
        return 0
    errors = check(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    document = build_document(ROOT)
    print(
        "PASS: graph-derived runtime qualification is current "
        f"({document['connected_stable_state_count']} connected stable states; "
        f"{document['workflow_e2e_physical_render_count']} workflow-e2e physical renders)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
