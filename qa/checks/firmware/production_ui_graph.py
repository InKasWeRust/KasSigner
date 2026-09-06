#!/usr/bin/env python3
"""Validate and generate the authoritative production M5Stack UI graph artifacts."""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GRAPH_FILE = Path("apps/signer-firmware/src/runtime/navigation/ui_graph.rs")
GRAPH_PARTS = (
    GRAPH_FILE,
    Path("apps/signer-firmware/src/runtime/navigation/ui_graph/states.rs"),
    Path("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs"),
)
STATE_FILE = Path("apps/signer-firmware/src/runtime/input/state.rs")
JSON_OUTPUT = Path("qa/config/workflow/production_ui_graph.json")
MARKDOWN_OUTPUT = Path("qa/generated/production_ui_map.md")
EXCLUDED_STATE_CFG = ("developer-ui", "workflow-tests", "waveshare", "qemu")
ALLOWED_OWNERS = {"Onboarding", "Main", "Seeds", "Settings", "Signing", "Export", "Storage", "Stego", "Multisig", "Dynamic"}
ALLOWED_KINDS = {"Menu", "Choice", "Input", "Modal", "Result", "Screen"}
ALLOWED_OPERATIONS = {"ConnectKasSee", "DeriveMultisigKpub", "SignTransaction"}
ALLOWED_SPECIAL_BACK = {"-", "workflow-specific", "history"}
ALLOWED_EXTERNAL_ENTRIES = {"ImportExportChoice": "external:legacy-import-export"}

STATE_RE = re.compile(
    r"ui_state!\(\s*([A-Z][A-Za-z0-9_]*)\s*,\s*([A-Za-z]+)\s*,\s*([A-Za-z]+)\s*,\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"\s*\)"
)
MENU_RE = re.compile(
    r"ui_menu!\(\s*([A-Z][A-Za-z0-9_]*)\s*,\s*(\d+)\s*,\s*\"([^\"]+)\"\s*,\s*\"([^\"]+)\"\s*,\s*([A-Z][A-Za-z0-9_]*)\s*,\s*\"([^\"]+)\"(?:\s*,\s*([A-Z][A-Za-z0-9_]*))?\s*\)"
)
MENU_SPEC_RE = re.compile(
    r"UiMenuSpec\s*\{\s*state:\s*\"([^\"]+)\"\s*,\s*back:\s*\"([^\"]+)\"\s*,\s*items:\s*&([A-Z0-9_]+)\s*\}"
)


def _read(root: Path, relative: Path) -> str:
    return (root / relative).read_text(encoding="utf-8", errors="strict")


def app_state_names(root: Path) -> list[str]:
    source = _read(root, STATE_FILE)
    body = source.split("pub enum AppState {", 1)[1]
    states: list[str] = []
    pending: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped == "}":
            break
        if stripped.startswith("#["):
            pending.append(stripped)
            continue
        if not stripped or stripped.startswith(("//", "///")):
            continue
        match = re.match(r"([A-Z][A-Za-z0-9_]*)\b", stripped)
        if not match:
            continue
        attrs = " ".join(pending)
        pending.clear()
        if any(token in attrs for token in EXCLUDED_STATE_CFG):
            continue
        states.append(match.group(1))
    return sorted(set(states))


def _graph_source(root: Path) -> str:
    return "\n".join(_read(root, path) for path in GRAPH_PARTS)


def parse_graph(root: Path) -> dict:
    source = _graph_source(root)
    states = [
        {"state": state, "owner": owner, "kind": kind, "entry": entry, "back": back}
        for state, owner, kind, entry, back in STATE_RE.findall(source)
    ]
    menus: dict[str, list[dict]] = defaultdict(list)
    for menu, index, label, action, destination, guard, operation in MENU_RE.findall(source):
        menus[menu].append({
            "index": int(index), "label": label, "action": action,
            "destination": destination, "guard": guard,
            "operation": operation or None,
        })
    menu_specs = [
        {"state": state, "back": back, "items_const": items_const}
        for state, back, items_const in MENU_SPEC_RE.findall(source)
    ]
    for items in menus.values():
        items.sort(key=lambda item: item["index"])
    return {"states": states, "menus": dict(sorted(menus.items())), "menu_specs": menu_specs}


def _is_state_ref(value: str, state_names: set[str]) -> bool:
    return value in state_names


def validate_graph(root: Path) -> list[str]:
    errors: list[str] = []
    graph = parse_graph(root)
    state_rows = graph["states"]
    state_names = [row["state"] for row in state_rows]
    state_set = set(state_names)
    app_states = set(app_state_names(root))

    if len(state_rows) != len(state_set):
        errors.append("production UI graph has duplicate state rows")
    missing = sorted(app_states - state_set)
    extra = sorted(state_set - app_states)
    if missing:
        errors.append("production AppState missing from UI graph: " + ", ".join(missing))
    if extra:
        errors.append("UI graph contains non-production AppState: " + ", ".join(extra))

    row_by_state = {row["state"]: row for row in state_rows}
    for row in state_rows:
        if row["owner"] not in ALLOWED_OWNERS:
            errors.append(f"{row['state']}: invalid UI owner {row['owner']}")
        if row["kind"] not in ALLOWED_KINDS:
            errors.append(f"{row['state']}: invalid UI kind {row['kind']}")
        entry = row["entry"]
        if not (_is_state_ref(entry, state_set) or entry.startswith("boot:") or entry.startswith("external:")):
            errors.append(f"{row['state']}: invalid canonical entry {entry}")
        if entry.startswith("external:") and ALLOWED_EXTERNAL_ENTRIES.get(row["state"]) != entry:
            errors.append(f"{row['state']}: unapproved external UI-graph root {entry}")
        back = row["back"]
        if not (_is_state_ref(back, state_set) or back in ALLOWED_SPECIAL_BACK or back.startswith("dynamic:")):
            errors.append(f"{row['state']}: invalid Back metadata {back}")

    # Canonical entry must terminate at an explicit boot/external root, never a cycle.
    for state in sorted(state_set):
        seen: set[str] = set()
        cursor = state
        while True:
            if cursor in seen:
                errors.append(f"{state}: canonical-entry cycle through {cursor}")
                break
            seen.add(cursor)
            entry = row_by_state[cursor]["entry"]
            if entry.startswith(("boot:", "external:")):
                break
            if entry not in row_by_state:
                errors.append(f"{state}: canonical-entry target {entry} is not a graph state")
                break
            cursor = entry

    menus = graph["menus"]
    spec_by_state = {item["state"]: item for item in graph["menu_specs"]}
    if set(menus) != set(spec_by_state):
        missing_specs = sorted(set(menus) - set(spec_by_state))
        missing_rows = sorted(set(spec_by_state) - set(menus))
        if missing_specs:
            errors.append("UI menus missing UiMenuSpec rows: " + ", ".join(missing_specs))
        if missing_rows:
            errors.append("UiMenuSpec rows missing ui_menu items: " + ", ".join(missing_rows))

    actions: set[str] = set()
    labels: set[str] = set()
    for menu, items in menus.items():
        state_row = row_by_state.get(menu)
        if state_row is None:
            errors.append(f"menu {menu} is not a production UI state")
            continue
        if state_row["kind"] != "Menu":
            errors.append(f"menu {menu} graph state kind is {state_row['kind']}, expected Menu")
        if spec_by_state.get(menu, {}).get("back") != state_row["back"]:
            errors.append(f"menu {menu} Back metadata disagrees between state/menu rows")
        indexes = [item["index"] for item in items]
        if indexes != list(range(len(items))):
            errors.append(f"menu {menu} indexes are not contiguous from zero: {indexes}")
        for item in items:
            if item["action"] in actions:
                errors.append(f"duplicate production UI action ID: {item['action']}")
            actions.add(item["action"])
            labels.add(item["label"])
            if item["destination"] not in state_set:
                errors.append(f"{menu}[{item['index']}] destination {item['destination']} is not a production state")
            if not item["guard"]:
                errors.append(f"{menu}[{item['index']}] has an empty availability guard")
            operation = item.get("operation")
            if operation is not None and operation not in ALLOWED_OPERATIONS:
                errors.append(f"{menu}[{item['index']}] has unknown operation {operation}")

    return errors


def build_document(root: Path) -> dict:
    errors = validate_graph(root)
    if errors:
        raise ValueError("; ".join(errors))
    graph = parse_graph(root)
    labels = sorted({item["label"] for items in graph["menus"].values() for item in items})
    return {
        "schema": 1,
        "sources": [path.as_posix() for path in GRAPH_PARTS],
        "state_count": len(graph["states"]),
        "menu_count": len(graph["menus"]),
        "menu_item_count": sum(len(items) for items in graph["menus"].values()),
        "unique_menu_label_count": len(labels),
        "operation_menu_item_count": sum(
            1 for items in graph["menus"].values() for item in items if item.get("operation")
        ),
        "operation_kinds": sorted({
            item["operation"] for items in graph["menus"].values()
            for item in items if item.get("operation")
        }),
        "external_entry_exceptions": ALLOWED_EXTERNAL_ENTRIES,
        "states": graph["states"],
        "menus": [
            {
                "state": spec["state"],
                "back": spec["back"],
                "items": graph["menus"][spec["state"]],
            }
            for spec in graph["menu_specs"]
        ],
        "unique_menu_labels": labels,
    }


def render_markdown(document: dict) -> str:
    out = [
        "# KasSigner Production UI Map\n\n",
        "> Generated from the production UI graph under `apps/signer-firmware/src/runtime/navigation/ui_graph.rs` and `ui_graph/`. Do not edit this file by hand.\n\n",
        f"Production state families: **{document['state_count']}**  \n",
        f"Declared menus: **{document['menu_count']}**  \n",
        f"Menu rows: **{document['menu_item_count']}**  \n",
        f"Unique menu labels: **{document['unique_menu_label_count']}**  \n"
        f"Menu-triggered operation rows: **{document['operation_menu_item_count']}**  \n"
        f"Operation kinds: **{', '.join(document['operation_kinds'])}**\n\n",
        "Stage 3 keeps this graph authoritative for stable production screens/menus and records menu-triggered operations separately from AppState. "
        "`history` Back metadata is resolved by the bounded navigation stack; `workflow-specific` remains reserved for data-driven operation/modal continuations that Stage 3 will separate from screen state.\n\n",
        "## Menus and declared transitions\n\n",
    ]
    for menu in document["menus"]:
        out.append(f"### {menu['state']}\n\n")
        out.append(f"Back: `{menu['back']}`\n\n")
        out.append("| # | Label | Action ID | Guard | Stable destination | Operation |\n")
        out.append("|---:|---|---|---|---|---|\n")
        for item in menu["items"]:
            out.append(
                f"| {item['index']} | {item['label']} | `{item['action']}` | `{item['guard']}` | "
                f"`{item['destination']}` | `{item.get('operation') or '-'}` |\n"
            )
        out.append("\n")
    out.append("## Production state inventory\n\n")
    out.append("| State | Owner | Kind | Canonical entry | Back metadata |\n")
    out.append("|---|---|---|---|---|\n")
    for state in document["states"]:
        out.append(
            f"| `{state['state']}` | {state['owner']} | {state['kind']} | `{state['entry']}` | `{state['back']}` |\n"
        )
    out.append("\n## Explicit entry exceptions\n\n")
    for state, reason in document["external_entry_exceptions"].items():
        out.append(f"- `{state}`: `{reason}`. This is explicit so legacy reachability cannot be mistaken for a normal production root.\n")
    return "".join(out)


def expected_outputs(root: Path) -> dict[Path, str]:
    document = build_document(root)
    return {
        JSON_OUTPUT: json.dumps(document, indent=2, sort_keys=False) + "\n",
        MARKDOWN_OUTPUT: render_markdown(document),
    }


def stale_outputs(root: Path) -> list[str]:
    errors = validate_graph(root)
    if errors:
        return errors
    for relative, expected in expected_outputs(root).items():
        path = root / relative
        if not path.is_file() or path.read_text(encoding="utf-8", errors="strict") != expected:
            errors.append(f"generated production UI graph artifact is stale: {relative.as_posix()}")
    return errors


def write_outputs(root: Path) -> None:
    for relative, content in expected_outputs(root).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="regenerate JSON and Markdown artifacts")
    args = parser.parse_args()
    if args.write:
        try:
            write_outputs(ROOT)
        except ValueError as error:
            print(f"ERROR: {error}")
            return 1
        document = build_document(ROOT)
        print(
            "PASS: production UI graph generated "
            f"states={document['state_count']} menus={document['menu_count']} "
            f"rows={document['menu_item_count']} labels={document['unique_menu_label_count']}"
        )
        return 0
    errors = stale_outputs(ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    document = build_document(ROOT)
    print(
        "PASS: authoritative production UI graph "
        f"states={document['state_count']} menus={document['menu_count']} "
        f"rows={document['menu_item_count']} labels={document['unique_menu_label_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
