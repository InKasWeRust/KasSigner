"""Context-aware reuse planning for development mutation-testing iterations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


_FINGERPRINT_FIELDS = ("package", "file", "function", "replacement", "genre", "diff")


def outcome_name(outcome: dict[str, Any]) -> str | None:
    scenario = outcome.get("scenario")
    if not isinstance(scenario, dict):
        return None
    mutant = scenario.get("Mutant")
    if not isinstance(mutant, dict):
        return None
    name = mutant.get("name")
    return name if isinstance(name, str) and name else None


def _mutant_name(mutant: dict[str, Any]) -> str:
    name = mutant.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("mutant inventory entry has no non-empty name")
    return name


def load_mutant_inventory(path: Path) -> list[dict[str, Any]]:
    """Load cargo-mutants' JSON inventory and reject ambiguous identities."""
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"mutation inventory cannot be read: {error}") from error
    return validate_mutant_inventory(document)


def validate_mutant_inventory(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, list):
        raise ValueError("mutation inventory root must be an array")
    inventory: list[dict[str, Any]] = []
    names: set[str] = set()
    for entry in document:
        if not isinstance(entry, dict):
            raise ValueError("mutation inventory entries must be objects")
        name = _mutant_name(entry)
        if name in names:
            raise ValueError(f"duplicate mutant identity in inventory: {name}")
        names.add(name)
        inventory.append(entry)
    return inventory


def mutant_context_sha256(mutant: dict[str, Any]) -> str:
    """Fingerprint the exact mutation and source context, independent of test outcomes."""
    payload = {field: mutant.get(field) for field in _FINGERPRINT_FIELDS}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def inventory_sha256(inventory: list[dict[str, Any]]) -> str:
    """Digest the complete current mutant identity/context inventory."""
    records = [
        {"name": _mutant_name(mutant), "context_sha256": mutant_context_sha256(mutant)}
        for mutant in inventory
    ]
    records.sort(key=lambda item: item["name"])
    encoded = json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def plan_incremental_reuse(
    previous_outcomes: dict[str, Any],
    previous_inventory: list[dict[str, Any]],
    current_inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    """Carry only caught/unviable outcomes whose exact identity and source context are unchanged."""
    previous_by_name = {_mutant_name(item): item for item in previous_inventory}
    current_by_name = {_mutant_name(item): item for item in current_inventory}

    caught_names = {
        name
        for outcome in previous_outcomes.get("outcomes", [])
        if isinstance(outcome, dict)
        and outcome.get("summary") == "CaughtMutant"
        and (name := outcome_name(outcome)) is not None
    }
    unviable_names = {
        name
        for outcome in previous_outcomes.get("outcomes", [])
        if isinstance(outcome, dict)
        and outcome.get("summary") == "Unviable"
        and (name := outcome_name(outcome)) is not None
    }
    stable_names = {
        name
        for name in previous_by_name.keys() & current_by_name.keys()
        if mutant_context_sha256(previous_by_name[name])
        == mutant_context_sha256(current_by_name[name])
    }
    carry_caught = sorted(caught_names & stable_names)
    carry_unviable = sorted(unviable_names & stable_names)
    skip_names = sorted(set(carry_caught) | set(carry_unviable))
    current_names = set(current_by_name)
    previous_names = set(previous_by_name)
    changed = sorted(
        name
        for name in previous_names & current_names
        if name not in stable_names
    )
    new = sorted(current_names - previous_names)
    removed = sorted(previous_names - current_names)
    rerun = sorted(current_names - set(skip_names))
    return {
        "schema_version": 1,
        "current_mutants": len(current_names),
        "previous_mutants": len(previous_names),
        "carried_forward_caught": len(carry_caught),
        "carried_forward_unviable": len(carry_unviable),
        "rerun_mutants": len(rerun),
        "changed_same_identity": len(changed),
        "new_mutants": len(new),
        "removed_mutants": len(removed),
        "carry_caught_names": carry_caught,
        "carry_unviable_names": carry_unviable,
        "skip_names": skip_names,
        "rerun_names": rerun,
        "changed_names": changed,
        "new_names": new,
        "removed_names": removed,
        "current_inventory_sha256": inventory_sha256(current_inventory),
    }


def carry_forward_document(
    previous: dict[str, Any],
    carry_caught_names: list[str],
    carry_unviable_names: list[str],
) -> dict[str, Any]:
    """Retain only baseline plus context-proven caught/unviable development outcomes."""
    carry_caught = set(carry_caught_names)
    carry_unviable = set(carry_unviable_names)
    baseline = next(
        (
            outcome
            for outcome in previous.get("outcomes", [])
            if isinstance(outcome, dict) and outcome_name(outcome) is None
        ),
        None,
    )
    carried = [
        outcome
        for outcome in previous.get("outcomes", [])
        if isinstance(outcome, dict)
        and (
            (outcome.get("summary") == "CaughtMutant" and outcome_name(outcome) in carry_caught)
            or (outcome.get("summary") == "Unviable" and outcome_name(outcome) in carry_unviable)
        )
    ]
    outcomes = ([baseline] if baseline is not None else []) + carried
    version = previous.get("cargo_mutants_version") or previous.get("version")
    return {
        "outcomes": outcomes,
        "total_mutants": len(carried),
        "missed": 0,
        "caught": len(carry_caught),
        "timeout": 0,
        "unviable": len(carry_unviable),
        "success": True,
        "start_time": previous.get("start_time"),
        "end_time": previous.get("end_time"),
        "cargo_mutants_version": version,
    }



def write_iterate_skip_state(
    results: Path,
    carry_caught_names: list[str],
    carry_unviable_names: list[str],
) -> None:
    """Seed cargo-mutants --iterate with only context-proven reusable mutants."""
    reusable = sorted(set(carry_caught_names) | set(carry_unviable_names))
    skip_text = "\n".join(reusable)
    if skip_text:
        skip_text += "\n"

    # cargo-mutants --iterate reads caught.txt, previously_caught.txt, and
    # unviable.txt before rotating the output directory. Clear the live outcome
    # lists so only our context-proven skip set can be inherited.
    (results / "caught.txt").write_text("")
    (results / "unviable.txt").write_text("")
    (results / "previously_caught.txt").write_text(skip_text)



def copy_carried_result_files(
    previous_results: Path,
    current_results: Path,
    carried_document: dict[str, Any],
) -> None:
    """Copy logs/diffs only for outcomes intentionally carried into current evidence."""
    if not previous_results.is_dir() or not current_results.is_dir():
        return
    relative_paths: set[Path] = set()
    for outcome in carried_document.get("outcomes", []):
        if not isinstance(outcome, dict) or outcome_name(outcome) is None:
            continue
        for field in ("log_path", "diff_path"):
            value = outcome.get(field)
            if isinstance(value, str) and value:
                relative_paths.add(Path(value))
    for relative in sorted(relative_paths):
        source = previous_results / relative
        destination = current_results / relative
        if not source.is_file() or destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
