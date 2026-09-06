#!/usr/bin/env python3
"""Execute development-incremental or fresh candidate mutation runs."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable

from mutation_support import (
    ROOT, load_run_scope, locate_results, merge_outcome_documents,
    mutation_cache_action, mutation_config_sha256, mutation_scope_sha256,
    read_outcomes, restore_results, run, setup, workspace_test_sha256,
    write_outcome_lists, write_run_scope,
)
from mutation_reuse import (
    carry_forward_document, copy_carried_result_files, inventory_sha256,
    load_mutant_inventory, plan_incremental_reuse, validate_mutant_inventory,
    write_iterate_skip_state,
)


def _mutant_record(outcome: dict[str, Any]) -> dict[str, Any] | None:
    scenario = outcome.get("scenario")
    if not isinstance(scenario, dict):
        return None
    mutant = scenario.get("Mutant")
    return mutant if isinstance(mutant, dict) else None


def _discover_current_mutants(policy: dict[str, Any]) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Ask pinned cargo-mutants for the complete current inventory without executing tests."""
    command = [
        "rustup",
        "run",
        policy["toolchain"],
        "cargo",
        "mutants",
        "--workspace",
        "--test-workspace=true",
        "--list",
        "--json",
    ]
    print("+", " ".join(command), flush=True)
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return None, f"cargo-mutants inventory discovery failed (exit {result.returncode}): {detail}"
    try:
        return validate_mutant_inventory(json.loads(result.stdout)), None
    except (json.JSONDecodeError, ValueError) as error:
        return None, f"cargo-mutants inventory discovery returned invalid JSON: {error}"


def _inventory_from_results(results: Path) -> tuple[list[dict[str, Any]] | None, str | None]:
    try:
        return load_mutant_inventory(results / "mutants.json"), None
    except ValueError as error:
        return None, str(error)


def _outcome_names(document: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for outcome in document.get("outcomes", []):
        if not isinstance(outcome, dict):
            continue
        mutant = _mutant_record(outcome)
        name = mutant.get("name") if mutant is not None else None
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _inventory_names(inventory: list[dict[str, Any]]) -> set[str]:
    return {str(mutant["name"]) for mutant in inventory}


def execute(
    policy: dict[str, Any],
    *,
    install: bool,
    fresh: bool,
    summarize_fn: Callable[[dict[str, Any], Path, Path], tuple[list[str], dict[str, Any]]],
) -> int:
    if install and setup(policy) != 0:
        return 2
    toolchain = policy["toolchain"]
    output_parent = ROOT / policy["output_directory"]
    artifact = ROOT / policy["artifact"]
    use_iterate = bool(policy.get("iterate", True)) and not fresh
    existing = locate_results(output_parent)
    if fresh:
        shutil.rmtree(output_parent, ignore_errors=True)
    elif use_iterate and not (existing / "outcomes.json").is_file():
        restored = restore_results(output_parent)
        if restored:
            restored_results = locate_results(output_parent)
            restored_document, restored_errors = read_outcomes(restored_results)
            if restored_document is not None and not restored_errors:
                print(
                    "Restored persisted mutation checkpoint: "
                    f"{restored_document.get('caught', 0)} caught, "
                    f"{restored_document.get('unviable', 0)} unviable, "
                    f"{restored_document.get('missed', 0)} missed, "
                    f"{restored_document.get('timeout', 0)} timeout"
                )
            else:
                print("Restored persisted mutation checkpoint for development iteration")

    current_scope = mutation_scope_sha256()
    current_test_scope = workspace_test_sha256()
    current_config = mutation_config_sha256()
    existing = locate_results(output_parent)
    prior_run_scope = load_run_scope(existing)
    has_existing_outcomes = (existing / "outcomes.json").is_file()
    cache_action = mutation_cache_action(
        use_iterate=use_iterate,
        has_existing_outcomes=has_existing_outcomes,
        run_scope=prior_run_scope,
        current_scope=current_scope,
        current_test_scope=current_test_scope,
        reuse_unchanged=bool(policy.get("reuse_unchanged_results", True)),
    )

    if cache_action == "fresh-unprovenanced":
        print(
            "Local mutation output has no immutable run provenance; discarding that "
            "interrupted/untrusted output and attempting the persisted checkpoint"
        )
        shutil.rmtree(output_parent, ignore_errors=True)
        existing = locate_results(output_parent)
        has_existing_outcomes = False
        recovered = False
        if use_iterate and restore_results(output_parent):
            existing = locate_results(output_parent)
            restored_document, restored_errors = read_outcomes(existing)
            restored_scope = load_run_scope(existing)
            if restored_document is not None and not restored_errors and restored_scope is not None:
                prior_run_scope = restored_scope
                has_existing_outcomes = True
                cache_action = mutation_cache_action(
                    use_iterate=use_iterate,
                    has_existing_outcomes=True,
                    run_scope=prior_run_scope,
                    current_scope=current_scope,
                    current_test_scope=current_test_scope,
                    reuse_unchanged=bool(policy.get("reuse_unchanged_results", True)),
                )
                recovered = True
                print(
                    "Recovered verified persisted mutation checkpoint after discarding "
                    "unprovenanced local output: "
                    f"{restored_document.get('caught', 0)} caught, "
                    f"{restored_document.get('unviable', 0)} unviable, "
                    f"{restored_document.get('missed', 0)} missed, "
                    f"{restored_document.get('timeout', 0)} timeout"
                )
        if not recovered:
            cache_action = "run"

    if cache_action == "reuse":
        print("Mutation source and workspace tests are unchanged; reusing cumulative evidence")
        # Upgrade legacy exact-match provenance without claiming candidate certification.
        if prior_run_scope is not None and prior_run_scope.get("schema_version") == 1:
            inventory, inventory_error = _inventory_from_results(existing)
            if inventory is not None:
                prior_document, prior_errors = read_outcomes(existing)
                version = policy["cargo_mutants_version"]
                if prior_document is not None and not prior_errors:
                    version = str(
                        prior_document.get("cargo_mutants_version")
                        or prior_document.get("version")
                        or version
                    )
                write_run_scope(
                    existing,
                    source_digest=current_scope,
                    test_digest=current_test_scope,
                    tool_version=version,
                    evidence_mode="development-reused-legacy",
                    candidate_certified=False,
                    config_digest=current_config,
                    inventory_digest=inventory_sha256(inventory),
                )
                print("Upgraded exact-match legacy mutation provenance to schema 2 (development only)")
            elif inventory_error:
                print(f"WARNING: legacy mutation provenance could not be upgraded: {inventory_error}")
        errors, document = summarize_fn(policy, output_parent, artifact)
        print(
            f"Mutation score: {document['score_percent']:.2f}% "
            f"({document['counts']['caught']} caught / {document['viable_mutants']} viable)"
        )
        print(f"Persisted raw mutation evidence: {document['raw_artifact']}")
        for error in errors:
            print(f"ERROR: {error}")
        return 1 if errors else 0

    prior_document: dict[str, Any] | None = None
    prior_backup: Path | None = None
    current_inventory: list[dict[str, Any]] | None = None
    reuse_plan: dict[str, Any] | None = None
    evidence_mode = "certification-fresh" if fresh else "development-full"
    base_source_digest: str | None = None

    if cache_action in {"iterate-source-changed", "iterate-tests-changed"} and has_existing_outcomes:
        complete_prior, prior_errors = read_outcomes(existing)
        if prior_errors or complete_prior is None:
            for error in prior_errors or ["prior mutation evidence is invalid"]:
                print(f"ERROR: {error}")
            return 2

        target_qa = ROOT / "target/qa"
        target_qa.mkdir(parents=True, exist_ok=True)
        prior_backup = (
            Path(tempfile.mkdtemp(prefix="mutation-prior-", dir=target_qa)) / "mutants.out"
        )
        shutil.copytree(existing, prior_backup)

        can_context_reuse = True
        if prior_run_scope is None:
            can_context_reuse = False
        elif prior_run_scope.get("schema_version") == 2:
            if prior_run_scope.get("mutation_config_sha256") != current_config:
                print(
                    "Mutation configuration changed; no old mutants will be skipped in this "
                    "development run"
                )
                can_context_reuse = False
        elif cache_action == "iterate-source-changed":
            # A legacy global digest cannot distinguish source changes from config changes.
            print(
                "Legacy mutation provenance cannot prove the mutation configuration across a "
                "production-source change; running all current mutants once"
            )
            can_context_reuse = False

        previous_inventory: list[dict[str, Any]] | None = None
        if can_context_reuse:
            previous_inventory, previous_inventory_error = _inventory_from_results(existing)
            if previous_inventory is None:
                print(
                    "Mutation inventory is unavailable for context proof; running all current "
                    f"mutants instead ({previous_inventory_error})"
                )
                can_context_reuse = False

        if can_context_reuse:
            current_inventory, discovery_error = _discover_current_mutants(policy)
            if current_inventory is None:
                print(
                    "Mutation inventory discovery could not prove safe reuse; running all current "
                    f"mutants instead ({discovery_error})"
                )
                can_context_reuse = False

        if can_context_reuse:
            assert previous_inventory is not None and current_inventory is not None
            reuse_plan = plan_incremental_reuse(
                complete_prior, previous_inventory, current_inventory
            )
            carry_caught_names = list(reuse_plan["carry_caught_names"])
            carry_unviable_names = list(reuse_plan["carry_unviable_names"])
            prior_document = carry_forward_document(
                complete_prior, carry_caught_names, carry_unviable_names
            )
            write_iterate_skip_state(
                existing, carry_caught_names, carry_unviable_names
            )
            evidence_mode = "development-incremental"
            base_source_digest = (
                prior_run_scope.get("mutation_scope_sha256") if prior_run_scope else None
            )
            print(
                "Context-aware mutation reuse: "
                f"{reuse_plan['carried_forward_caught']} unchanged caught and "
                f"{reuse_plan['carried_forward_unviable']} unchanged unviable mutants carried; "
                f"{reuse_plan['rerun_mutants']} current mutants will run "
                f"({reuse_plan['new_mutants']} new, "
                f"{reuse_plan['changed_same_identity']} same-name/context-changed, "
                f"{reuse_plan['removed_mutants']} removed from the old inventory)"
            )
        else:
            shutil.rmtree(output_parent, ignore_errors=True)
            existing = locate_results(output_parent)
            has_existing_outcomes = False
            if prior_backup is not None:
                shutil.rmtree(prior_backup.parent, ignore_errors=True)
                prior_backup = None

    output_parent.mkdir(parents=True, exist_ok=True)
    command = [
        "rustup",
        "run",
        toolchain,
        "cargo",
        "mutants",
        "--workspace",
        "--test-workspace=true",
        "--output",
        str(output_parent),
    ]
    if prior_document is not None and (locate_results(output_parent) / "outcomes.json").is_file():
        command.append("--iterate")
    result = run(command, check=False)
    results = locate_results(output_parent)
    if result.returncode not in (0, 2, 3) and not results.is_dir():
        if prior_backup is not None:
            shutil.rmtree(prior_backup.parent, ignore_errors=True)
        print(f"ERROR: cargo-mutants failed before producing evidence (exit {result.returncode})")
        return result.returncode or 1

    if prior_document is not None:
        current_document, current_errors = read_outcomes(results)
        if current_errors or current_document is None:
            if prior_backup is not None:
                shutil.rmtree(prior_backup.parent, ignore_errors=True)
            for error in current_errors or ["incremental outcomes are missing"]:
                print(f"ERROR: {error}")
            return 2
        try:
            merged_document = merge_outcome_documents(prior_document, current_document)
        except ValueError as error:
            if prior_backup is not None:
                shutil.rmtree(prior_backup.parent, ignore_errors=True)
            print(f"ERROR: incremental mutation evidence could not be merged: {error}")
            return 2
        assert current_inventory is not None
        missing = _inventory_names(current_inventory) - _outcome_names(merged_document)
        if missing:
            if prior_backup is not None:
                shutil.rmtree(prior_backup.parent, ignore_errors=True)
            print(
                "ERROR: incremental mutation run did not produce outcomes for every current "
                f"mutant ({len(missing)} missing)"
            )
            return 2
        if prior_backup is not None:
            copy_carried_result_files(prior_backup, results, prior_document)
        (results / "outcomes.json").write_text(
            json.dumps(merged_document, indent=2, sort_keys=False) + "\n"
        )
        (results / "mutants.json").write_text(
            json.dumps(current_inventory, indent=2, sort_keys=False) + "\n"
        )
        write_outcome_lists(results, merged_document)
        print(
            "Merged context-proven development outcomes with the current run: "
            f"{current_document.get('total_mutants', 0)} executed, "
            f"{merged_document['total_mutants']} current cumulative"
        )

    final_document, final_errors = read_outcomes(results)
    if final_document is None or final_errors:
        if prior_backup is not None:
            shutil.rmtree(prior_backup.parent, ignore_errors=True)
        for error in final_errors or ["mutation outcomes are unavailable"]:
            print(f"ERROR: {error}")
        return 2

    if current_inventory is None:
        current_inventory, inventory_error = _inventory_from_results(results)
        if current_inventory is None:
            if prior_backup is not None:
                shutil.rmtree(prior_backup.parent, ignore_errors=True)
            print(f"ERROR: current mutation inventory is unavailable: {inventory_error}")
            return 2

    missing = _inventory_names(current_inventory) - _outcome_names(final_document)
    if missing:
        if prior_backup is not None:
            shutil.rmtree(prior_backup.parent, ignore_errors=True)
        print(
            "ERROR: mutation evidence is incomplete for the current inventory "
            f"({len(missing)} missing outcomes)"
        )
        return 2

    final_version = (
        final_document.get("cargo_mutants_version")
        or final_document.get("version")
        or policy["cargo_mutants_version"]
    )
    carried = int(reuse_plan["carried_forward_caught"]) if reuse_plan else 0
    carried_unviable = int(reuse_plan["carried_forward_unviable"]) if reuse_plan else 0
    write_run_scope(
        results,
        source_digest=current_scope,
        test_digest=current_test_scope,
        tool_version=str(final_version),
        evidence_mode=evidence_mode,
        candidate_certified=fresh,
        config_digest=current_config,
        inventory_digest=inventory_sha256(current_inventory),
        carried_forward_caught=carried,
        carried_forward_unviable=carried_unviable,
        base_source_digest=base_source_digest,
    )

    if prior_backup is not None:
        shutil.rmtree(prior_backup.parent, ignore_errors=True)

    errors, document = summarize_fn(policy, output_parent, artifact)
    print(
        f"Mutation score: {document['score_percent']:.2f}% "
        f"({document['counts']['caught']} caught / {document['viable_mutants']} viable)"
    )
    if document.get("candidate_certified"):
        print("Mutation evidence mode: fresh candidate certification")
    else:
        print(
            "Mutation evidence mode: development only; run `make qa` or `python3 qa/checks/security/mutation.py run --fresh` "
            "once the candidate is frozen"
        )
    print(f"Persisted raw mutation evidence: {document['raw_artifact']}")
    for error in errors:
        print(f"ERROR: {error}")
    return 1 if errors else 0
