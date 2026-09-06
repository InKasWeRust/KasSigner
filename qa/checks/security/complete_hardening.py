#!/usr/bin/env python3
"""Complete a prior hardening run by supplementing its sole failed real-node gate.

The original gate-results.json is immutable. A standalone real-node rerun may
complete the release evidence only when that gate was the sole failure and the
current mutation production/test provenance exactly matches the successful
mutation evidence from the original run.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SECURITY = ROOT / "target/qa/security"
_SECURITY_DIR = Path(__file__).resolve().parent
if str(_SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(_SECURITY_DIR))

from mutation_support import mutation_scope_sha256, workspace_test_sha256  # noqa: E402

REAL_NODE_GATE = "real Kaspa node integration"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid or missing JSON {path.relative_to(ROOT)}: {error}") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"invalid JSON object: {path.relative_to(ROOT)}")
    return document


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-node-evidence", type=Path, required=True)
    args = parser.parse_args()

    evidence = args.real_node_evidence
    if not evidence.is_absolute():
        evidence = ROOT / evidence
    real_node = load_json(evidence)
    if real_node.get("healthy") is not True or real_node.get("status") != "pass":
        raise SystemExit("ERROR: standalone real-node evidence is not a PASS")

    pointer_path = SECURITY / "latest-run.json"
    if not pointer_path.is_file():
        print("Standalone real-node PASS persisted; there is no previous hardening run to complete.")
        return 0
    pointer = load_json(pointer_path)
    run_value = pointer.get("run_directory")
    if not isinstance(run_value, str) or not run_value:
        raise SystemExit("ERROR: latest hardening pointer has no run_directory")
    run_dir = Path(run_value)
    if not run_dir.is_absolute():
        run_dir = ROOT / run_dir

    gates_path = run_dir / "gate-results.json"
    gates = load_json(gates_path)
    if gates.get("healthy") is True:
        print("Previous production-hardening evidence is already healthy; no supplemental completion was needed.")
        return 0

    failed = gates.get("failed_gates")
    if failed != [REAL_NODE_GATE]:
        print(
            "Standalone real-node PASS persisted, but the previous hardening run had failures other than "
            f"{REAL_NODE_GATE!r}; it was not auto-completed."
        )
        return 0

    mutation = load_json(SECURITY / "mutation-summary.json")
    crypto = load_json(SECURITY / "crypto-mutation-summary.json")
    if mutation.get("healthy") is not True:
        raise SystemExit("ERROR: previous global mutation evidence is not healthy")
    if crypto.get("healthy") is not True:
        raise SystemExit("ERROR: previous cryptographic mutation evidence is not healthy")
    if mutation.get("candidate_certified") is not True:
        raise SystemExit("ERROR: previous global mutation evidence is development-only, not candidate-certified")
    if crypto.get("candidate_certified") is not True:
        raise SystemExit("ERROR: previous cryptographic mutation evidence is development-only, not candidate-certified")

    current_scope = mutation_scope_sha256()
    current_tests = workspace_test_sha256()
    expected_scope = mutation.get("mutation_scope_sha256")
    expected_tests = mutation.get("workspace_test_sha256")
    crypto_scope = crypto.get("mutation_scope_sha256")
    crypto_tests = crypto.get("workspace_test_sha256")
    mismatches: list[str] = []
    if expected_scope != current_scope:
        mismatches.append(f"global mutation production scope: evidence={expected_scope} current={current_scope}")
    if crypto_scope != current_scope:
        mismatches.append(f"crypto mutation production scope: evidence={crypto_scope} current={current_scope}")
    if expected_tests != current_tests:
        mismatches.append(f"global mutation test scope: evidence={expected_tests} current={current_tests}")
    if crypto_tests != current_tests:
        mismatches.append(f"crypto mutation test scope: evidence={crypto_tests} current={current_tests}")
    if mismatches:
        print("Standalone real-node PASS persisted, but prior hardening evidence was not auto-completed:")
        for mismatch in mismatches:
            print(f"  - {mismatch}")
        print("The original hardening evidence was left unchanged rather than reusing stale provenance.")
        return 0

    gate_record = next(
        (gate for gate in gates.get("gates", []) if isinstance(gate, dict) and gate.get("id") == "real-node-integration"),
        None,
    )
    if gate_record is None or gate_record.get("status") != "fail":
        raise SystemExit("ERROR: previous hardening run does not contain the expected failed real-node gate")

    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    completion = {
        "schema_version": 1,
        "healthy": True,
        "completion_mode": "supplemental-sole-failed-gate-rerun",
        "completed_at_utc": completed_at,
        "base_run_directory": relative(run_dir),
        "base_gate_results": relative(gates_path),
        "base_gate_results_sha256": sha256_file(gates_path),
        "base_failed_gates": [REAL_NODE_GATE],
        "supplemental_gate": {
            "id": "real-node-integration",
            "name": REAL_NODE_GATE,
            "status": "pass",
            "evidence": relative(evidence),
            "evidence_sha256": sha256_file(evidence),
        },
        "provenance": {
            "mutation_scope_sha256": current_scope,
            "workspace_test_sha256": current_tests,
            "global_mutation_score_percent": mutation.get("score_percent"),
            "global_mutation_timeouts": mutation.get("counts", {}).get("timeout"),
            "crypto_mutation_score_percent": crypto.get("score_percent"),
            "crypto_mutation_remaining_missed": crypto.get("counts", {}).get("remaining_missed"),
            "crypto_mutation_timeouts": crypto.get("counts", {}).get("timeout"),
        },
        "statement": (
            "The original hardening run is completed by a later standalone rerun of its sole failed "
            "real Kaspa node integration gate. The original gate-results.json remains unchanged; "
            "reuse is permitted only because mutation production and workspace-test provenance are identical."
        ),
    }
    run_completion = run_dir / "hardening-completion.json"
    run_completion.write_text(json.dumps(completion, indent=2, sort_keys=True) + "\n")
    (SECURITY / "hardening-completion.json").write_text(
        json.dumps(completion, indent=2, sort_keys=True) + "\n"
    )

    pointer.update(
        {
            "healthy": True,
            "base_run_healthy": False,
            "completion_record": relative(run_completion),
            "completed_by_supplemental_gate": "real-node-integration",
        }
    )
    pointer_path.write_text(json.dumps(pointer, indent=2, sort_keys=True) + "\n")

    packager = ROOT / "qa/checks/security/package_artifacts.py"
    for mode in ("healthy", "evidence"):
        result = subprocess.run([sys.executable, str(packager), "--mode", mode], cwd=ROOT)
        if result.returncode != 0:
            raise SystemExit(f"ERROR: hardening {mode} package refresh failed after supplemental completion")

    print("PASS: previous production-hardening run completed by the standalone real-node PASS.")
    print(f"Completion record: {relative(run_completion)}")
    print("Healthy bundle: target/qa/security/hardening/kassigner-production-hardening.zip")
    print("Evidence bundle: target/qa/security/hardening/kassigner-production-hardening-evidence.zip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
