#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Real-node integration"
cd "$ROOT"
# shellcheck source=qa/config/toolchains.env
source "$ROOT/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "$ROOT/scripts/linux/lib/rustup_bootstrap.sh"
kassigner_ensure_rust_toolchain "$KASSIGNER_STABLE_RUST" || exit $?
# shellcheck source=scripts/linux/lib/cargo_locks.sh
source "$ROOT/scripts/linux/lib/cargo_locks.sh"

if (($# != 0)); then
  echo "Usage: $0" >&2
  echo "This gate uses Kaspa's public-node resolver only; no local-node mode exists." >&2
  exit 2
fi

echo "==> Reconciling/verifying host Cargo.lock files under pinned Cargo $KASSIGNER_STABLE_RUST"
kassigner_reconcile_host_locks "$ROOT"

echo "==> Building the real KasSee WebAssembly package"
make kassee

echo "==> Real Kaspa public-node integration (official resolver pool)"
REAL_NODE_EVIDENCE="target/qa/security/real-node-integration.json"
python3 qa/checks/integration/real_node_browser.py --evidence "$REAL_NODE_EVIDENCE"

# A production-hardening run already captures this gate itself. For a standalone
# rerun, complete a prior hardening run only when this was its sole failure and
# immutable mutation/test provenance still matches the current tree.
if [[ -z "${KASSIGNER_SECURITY_RUN_DIR:-}" && -z "${KASSIGNER_QA_CATALOG_ACTIVE:-}" ]]; then
  python3 qa/checks/security/complete_hardening.py --real-node-evidence "$REAL_NODE_EVIDENCE"
fi
