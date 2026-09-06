#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Funded testnet E2E"
cd "$ROOT"
# Use the same pinned stable Rust toolchain as the rest of release QA.
# shellcheck source=qa/config/toolchains.env
source "$ROOT/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "$ROOT/scripts/linux/lib/rustup_bootstrap.sh"
kassigner_ensure_rust_toolchain "$KASSIGNER_STABLE_RUST" || exit $?
export KASSIGNER_STABLE_RUST

if (($# != 0)); then
  echo "Usage: $0" >&2
  echo "The funded E2E asks for the public Kaspa testnet interactively before creating/loading a wallet." >&2
  exit 2
fi

python3 qa/checks/integration/funded_testnet_e2e.py
