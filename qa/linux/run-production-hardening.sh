#!/usr/bin/env bash
# Compatibility alias for the authoritative non-hardware QA catalog.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Production hardening compatibility alias"
FUZZ_PASSES="${FUZZ_PASSES:-100000}"
printf 'NOTE: production hardening is now an alias for the authoritative make qa catalog.\n' >&2
printf '      Physical/HIL tests remain explicit make test-hardware/workflow-* commands.\n' >&2
bash "$ROOT/qa/linux/run-all.sh" --profile full --fuzz-passes "$FUZZ_PASSES" "$@"
