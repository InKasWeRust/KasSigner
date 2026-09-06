#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Release readiness"
EVIDENCE_DIR="${KASSIGNER_RELEASE_EVIDENCE_DIR:-}"
SOURCE_SHA256="${KASSIGNER_SOURCE_SHA256:-}"
RELEASE_SHA256="${KASSIGNER_RELEASE_ARTIFACT_SHA256:-}"
RELEASE_MANIFEST="${KASSIGNER_RELEASE_MANIFEST:-}"
TRUST_POLICY="${KASSIGNER_RELEASE_TRUST_POLICY:-}"
TRUST_POLICY_SHA256="${KASSIGNER_RELEASE_TRUST_POLICY_SHA256:-}"
[[ -n "$EVIDENCE_DIR" && -n "$SOURCE_SHA256" && -n "$RELEASE_SHA256" && -n "$RELEASE_MANIFEST" && -n "$TRUST_POLICY" && -n "$TRUST_POLICY_SHA256" ]] || {
  echo 'ERROR: release readiness requires a concrete release artifact and signed evidence.' >&2
  echo 'Set KASSIGNER_RELEASE_EVIDENCE_DIR, KASSIGNER_SOURCE_SHA256, KASSIGNER_RELEASE_ARTIFACT_SHA256, KASSIGNER_RELEASE_MANIFEST, KASSIGNER_RELEASE_TRUST_POLICY, and KASSIGNER_RELEASE_TRUST_POLICY_SHA256.' >&2
  echo 'See qa/release/README.md; these values cannot be synthesized safely by the launcher.' >&2
  exit 2
}
command -v openssl >/dev/null 2>&1 || { echo 'ERROR: OpenSSL is required for Ed25519 release-evidence verification.' >&2; exit 2; }
python3 "$ROOT/qa/checks/release/release_readiness.py" \
  --evidence-dir "$EVIDENCE_DIR" \
  --source-sha256 "$SOURCE_SHA256" \
  --release-artifact-sha256 "$RELEASE_SHA256" \
  --release-manifest "$RELEASE_MANIFEST" \
  --trust-policy "$TRUST_POLICY" \
  --trust-policy-sha256 "$TRUST_POLICY_SHA256"
