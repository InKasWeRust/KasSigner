#!/usr/bin/env bash
# Provision, run, validate, and package the pinned-nightly branch-coverage job.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT_DIR/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Pinned branch coverage"
# shellcheck source=qa/config/toolchains.env
source "$ROOT_DIR/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "$ROOT_DIR/scripts/linux/lib/rustup_bootstrap.sh"
kassigner_ensure_rustup || exit $?
TOOLCHAIN="$KASSIGNER_BRANCH_RUST"
LLVM_COV_VERSION="$KASSIGNER_CARGO_LLVM_COV_VERSION"
CARGO_CRAP_VERSION="$KASSIGNER_CARGO_CRAP_VERSION"
CRAP_DIR="$ROOT_DIR/target/qa/crap"
TARGET_BUNDLE="$ROOT_DIR/target/qa/kassigner-branch-coverage.zip"
TARGET_BUNDLE_SHA256="$TARGET_BUNDLE.sha256"

step() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

verify_version() {
    local label="$1" actual="$2" expected="$3"
    [[ "$actual" == "$label $expected" ]] \
        || fail "expected $label $expected, found: $actual"
    printf '  %-18s %s\n' "$label:" "$actual"
}

require_command cargo
require_command install
require_command make
require_command python3
require_command sha256sum

cd "$ROOT_DIR"

step "1/6 Provisioning the pinned nightly and analysis tools"
CRAP_BRANCH_TOOLCHAIN="$TOOLCHAIN" \
CRAP_LLVM_COV_VERSION="$LLVM_COV_VERSION" \
CRAP_CARGO_CRAP_VERSION="$CARGO_CRAP_VERSION" \
scripts/linux/quality/branch-coverage-setup.sh

step "2/6 Verifying exact analysis-tool versions"
llvm_cov_actual="$(rustup run "$TOOLCHAIN" cargo llvm-cov --version)"
cargo_crap_actual="$(rustup run "$TOOLCHAIN" cargo crap --version)"
verify_version "cargo-llvm-cov" "$llvm_cov_actual" "$LLVM_COV_VERSION"
verify_version "cargo-crap" "$cargo_crap_actual" "$CARGO_CRAP_VERSION"

step "3/6 Clearing stale coverage state"
rustup run "$TOOLCHAIN" cargo llvm-cov clean --workspace
rm -rf "$CRAP_DIR"
rm -f "$TARGET_BUNDLE" "$TARGET_BUNDLE_SHA256"

step "4/6 Running pinned-nightly branch coverage"
CRAP_COVERAGE_TOOLCHAIN="$TOOLCHAIN" \
CRAP_ENABLE_BRANCH=1 \
CRAP_BRANCH_TOOLCHAIN="$TOOLCHAIN" \
scripts/linux/quality/crap.sh --strict

step "5/6 Validating persisted branch records and critical-domain ratchets"
python3 qa/checks/quality/crap/package_branch_artifacts.py --validate-only --input-dir "$CRAP_DIR"
python3 qa/checks/security/branch_ratchets.py

step "6/6 Packaging the ephemeral upload bundle under target/qa"
python3 qa/checks/quality/crap/package_branch_artifacts.py --input-dir "$CRAP_DIR" --output "$TARGET_BUNDLE"
[[ -s "$TARGET_BUNDLE" ]] || fail "bundle target did not create: $TARGET_BUNDLE"
(
    cd "$(dirname "$TARGET_BUNDLE")"
    sha256sum "$(basename "$TARGET_BUNDLE")" > "$(basename "$TARGET_BUNDLE_SHA256")"
    sha256sum --check "$(basename "$TARGET_BUNDLE_SHA256")"
)

printf '\nSHA-256:\n'
cat "$TARGET_BUNDLE_SHA256"
printf '\nBranch-coverage job completed successfully.\n'
printf 'Fresh evidence is retained only under target/qa/crap/.\n'
printf 'Optional upload ZIP (ephemeral):\n  %s\n' "$TARGET_BUNDLE"
