#!/usr/bin/env bash
# Provision the exact local toolchain required by the pinned branch-coverage job.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=qa/config/toolchains.env
source "$ROOT_DIR/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "$ROOT_DIR/scripts/linux/lib/rustup_bootstrap.sh"
kassigner_ensure_rustup || exit $?
TOOLCHAIN="${CRAP_BRANCH_TOOLCHAIN:-$KASSIGNER_BRANCH_RUST}"
LLVM_COV_VERSION="${CRAP_LLVM_COV_VERSION:-$KASSIGNER_CARGO_LLVM_COV_VERSION}"
CARGO_CRAP_VERSION="${CRAP_CARGO_CRAP_VERSION:-$KASSIGNER_CARGO_CRAP_VERSION}"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'ERROR: required command not found: %s\n' "$1" >&2
        exit 127
    }
}

ensure_cargo_plugin() {
    local subcommand="$1" package="$2" expected="$3" actual=""
    actual="$(rustup run "$TOOLCHAIN" cargo "$subcommand" --version 2>/dev/null || true)"
    if [[ "$actual" == *" $expected" ]]; then
        printf '  %-16s %s\n' "$package:" "$actual"
        return 0
    fi

    printf 'Installing %s %s for %s...\n' "$package" "$expected" "$TOOLCHAIN"
    local -a install_args=(install "$package" --version "$expected" --locked)
    [[ -z "$actual" ]] || install_args+=(--force)
    rustup run "$TOOLCHAIN" cargo "${install_args[@]}"

    actual="$(rustup run "$TOOLCHAIN" cargo "$subcommand" --version)"
    [[ "$actual" == *" $expected" ]] || {
        printf 'ERROR: expected %s %s, found: %s\n' "$package" "$expected" "$actual" >&2
        exit 2
    }
    printf '  %-16s %s\n' "$package:" "$actual"
}

require_command rustup

printf 'Provisioning pinned branch-coverage tools:\n'
printf '  Toolchain:       %s\n' "$TOOLCHAIN"
if rustup run "$TOOLCHAIN" rustc --version >/dev/null 2>&1; then
    printf '  Rust toolchain:  already installed\n'
else
    rustup toolchain install "$TOOLCHAIN" --profile minimal --component llvm-tools-preview
fi

if rustup component list --toolchain "$TOOLCHAIN" --installed 2>/dev/null \
    | grep -Eq '^llvm-tools'; then
    printf '  LLVM tools:      already installed\n'
else
    rustup component add llvm-tools-preview --toolchain "$TOOLCHAIN"
    rustup component list --toolchain "$TOOLCHAIN" --installed \
        | grep -Eq '^llvm-tools' || {
            printf 'ERROR: llvm-tools-preview is not installed for %s\n' "$TOOLCHAIN" >&2
            exit 2
        }
    printf '  LLVM tools:      installed\n'
fi

ensure_cargo_plugin llvm-cov cargo-llvm-cov "$LLVM_COV_VERSION"
ensure_cargo_plugin crap cargo-crap "$CARGO_CRAP_VERSION"

printf 'Pinned branch-coverage tools are ready.\n'
