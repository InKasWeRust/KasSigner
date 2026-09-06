#!/usr/bin/env bash
# Verified user-local rustup bootstrap shared by Linux QA/build tooling.
# Safe to source; direct execution supports --ensure-rustup and --ensure-toolchain <name>.

_kassigner_rustup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [[ -r "${_kassigner_rustup_root}/qa/config/toolchains.env" ]]; then
    # shellcheck disable=SC1091
    source "${_kassigner_rustup_root}/qa/config/toolchains.env"
fi

kassigner_prepend_cargo_bin() {
    local cargo_bin="${CARGO_HOME:-${HOME}/.cargo}/bin"
    case ":${PATH}:" in
        *":${cargo_bin}:"*) ;;
        *) export PATH="${cargo_bin}:${PATH}" ;;
    esac
    hash -r 2>/dev/null || true
}

kassigner_rustup_host_tuple() {
    local machine system
    machine="$(uname -m)"
    system="$(uname -s)"
    [[ "$system" == "Linux" ]] || {
        printf 'ERROR: automatic rustup bootstrap currently supports Linux only (found %s).\n' "$system" >&2
        return 2
    }
    case "$machine" in
        x86_64|amd64) printf 'x86_64-unknown-linux-gnu\n' ;;
        aarch64|arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
        *)
            printf 'ERROR: unsupported Linux CPU for automatic rustup bootstrap: %s\n' "$machine" >&2
            return 2
            ;;
    esac
}

kassigner_ensure_rustup() {
    kassigner_prepend_cargo_bin
    if command -v rustup >/dev/null 2>&1; then
        return 0
    fi

    command -v curl >/dev/null 2>&1 || {
        printf 'ERROR: rustup is missing and curl is required for automatic installation.\n' >&2
        return 2
    }
    command -v sha256sum >/dev/null 2>&1 || {
        printf 'ERROR: rustup is missing and sha256sum is required for verified installation.\n' >&2
        return 2
    }

    local version="${KASSIGNER_RUSTUP_VERSION:?KASSIGNER_RUSTUP_VERSION is not set}"
    local host base cache installer checksum expected actual
    host="$(kassigner_rustup_host_tuple)" || return $?
    base="https://static.rust-lang.org/rustup/archive/${version}/${host}/rustup-init"
    cache="${_kassigner_rustup_root}/target/qa/toolchains/rustup-${version}-${host}"
    installer="${cache}/rustup-init"
    checksum="${cache}/rustup-init.sha256"
    mkdir -p "$cache"

    printf 'rustup is missing; downloading pinned rustup %s for %s...\n' "$version" "$host"
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        "$base" --output "$installer" || return $?
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        "${base}.sha256" --output "$checksum" || return $?

    expected="$(awk 'NR == 1 {print $1}' "$checksum")"
    [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || {
        printf 'ERROR: invalid rustup checksum document from static.rust-lang.org.\n' >&2
        return 2
    }
    actual="$(sha256sum "$installer" | awk '{print $1}')"
    [[ "${actual,,}" == "${expected,,}" ]] || {
        printf 'ERROR: rustup-init SHA-256 mismatch. expected=%s actual=%s\n' "$expected" "$actual" >&2
        return 2
    }

    chmod 700 "$installer"
    RUSTUP_INIT_SKIP_PATH_CHECK=yes "$installer" \
        -y --no-modify-path --profile minimal --default-toolchain none || return $?
    kassigner_prepend_cargo_bin
    command -v rustup >/dev/null 2>&1 || {
        printf 'ERROR: verified rustup installation completed but rustup is not available.\n' >&2
        return 2
    }
    printf 'Installed rustup %s under %s.\n' "$version" "${CARGO_HOME:-${HOME}/.cargo}"
}

kassigner_ensure_rust_toolchain() {
    local toolchain="$1"
    shift || true
    kassigner_ensure_rustup || return $?
    if rustup run "$toolchain" rustc --version >/dev/null 2>&1; then
        return 0
    fi
    printf 'Installing pinned Rust toolchain %s...\n' "$toolchain"
    rustup toolchain install "$toolchain" --profile minimal "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --ensure-rustup)
            kassigner_ensure_rustup
            ;;
        --ensure-toolchain)
            [[ -n "${2:-}" ]] || { echo 'ERROR: --ensure-toolchain requires a toolchain name.' >&2; exit 2; }
            shift
            kassigner_ensure_rust_toolchain "$@"
            ;;
        *)
            echo 'Usage: scripts/linux/lib/rustup_bootstrap.sh --ensure-rustup | --ensure-toolchain TOOLCHAIN [rustup install args...]' >&2
            exit 2
            ;;
    esac
fi
