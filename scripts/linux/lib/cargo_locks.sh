#!/usr/bin/env bash
# Transactional host Cargo.lock reconciliation under the repository-pinned stable Cargo.
# Intended to be sourced after qa/config/toolchains.env has been loaded.

_KASSIGNER_CARGO_LOCKS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "${_KASSIGNER_CARGO_LOCKS_ROOT}/scripts/linux/lib/rustup_bootstrap.sh"


kassigner_lock_sha256() {
    python3 - "$1" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys
print(sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

kassigner_lock_package_count() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
import tomllib
print(len(tomllib.loads(Path(sys.argv[1]).read_text()).get("package", [])))
PY
}

kassigner_host_cargo_metadata() {
    local root="$1"
    local manifest="$2"
    shift 2
    env -u RUSTC -u RUSTDOC -u CARGO_BUILD_TARGET -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS \
        PATH="${HOME}/.cargo/bin:${PATH}" \
        RUSTUP_TOOLCHAIN="${KASSIGNER_STABLE_RUST}" \
        CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback \
        rustup run "${KASSIGNER_STABLE_RUST}" cargo metadata \
        --manifest-path "${root}/${manifest}" \
        --format-version 1 \
        "$@"
}

kassigner_reconcile_one_host_lock() {
    local root="$1"
    local label="$2"
    local manifest="$3"
    local lock="$4"
    local lock_path="${root}/${lock}"
    local backup output old_hash old_count new_hash new_count

    if output="$(kassigner_host_cargo_metadata "$root" "$manifest" --locked 2>&1 >/dev/null)"; then
        return 0
    fi

    [[ -f "$lock_path" ]] || {
        printf 'ERROR: expected workspace lockfile is missing: %s\n' "$lock" >&2
        return 2
    }

    backup="$(mktemp "${TMPDIR:-/tmp}/kassigner-lock.XXXXXX")"
    cp "$lock_path" "$backup"
    old_hash="$(kassigner_lock_sha256 "$lock_path")"
    old_count="$(kassigner_lock_package_count "$lock_path")"
    printf '%s Cargo.lock is stale under pinned Cargo %s; reconciling transactionally.\n' \
        "$label" "$KASSIGNER_STABLE_RUST"
    printf '  Existing: sha256=%s packages=%s\n' "$old_hash" "$old_count"

    if ! kassigner_host_cargo_metadata "$root" "$manifest" --offline >/dev/null 2>"${backup}.err"; then
        cp "$backup" "$lock_path"
        printf '  Offline reconciliation was insufficient; retrying with registry access.\n'
        if ! kassigner_host_cargo_metadata "$root" "$manifest" >/dev/null 2>"${backup}.err"; then
            cp "$backup" "$lock_path"
            printf 'ERROR: Cargo could not reconcile %s.\n' "$lock" >&2
            cat "${backup}.err" >&2 || true
            rm -f "$backup" "${backup}.err"
            return 2
        fi
    fi
    rm -f "${backup}.err"

    if ! output="$(kassigner_host_cargo_metadata "$root" "$manifest" --locked 2>&1 >/dev/null)"; then
        cp "$backup" "$lock_path"
        printf 'ERROR: reconciled %s still fails Cargo --locked verification.\n%s\n' \
            "$lock" "$output" >&2
        rm -f "$backup"
        return 2
    fi

    new_hash="$(kassigner_lock_sha256 "$lock_path")"
    new_count="$(kassigner_lock_package_count "$lock_path")"
    printf '  Reconciled: sha256=%s packages=%s\n' "$new_hash" "$new_count"
    rm -f "$backup"
}

kassigner_metadata_incompatible_with_rust() {
    local max_rust="$1"
    python3 -c '
import json
import sys

def version_tuple(text):
    parts = [int(p) for p in text.split(".")]
    return tuple((parts + [0, 0, 0])[:3])

limit = version_tuple(sys.argv[1])
data = json.load(sys.stdin)
bad = []
for package in data.get("packages", []):
    rust_version = package.get("rust_version")
    if rust_version and version_tuple(rust_version) > limit:
        bad.append((package.get("name", "?"), package.get("version", "?"), rust_version))
for name, version, rust_version in sorted(bad):
    print(f"{name} {version} requires Rust {rust_version}")
raise SystemExit(1 if bad else 0)
' "$max_rust"
}

kassigner_kassee_lock_msrv_compatible() {
    local root="$1"
    local metadata incompatible
    if ! metadata="$(kassigner_host_cargo_metadata "$root" "apps/kassee-web/Cargo.toml" --filter-platform wasm32-unknown-unknown --locked 2>/dev/null)"; then
        return 1
    fi
    if incompatible="$(printf '%s' "$metadata" | kassigner_metadata_incompatible_with_rust "${KASSIGNER_REPRO_HOST_RUST}")"; then
        return 0
    fi
    [[ -z "$incompatible" ]] || printf '%s\n' "$incompatible" >&2
    return 1
}

kassigner_reconcile_kassee_msrv_lock() {
    local root="$1"
    local lock="$root/apps/kassee-web/Cargo.lock"
    local backup old_hash old_count new_hash new_count metadata incompatible

    if kassigner_kassee_lock_msrv_compatible "$root"; then
        return 0
    fi

    backup="$(mktemp "${TMPDIR:-/tmp}/kassigner-kassee-msrv-lock.XXXXXX")"
    cp "$lock" "$backup"
    old_hash="$(kassigner_lock_sha256 "$lock")"
    old_count="$(kassigner_lock_package_count "$lock")"
    printf 'KasSee Web Cargo.lock is not compatible with reproducible Rust %s; resolving an MSRV-compatible lock transactionally.\n' \
        "$KASSIGNER_REPRO_HOST_RUST"
    printf '  Existing: sha256=%s packages=%s\n' "$old_hash" "$old_count"

    rm -f "$lock"
    if ! kassigner_host_cargo_metadata "$root" "apps/kassee-web/Cargo.toml" --offline >/dev/null 2>"${backup}.err"; then
        rm -f "$lock"
        printf '  Offline MSRV reconciliation was insufficient; retrying with registry access.\n'
        if ! kassigner_host_cargo_metadata "$root" "apps/kassee-web/Cargo.toml" >/dev/null 2>"${backup}.err"; then
            cp "$backup" "$lock"
            printf 'ERROR: Cargo could not resolve an MSRV-compatible KasSee lock.\n' >&2
            cat "${backup}.err" >&2 || true
            rm -f "$backup" "${backup}.err"
            return 2
        fi
    fi
    rm -f "${backup}.err"

    if ! metadata="$(kassigner_host_cargo_metadata "$root" "apps/kassee-web/Cargo.toml" --filter-platform wasm32-unknown-unknown --locked 2>/dev/null)"; then
        cp "$backup" "$lock"
        printf 'ERROR: MSRV-reconciled KasSee lock fails Cargo --locked verification.\n' >&2
        rm -f "$backup"
        return 2
    fi
    if ! incompatible="$(printf '%s' "$metadata" | kassigner_metadata_incompatible_with_rust "${KASSIGNER_REPRO_HOST_RUST}")"; then
        cp "$backup" "$lock"
        printf 'ERROR: no dependency resolution compatible with reproducible Rust %s was produced.\n' \
            "$KASSIGNER_REPRO_HOST_RUST" >&2
        [[ -z "$incompatible" ]] || printf '%s\n' "$incompatible" >&2
        rm -f "$backup"
        return 2
    fi

    new_hash="$(kassigner_lock_sha256 "$lock")"
    new_count="$(kassigner_lock_package_count "$lock")"
    printf '  MSRV-compatible: sha256=%s packages=%s\n' "$new_hash" "$new_count"
    rm -f "$backup"
}

kassigner_reconcile_host_locks() {
    local root="$1"

    kassigner_ensure_rustup || return $?
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR: python3 is required to reconcile pinned Cargo.lock files.\n' >&2
        return 2
    }

    if ! rustup run "${KASSIGNER_STABLE_RUST}" cargo --version >/dev/null 2>&1; then
        printf '==> Installing pinned host Rust %s for lock verification\n' "$KASSIGNER_STABLE_RUST"
        rustup toolchain install "$KASSIGNER_STABLE_RUST" --profile minimal
    fi

    # Mirror the master QA runner's five independent Cargo resolution checks so
    # a freshly extracted release tree converges to the same pinned lock state
    # before either final public-node evidence or reproducible-build evidence.
    kassigner_reconcile_one_host_lock "$root" "Root workspace" "Cargo.toml" "Cargo.lock"
    kassigner_reconcile_one_host_lock "$root" "Signer firmware workspace" "apps/signer-firmware/Cargo.toml" "apps/signer-firmware/Cargo.lock"
    kassigner_reconcile_one_host_lock "$root" "KasSee Web" "apps/kassee-web/Cargo.toml" "apps/kassee-web/Cargo.lock"
    kassigner_reconcile_kassee_msrv_lock "$root"
    kassigner_reconcile_one_host_lock "$root" "External rqrr workspace" "external/rqrr-nostd/Cargo.toml" "external/rqrr-nostd/Cargo.lock"
    kassigner_reconcile_one_host_lock "$root" "Funded/tools workspace" "tools/Cargo.toml" "tools/Cargo.lock"
    kassigner_reconcile_one_host_lock "$root" "QA workspace" "qa/Cargo.toml" "qa/Cargo.lock"
}
