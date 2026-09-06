# This file is sourced by qa/linux/run-all.sh. If a file manager executes it
# directly, explain that it is a support library and keep the terminal visible.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
    # shellcheck source=qa/linux/lib/terminal_pause.sh
    source "${ROOT_DIR}/qa/linux/lib/terminal_pause.sh"
    kassigner_qa_install_exit_handler "QA runner support library"
    printf 'ERROR: %s is sourced by qa/linux/run-all.sh and is not a standalone QA entrypoint.\n' \
        "${BASH_SOURCE[0]}" >&2
    exit 2
fi

# Shared command execution for the master test runner.
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "${ROOT_DIR}/scripts/linux/lib/rustup_bootstrap.sh"

require_command() {
    if $DRY_RUN; then
        return 0
    fi
    command -v "$1" >/dev/null 2>&1 || {
        print_missing_command_guidance "$1"
        return 127
    }
}

run_in_directory() {
    local directory="$1"
    shift
    printf '  + (cd %q &&' "$directory"
    printf ' %q' "$@"
    printf ')\n'
    if $DRY_RUN; then
        return 0
    fi
    (cd "$directory" && "$@")
}

run_locked_cargo_metadata() {
    local directory="$1"
    local manifest="$2"
    (
        cd "$directory"
        if $REPAIR_LOCKFILES; then
            cargo metadata \
                --manifest-path "$manifest" \
                --format-version 1 \
                --locked \
                >/dev/null
        else
            # Strict Core CI must validate lockfiles with the repository-pinned
            # host Cargo even inside workspaces that select a custom toolchain
            # (notably apps/signer-firmware's `channel = "esp"`).  Setting
            # RUSTUP_TOOLCHAIN overrides directory rust-toolchain.toml files
            # without changing normal firmware development or lock repair.
            RUSTUP_TOOLCHAIN="$KASSIGNER_STABLE_RUST" cargo metadata \
                --manifest-path "$manifest" \
                --format-version 1 \
                --locked \
                >/dev/null
        fi
    )
}

restore_lockfile() {
    local lockfile="$1"
    local backup="$2"
    local existed="$3"
    if [[ "$existed" == true ]]; then
        cp -p "$backup" "$lockfile"
    else
        rm -f "$lockfile"
    fi
}

refresh_cargo_lockfile() {
    local directory="$1"
    local manifest="$2"
    local lockfile="${directory}/Cargo.lock"
    local backup refresh_log existed=false
    backup="$(mktemp)"
    refresh_log="$(mktemp)"

    if [[ -f "$lockfile" ]]; then
        cp -p "$lockfile" "$backup"
        existed=true
    fi

    printf '  ! Locked graph is stale; refreshing %s transactionally.\n' "$lockfile"
    printf '  + (cd %q && cargo metadata --manifest-path %q --format-version 1 --offline >/dev/null)\n' \
        "$directory" "$manifest"

    if ! (
        cd "$directory"
        cargo metadata \
            --manifest-path "$manifest" \
            --format-version 1 \
            --offline \
            >/dev/null
    ) 2>"$refresh_log"; then
        printf '  ! Offline refresh was unavailable; retrying with registry access.\n'
        printf '  + (cd %q && cargo metadata --manifest-path %q --format-version 1 >/dev/null)\n' \
            "$directory" "$manifest"
        if ! (
            cd "$directory"
            cargo metadata \
                --manifest-path "$manifest" \
                --format-version 1 \
                >/dev/null
        ) 2>>"$refresh_log"; then
            printf 'ERROR: Cargo could not refresh %s.\n' "$lockfile" >&2
            cat "$refresh_log" >&2
            restore_lockfile "$lockfile" "$backup" "$existed"
            rm -f "$backup" "$refresh_log"
            return 101
        fi
    fi

    if ! run_locked_cargo_metadata "$directory" "$manifest" 2>>"$refresh_log"; then
        printf 'ERROR: refreshed lockfile still does not resolve under --locked: %s\n' \
            "$lockfile" >&2
        cat "$refresh_log" >&2
        restore_lockfile "$lockfile" "$backup" "$existed"
        rm -f "$backup" "$refresh_log"
        return 101
    fi

    rm -f "$backup" "$refresh_log"
    printf '  ! Refreshed and verified: %s\n' "$lockfile"
}

run_cargo_metadata_check() {
    local directory="$1"
    local manifest="$2"
    local failure_log
    require_command cargo || return
    if $REPAIR_LOCKFILES; then
        printf \
            '  + (cd %q && cargo metadata --manifest-path %q --format-version 1 --locked >/dev/null)\n' \
            "$directory" "$manifest"
    else
        printf \
            '  + (cd %q && RUSTUP_TOOLCHAIN=%q cargo metadata --manifest-path %q --format-version 1 --locked >/dev/null)\n' \
            "$directory" "$KASSIGNER_STABLE_RUST" "$manifest"
    fi
    if $DRY_RUN; then
        return 0
    fi

    failure_log="$(mktemp)"
    if run_locked_cargo_metadata "$directory" "$manifest" 2>"$failure_log"; then
        rm -f "$failure_log"
        return 0
    fi

    cat "$failure_log" >&2
    rm -f "$failure_log"
    if ! $REPAIR_LOCKFILES; then
        printf 'ERROR: locked Cargo graph is stale and --strict-lockfiles was requested.\n' >&2
        return 101
    fi
    refresh_cargo_lockfile "$directory" "$manifest"
}


run_core_ci_gate() {
    require_command rustup || return
    require_command cargo || return
    require_command git || return
    require_command make || return
    require_command tee || return

    local log_dir="${ROOT_DIR}/target/qa/core-ci"
    local log_path="${log_dir}/core-ci.log"
    mkdir -p "$log_dir"

    if $DRY_RUN; then
        printf '  + Core CI log: %s\n' "$log_path"
        printf '  + rustup toolchain install %q --profile minimal --component rustfmt --component clippy\n' "$KASSIGNER_STABLE_RUST"
        printf '  + rustup run %q cargo fmt --all -- --check\n' "$KASSIGNER_STABLE_RUST"
        printf '  + rustup run %q cargo clippy --workspace --all-targets --locked -- -D warnings\n' "$KASSIGNER_STABLE_RUST"
        printf '  + make test STRICT_LOCKFILES=1\n'
        printf '  + git diff --check\n'
        return 0
    fi

    set +e
    (
        set -uo pipefail
        cd "$ROOT_DIR" || exit 1

        echo "===== REPOSITORY ====="
        pwd
        git rev-parse --show-toplevel
        git status --short
        echo

        set -a
        # shellcheck source=qa/config/toolchains.env
        source qa/config/toolchains.env
        set +a

        echo "KASSIGNER_STABLE_RUST=$KASSIGNER_STABLE_RUST"
        echo

        echo "===== INSTALL PINNED CORE TOOLCHAIN ====="
        rustup toolchain install "$KASSIGNER_STABLE_RUST" \
          --profile minimal \
          --component rustfmt \
          --component clippy
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "FAILED: toolchain install (exit $rc)"
            exit "$rc"
        fi

        echo
        echo "===== CORE CI: FORMAT ====="
        rustup run "$KASSIGNER_STABLE_RUST" \
          cargo fmt --all -- --check
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo
            echo "FAILED: CORE FORMAT (exit $rc)"
            exit "$rc"
        fi

        echo
        echo "===== CORE CI: CLIPPY ====="
        rustup run "$KASSIGNER_STABLE_RUST" \
          cargo clippy --workspace --all-targets --locked -- -D warnings
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo
            echo "FAILED: CORE CLIPPY (exit $rc)"
            exit "$rc"
        fi

        echo
        echo "===== CORE CI: TEST ====="
        make test STRICT_LOCKFILES=1
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo
            echo "FAILED: CORE TEST (exit $rc)"
            exit "$rc"
        fi

        echo
        echo "===== FINAL DIFF CHECK ====="
        git diff --check
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo
            echo "FAILED: git diff --check (exit $rc)"
            exit "$rc"
        fi

        echo
        echo "================================"
        echo "ALL CORE CI GATES PASSED LOCALLY"
        echo "================================"
    ) 2>&1 | tee "$log_path"
    local core_rc="${PIPESTATUS[0]}"
    set -e

    {
        echo
        echo "Core CI child exit code: $core_rc"
        echo "Full log: $log_path"
    } | tee -a "$log_path"

    return "$core_rc"
}

run_all_cargo_resolutions() {
    local record directory manifest
    local -a workspaces=(
        "$ROOT_DIR|Cargo.toml"
        "$ROOT_DIR/apps/signer-firmware|Cargo.toml"
        "$ROOT_DIR/apps/kassee-web|Cargo.toml"
        "$ROOT_DIR/tools|Cargo.toml"
        "$ROOT_DIR/qa|Cargo.toml"
    )
    for record in "${workspaces[@]}"; do
        IFS='|' read -r directory manifest <<<"$record"
        run_cargo_metadata_check "$directory" "$manifest" || return $?
    done
}

run_cargo_test() {
    require_command cargo || return
    local -a extra=("$@")
    local -a command=(cargo test "${extra[@]}")
    local qa_workspace=false index
    for ((index = 0; index + 1 < ${#extra[@]}; index++)); do
        if [[ "${extra[index]}" == "--manifest-path" && "${extra[index + 1]}" == "qa/Cargo.toml" ]]; then
            qa_workspace=true
            break
        fi
    done
    if [[ -n "$TEST_FILTER" ]]; then
        command+=("$TEST_FILTER")
        if $EXACT_TEST; then
            command+=(-- --exact)
        fi
    fi
    if $qa_workspace; then
        run_in_directory "$ROOT_DIR" env CARGO_TARGET_DIR="$ROOT_DIR/target/qa" "${command[@]}"
    else
        run_in_directory "$ROOT_DIR" "${command[@]}"
    fi
}

run_firmware_unit_compilation() {
    require_command cargo || return
    local firmware="${ROOT_DIR}/apps/signer-firmware"
    run_in_directory "$firmware" env ESP_HAL_CONFIG_PSRAM_MODE=octal \
        cargo check --locked --no-default-features --features waveshare,verbose-boot || return $?
    run_in_directory "$firmware" \
        cargo check --locked --no-default-features --features m5stack,verbose-boot || return $?
}

registered_fuzz_targets() {
    require_command python3 || return
    python3 "${ROOT_DIR}/qa/checks/security/fuzz_targets.py" --validate
}


ensure_fuzz_toolchain() {
    if ! $DRY_RUN; then
        kassigner_ensure_rustup || return $?
    fi
    require_command rustup || return
    local execution_toolchain="$KASSIGNER_BRANCH_RUST"
    local installer_toolchain="$KASSIGNER_STABLE_RUST"
    local version="$KASSIGNER_CARGO_FUZZ_VERSION"
    if $DRY_RUN; then
        return 0
    fi
    if ! rustup run "$installer_toolchain" rustc --version >/dev/null 2>&1; then
        printf '  ! Pinned cargo-fuzz installer toolchain is missing; installing %s.\n' "$installer_toolchain"
        rustup toolchain install "$installer_toolchain" --profile minimal
    fi
    if ! rustup run "$execution_toolchain" rustc --version >/dev/null 2>&1; then
        printf '  ! Pinned nightly is missing; installing %s.\n' "$execution_toolchain"
        rustup toolchain install "$execution_toolchain" --profile minimal
    fi
    local actual
    actual="$(rustup run "$execution_toolchain" cargo fuzz --version 2>/dev/null || true)"
    if [[ "$actual" != *"cargo-fuzz $version"* ]]; then
        printf '  ! Installing pinned cargo-fuzz %s with stable %s.\n' "$version" "$installer_toolchain"
        rustup run "$installer_toolchain" cargo install cargo-fuzz --version "$version" --locked --force
        actual="$(rustup run "$execution_toolchain" cargo fuzz --version 2>/dev/null || true)"
    fi
    [[ "$actual" == *"cargo-fuzz $version"* ]] || {
        printf 'ERROR: expected cargo-fuzz %s, received: %s\n' "$version" "$actual" >&2
        return 2
    }
}


run_fuzz_targets() {
    require_command cargo || return
    require_command python3 || return
    ensure_fuzz_toolchain || return
    local -a targets=()
    if [[ -n "$FUZZ_TARGET" ]]; then
        targets=("$FUZZ_TARGET")
    else
        mapfile -t targets < <(registered_fuzz_targets)
    fi
    ((${#targets[@]} > 0)) || {
        printf 'ERROR: no fuzz targets are registered\n' >&2
        return 1
    }

    local state_root="${ROOT_DIR}/target/qa/fuzz"
    local status_file="${state_root}/statuses.tsv"
    local artifact_root="${state_root}/artifacts"
    local corpus_root="${state_root}/corpus"
    local actual
    actual="$(rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz --version 2>/dev/null || true)"

    if $DRY_RUN; then
        local target
        for target in "${targets[@]}"; do
            run_in_directory "${ROOT_DIR}/qa/fuzz" env CARGO_TARGET_DIR="$ROOT_DIR/target/qa" \
                rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz run "$target" -- \
                    "-runs=${FUZZ_PASSES}" \
                    "-artifact_prefix=${artifact_root}/${target}/" \
                    "${corpus_root}/${target}" || return $?
        done
        printf '  + python3 qa/checks/security/fuzz_results.py --statuses %q --tool %q --started <utc> --completed <utc> --runs %q\n' \
            "$status_file" "$actual" "$FUZZ_PASSES"
        return 0
    fi

    rm -rf "$state_root"
    mkdir -p "$state_root" "$artifact_root" "$corpus_root"
    : > "$status_file"
    local started completed target target_status
    started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    for target in "${targets[@]}"; do
        local seed_dir="${ROOT_DIR}/qa/fuzz/seeds/${target}"
        local corpus_dir="${corpus_root}/${target}"
        local artifact_dir="${artifact_root}/${target}"
        local log_file="${state_root}/${target}.log"
        if [[ ! -d "$seed_dir" ]]; then
            printf 'ERROR: authored fuzz seeds are missing for %s: %s\n' "$target" "$seed_dir" >&2
            printf '%s\t%s\n' "$target" 2 >> "$status_file"
            continue
        fi
        mkdir -p "$corpus_dir" "$artifact_dir"
        cp -a "$seed_dir"/. "$corpus_dir"/
        printf '=== fuzz: %s (%s runs) ===\n' "$target" "$FUZZ_PASSES"
        if (
            cd "${ROOT_DIR}/qa/fuzz" &&
            CARGO_TARGET_DIR="$ROOT_DIR/target/qa" rustup run "$KASSIGNER_BRANCH_RUST" cargo fuzz run "$target" -- \
                "-runs=${FUZZ_PASSES}" \
                "-artifact_prefix=${artifact_dir}/" \
                "$corpus_dir"
        ) 2>&1 | tee "$log_file"; then
            target_status=0
        else
            target_status=${PIPESTATUS[0]}
        fi
        printf '%s\t%s\n' "$target" "$target_status" >> "$status_file"
        if ((target_status != 0)); then
            printf 'FAIL: fuzz target %s (exit %s)\n' "$target" "$target_status" >&2
        fi
    done

    completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    run_in_directory "$ROOT_DIR" python3 qa/checks/security/fuzz_results.py \
        --statuses "$status_file" \
        --tool "$actual" \
        --started "$started" \
        --completed "$completed" \
        --runs "$FUZZ_PASSES"
}


run_firmware_hardware_tests() {
    require_command python3 || return
    [[ -n "$HARDWARE_BOARD" ]] || {
        printf 'ERROR: hardware tests require --hardware waveshare, waveshare-af, or --hardware m5stack\n' >&2
        return 2
    }

    local -a command=(
        python3 qa/checks/firmware/run_hardware_tests.py
        --board "$HARDWARE_BOARD"
        --timeout "$HARDWARE_TIMEOUT"
    )
    [[ -z "$HARDWARE_PORT" ]] || command+=(--port "$HARDWARE_PORT")
    run_in_directory "$ROOT_DIR" "${command[@]}"
}
