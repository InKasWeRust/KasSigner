#!/usr/bin/env bash
# Run the complete KasSigner test catalog in a stable, resumable order.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_PATH="${ROOT_DIR}/qa/linux/run-all.sh"
SCRIPT_DIR="${ROOT_DIR}/qa/linux"

# shellcheck source=qa/linux/lib/terminal_pause.sh
source "${SCRIPT_DIR}/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "KasSigner test runner"

FUZZ_PASSES=100000
PROFILE="full"
RESUME_FROM=""
ONLY_STEP=""
CATEGORY_FILTER=""
WORKSPACE_FILTER=""
TEST_FILTER=""
FUZZ_TARGET=""
EXACT_TEST=false
DRY_RUN=false
LIST_ONLY=false
SKIP_FUZZ=false
SKIP_QEMU=false
PAUSE_ON_EXIT=false
REPAIR_LOCKFILES=true
HARDWARE_BOARD=""
HARDWARE_PORT=""
HARDWARE_TIMEOUT=240
CORE_CI_TESTS_COMPLETE=false

# shellcheck source=qa/linux/runner/environment.sh
source "${SCRIPT_DIR}/runner/environment.sh"
# shellcheck source=qa/linux/runner/commands.sh
source "${SCRIPT_DIR}/runner/commands.sh"
# shellcheck source=qa/linux/runner/catalog.sh
source "${SCRIPT_DIR}/runner/catalog.sh"

# cargo-fuzz conventionally creates these beside qa/fuzz/Cargo.toml. They are
# transient scratch only; retained corpora/artifacts live under target/qa/fuzz.
rm -rf "${ROOT_DIR}/qa/fuzz/artifacts" "${ROOT_DIR}/qa/fuzz/corpus"

usage() {
    cat <<'EOF'
Usage: qa/linux/run-all.sh [options]

Runs the canonical KasSigner test catalog. Profile `test` is the fast contributor
suite. Profile `full` runs strict coverage/CRAP first, then the pinned stable Core CI
gate (format, Clippy, strict `make test`, and git diff validation), followed by every
additional registered non-hardware QA step, with fresh mutation and fuzz last.
Each catalog entry has a stable ID that can be resumed independently.

Selection:
  --profile NAME                 Run the strict QA catalog (default) or the normal contributor test profile.
  --list                         List stable step IDs.
  --resume-from ID              Resume at ID, category, or ID prefix.
  --from ID                     Alias for --resume-from.
  --only ID                     Run one exact catalog step.
  --section ID                  Alias for --only.
  --category NAME               Run one category: preflight, unit, integration, static, security, coverage, interactive, emulation, bench, mutation, fuzz, or hardware.
  --workspace NAME              Limit to one workspace or repository group.
  --test [WORKSPACE::]NAME       Run only matching Cargo test names.
  --exact                       Use the Cargo test harness --exact flag.

Fuzz:
  --fuzz-passes COUNT           libFuzzer run count per target (default: 100000).
  --fuzz-target NAME            Run one registered fuzz target.
  --skip-fuzz                   Skip fuzzing while retaining all prior sections.
  --skip-qemu                   Skip the ESP32-S3 QEMU execution stage.

Hardware (opt-in):
  --hardware BOARD              Flash and run on-device tests (waveshare, waveshare-af, or m5stack).
  --hardware-port PORT          Use a specific serial port for the ESP device.
  --hardware-timeout SECONDS    Device-test timeout (default: 240).

Other:
  --dry-run                     Print commands without executing them.
  --strict-lockfiles            Fail instead of transactionally refreshing stale lockfiles.
  --pause                       Force a wait for Enter before closing the terminal.

Direct interactive launches pause automatically and always print a final PASS/FAIL
summary. Set KASSIGNER_QA_NO_PAUSE=1 to suppress the automatic pause. GNU Make,
nested QA launchers, CI, and non-interactive invocations never auto-pause.
  -h, --help                    Show this help.

Examples:
  qa/linux/run-all.sh --profile test
  qa/linux/run-all.sh --resume-from integration.kassee-web-generated
  qa/linux/run-all.sh --category unit --workspace offline-signer
  qa/linux/run-all.sh --test offline-signer::bip32_vector
  qa/linux/run-all.sh --only integration.repository-architecture
  qa/linux/run-all.sh --fuzz-passes 1000000
  qa/linux/run-all.sh --hardware waveshare --hardware-port /dev/ttyACM0
EOF
}

fail_usage() {
    printf 'ERROR: %s\n\n' "$1" >&2
    usage >&2
    exit 2
}

canonical_step_id() {
    case "$1" in
        unit.architecture-imports) printf 'unit.repository-python-qa\n' ;;
        fuzz.shared-signer-qr-payload) printf 'fuzz.repository-security-targets\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

normalize_workspace() {
    case "$1" in
        kasee-web|kassee-web) printf 'kassee-web\n' ;;
        signer-firmware|kassee-ios|kassee-android|online-watcher|offline-signer|shared-signer|signer-firmware-core|external-rqrr|tools|repository)
            printf '%s\n' "$1" ;;
        *) fail_usage "unknown workspace: $1" ;;
    esac
}

normalize_category() {
    case "$1" in
        preflight|unit|integration|static|security|coverage|interactive|emulation|hardware|mutation|fuzz) printf '%s\n' "$1" ;;
        bench|benches) printf 'bench\n' ;;
        *) fail_usage "unknown category: $1" ;;
    esac
}

parse_arguments() {
    while (($#)); do
        case "$1" in
            --profile)
                (($# >= 2)) || fail_usage "--profile requires full or test"
                case "$2" in
                    full|test) PROFILE="$2" ;;
                    *) fail_usage "invalid profile: $2 (expected full or test)" ;;
                esac
                shift 2 ;;
            --list) LIST_ONLY=true; shift ;;
            --resume-from|--from)
                (($# >= 2)) || fail_usage "$1 requires a section ID"
                RESUME_FROM="$(canonical_step_id "$2")"; shift 2 ;;
            --only|--section)
                (($# >= 2)) || fail_usage "$1 requires a step ID"
                ONLY_STEP="$(canonical_step_id "$2")"; shift 2 ;;
            --category)
                (($# >= 2)) || fail_usage "--category requires a value"
                CATEGORY_FILTER="$(normalize_category "$2")"; shift 2 ;;
            --workspace)
                (($# >= 2)) || fail_usage "--workspace requires a value"
                WORKSPACE_FILTER="$(normalize_workspace "$2")"; shift 2 ;;
            --test)
                (($# >= 2)) || fail_usage "--test requires a test name"
                TEST_FILTER="$2"; shift 2
                parse_qualified_test_filter ;;
            --exact) EXACT_TEST=true; shift ;;
            --fuzz-passes)
                (($# >= 2)) || fail_usage "--fuzz-passes requires a positive integer"
                [[ "$2" =~ ^[1-9][0-9]*$ ]] || fail_usage "invalid fuzz pass count: $2"
                FUZZ_PASSES="$2"; shift 2 ;;
            --fuzz-target)
                (($# >= 2)) || fail_usage "--fuzz-target requires a target name"
                FUZZ_TARGET="$2"; shift 2 ;;
            --skip-fuzz) SKIP_FUZZ=true; shift ;;
            --skip-qemu) SKIP_QEMU=true; shift ;;
            --hardware)
                (($# >= 2)) || fail_usage "--hardware requires waveshare, waveshare-af, or m5stack"
                case "$2" in
                    waveshare|waveshare-af|m5stack) HARDWARE_BOARD="$2" ;;
                    *) fail_usage "invalid hardware board: $2 (expected waveshare, waveshare-af, or m5stack)" ;;
                esac
                shift 2 ;;
            --hardware-port)
                (($# >= 2)) || fail_usage "--hardware-port requires a serial port"
                [[ -n "$2" ]] || fail_usage "--hardware-port requires a non-empty serial port"
                HARDWARE_PORT="$2"; shift 2 ;;
            --hardware-timeout)
                (($# >= 2)) || fail_usage "--hardware-timeout requires a positive integer"
                [[ "$2" =~ ^[1-9][0-9]*$ ]] || fail_usage "invalid hardware timeout: $2"
                HARDWARE_TIMEOUT="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --strict-lockfiles) REPAIR_LOCKFILES=false; shift ;;
            --pause) PAUSE_ON_EXIT=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) fail_usage "unknown option: $1" ;;
        esac
    done
}

parse_qualified_test_filter() {
    [[ "$TEST_FILTER" == *::* ]] || return 0
    local test_workspace="${TEST_FILTER%%::*}"
    local test_name="${TEST_FILTER#*::}"
    [[ -n "$test_name" ]] || fail_usage "--test requires a name after WORKSPACE::"
    local normalized
    normalized="$(normalize_workspace "$test_workspace")"
    if [[ -n "$WORKSPACE_FILTER" && "$WORKSPACE_FILTER" != "$normalized" ]]; then
        fail_usage "--test workspace conflicts with --workspace"
    fi
    WORKSPACE_FILTER="$normalized"
    TEST_FILTER="$test_name"
}

print_catalog() {
    printf '%-46s %-10s %-14s %s\n' 'STEP ID' 'SCOPE' 'WORKSPACE' 'DESCRIPTION'
    printf '%-46s %-10s %-14s %s\n' '-------' '-----' '---------' '-----------'
    local record category workspace id description scope
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        scope="${STEP_SCOPES[$id]}"
        printf '%-46s %-10s %-14s %s\n' "$id" "$scope" "$workspace" "$description"
    done
}

step_exists() {
    local requested="$1" record category workspace id description
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        [[ "$id" == "$requested" ]] && return 0
    done
    return 1
}

resolve_resume_step() {
    local requested="$1" record category workspace id description
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        if [[ "$id" == "$requested" ]]; then
            printf '%s\n' "$id"
            return 0
        fi
    done
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        if [[ "$category" == "$requested" || "$id" == "$requested"* ]]; then
            printf '%s\n' "$id"
            return 0
        fi
    done
    return 1
}

step_selected() {
    local category="$1" workspace="$2" id="$3" scope="${STEP_SCOPES[$3]}"
    if [[ "$PROFILE" == "test" && "$scope" != "test" ]]; then
        return 1
    fi
    if [[ "$PROFILE" == "full" && "$scope" == "test" && "$CORE_CI_TESTS_COMPLETE" == true ]]; then
        return 1
    fi
    if [[ "$PROFILE" == "full" && "$scope" == "hardware" && "$CATEGORY_FILTER" != "hardware" && -z "$HARDWARE_BOARD" ]]; then
        return 1
    fi
    if [[ "$PROFILE" == "full" && "$scope" != "test" && "$scope" != "qa" && "$scope" != "hardware" ]]; then
        return 1
    fi
    [[ -z "$ONLY_STEP" || "$id" == "$ONLY_STEP" ]] || return 1
    [[ -z "$CATEGORY_FILTER" || "$category" == "$CATEGORY_FILTER" ]] || return 1
    [[ -z "$WORKSPACE_FILTER" || "$workspace" == "$WORKSPACE_FILTER" ]] || return 1
    if [[ -n "$TEST_FILTER" ]] && ! step_supports_test_filter "$id"; then
        return 1
    fi
    if [[ "$category" == "hardware" && -z "$HARDWARE_BOARD" ]]; then
        return 1
    fi
    if $SKIP_FUZZ && [[ "$category" == "fuzz" ]]; then
        return 1
    fi
    if $SKIP_QEMU && [[ "$category" == "emulation" ]]; then
        return 1
    fi
    return 0
}

test_profile_contains() {
    [[ "${STEP_SCOPES[$1]:-}" == "test" ]]
}


print_resume_command() {
    local id="$1"
    local -a command=("$SCRIPT_PATH" --profile "$PROFILE" --resume-from "$id" --fuzz-passes "$FUZZ_PASSES")
    [[ -z "$CATEGORY_FILTER" ]] || command+=(--category "$CATEGORY_FILTER")
    [[ -z "$WORKSPACE_FILTER" ]] || command+=(--workspace "$WORKSPACE_FILTER")
    [[ -z "$TEST_FILTER" ]] || command+=(--test "$TEST_FILTER")
    $EXACT_TEST && command+=(--exact)
    [[ -z "$FUZZ_TARGET" ]] || command+=(--fuzz-target "$FUZZ_TARGET")
    $SKIP_FUZZ && command+=(--skip-fuzz)
    $SKIP_QEMU && command+=(--skip-qemu)
    $PAUSE_ON_EXIT && command+=(--pause)
    $REPAIR_LOCKFILES || command+=(--strict-lockfiles)
    if [[ -n "$HARDWARE_BOARD" ]]; then
        command+=(--hardware "$HARDWARE_BOARD" --hardware-timeout "$HARDWARE_TIMEOUT")
        [[ -z "$HARDWARE_PORT" ]] || command+=(--hardware-port "$HARDWARE_PORT")
    fi
    printf 'Resume with:' >&2
    printf ' %q' "${command[@]}" >&2
    printf '\n' >&2
}

category_heading() {
    case "$1" in
        preflight) printf 'PREFLIGHT\n' ;;
        bench) printf 'BENCHMARKS\n' ;;
        coverage) printf 'COVERAGE / CRAP TESTS\n' ;;
        static) printf 'STATIC / ARCHITECTURE TESTS\n' ;;
        security) printf 'SECURITY POLICY TESTS\n' ;;
        interactive) printf 'REAL-NODE / INTERACTIVE E2E TESTS\n' ;;
        mutation) printf 'FRESH MUTATION TESTS\n' ;;
        emulation) printf 'QEMU EMULATION TESTS\n' ;;
        hardware) printf 'HARDWARE TESTS\n' ;;
        *) printf '%s TESTS\n' "${1^^}" ;;
    esac
}

ensure_resume_prerequisites() {
    local resolved_resume="$1" record category workspace id description reached=false needs_crap=false
    [[ -n "$resolved_resume" && "$PROFILE" == "full" ]] || return 0
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        if ! $reached; then
            [[ "$id" == "$resolved_resume" ]] || continue
            reached=true
        fi
        if [[ "$id" == "coverage.critical-branch-targets" ]] && step_selected "$category" "$workspace" "$id"; then
            needs_crap=true
            break
        fi
    done
    $needs_crap || return 0
    local required missing=()
    for required in health_summary.json lcov.info run.json cargo_crap.json crap_summary.json current.json; do
        [[ -s "$ROOT_DIR/target/qa/crap/$required" ]] || missing+=("target/qa/crap/$required")
    done
    if ((${#missing[@]} == 0)) && ! $DRY_RUN; then return 0; fi
    printf '\n[resume prerequisite] Fresh CRAP/coverage artifacts are required by later resumed QA steps.\n'
    ((${#missing[@]} == 0)) || printf '  Missing: %s\n' "${missing[*]}"
    printf '  Regenerating preflight.crap-check only; already-passed test steps remain skipped.\n'
    run_step preflight.crap-check
}


run_catalog() {
    local resolved_resume=""
    if [[ -n "$ONLY_STEP" ]] && ! step_exists "$ONLY_STEP"; then
        fail_usage "unknown exact step ID: $ONLY_STEP"
    fi
    if [[ -n "$RESUME_FROM" ]]; then
        resolved_resume="$(resolve_resume_step "$RESUME_FROM")" || \
            fail_usage "unknown resume section: $RESUME_FROM"
    fi

    ensure_resume_prerequisites "$resolved_resume" || {
        status=$?
        printf 'FAIL: resume prerequisite preflight.crap-check (exit %s)\n' "$status" >&2
        exit "$status"
    }

    local current_category="" current_workspace=""
    local resume_reached=false selected_count=0 passed_count=0 skipped_count=0
    [[ -z "$resolved_resume" ]] && resume_reached=true
    local record category workspace id description heading status
    for record in "${STEPS[@]}"; do
        IFS='|' read -r category workspace id description <<<"$record"
        if ! $resume_reached; then
            [[ "$id" == "$resolved_resume" ]] || continue
            resume_reached=true
        fi
        step_selected "$category" "$workspace" "$id" || continue
        ((selected_count += 1))

        if [[ "$category" != "$current_category" ]]; then
            current_category="$category"
            current_workspace=""
            heading="$(category_heading "$category")"
            printf '\n================================================================================\n'
            printf ' %s\n' "$heading"
            printf '================================================================================\n'
        fi
        if [[ "$workspace" != "$current_workspace" ]]; then
            current_workspace="$workspace"
            printf '\n---- %s ----\n' "$workspace"
        fi
        printf '\n[%s] %s\n' "$id" "$description"

        if run_step "$id"; then
            if [[ "${KASSIGNER_STEP_SKIPPED:-false}" == "true" ]]; then
                ((skipped_count += 1))
                printf 'SKIP: %s\n' "$id"
            else
                ((passed_count += 1))
                printf 'PASS: %s\n' "$id"
            fi
        else
            status=$?
            printf 'FAIL: %s (exit %s)\n' "$id" "$status" >&2
            print_resume_command "$id"
            exit "$status"
        fi
    done

    ((selected_count > 0)) || fail_usage "the selected filters matched no test steps"
    printf '\nPASS: %s passed, %s skipped, %s selected test sections completed\n' "$passed_count" "$skipped_count" "$selected_count"
}


acquire_release_workflow_lock() {
    # The Python tooling regression suite intentionally launches nested
    # qa/linux/run-all.sh processes to exercise launcher/preflight behavior. When
    # the outer run-all already owns this repository's workflow lock, those
    # descendants are part of the same serialized QA workflow and must not
    # block waiting on their own parent. Scope the inheritance marker to this
    # exact repository; the reproducible-build runner deliberately does not
    # honor this marker, so a nested release build still waits for QA to end.
    if [[ "${KASSIGNER_QA_RUN_ALL_LOCK_ROOT:-}" == "$ROOT_DIR" ]]; then
        return 0
    fi

    command -v flock >/dev/null 2>&1 || {
        echo "ERROR: flock is required to serialize QA and reproducible-release workflows." >&2
        exit 2
    }
    mkdir -p "$ROOT_DIR/target/qa/state"
    exec 9>"$ROOT_DIR/target/qa/state/release-workflow.lock"
    if ! flock -n 9; then
        echo "Another KasSigner QA/reproducible-release workflow is active; waiting for it to finish."
        flock 9
    fi
    export KASSIGNER_QA_RUN_ALL_LOCK_ROOT="$ROOT_DIR"
}


main() {
    parse_arguments "$@"
    if $LIST_ONLY; then
        print_catalog
        return 0
    fi
    if [[ -n "$HARDWARE_PORT" && -z "$HARDWARE_BOARD" ]]; then
        fail_usage "--hardware-port requires --hardware BOARD"
    fi
    if [[ "$CATEGORY_FILTER" == "hardware" && -z "$HARDWARE_BOARD" ]]; then
        fail_usage "--category hardware requires --hardware BOARD"
    fi
    if [[ "$ONLY_STEP" == hardware.* && -z "$HARDWARE_BOARD" ]]; then
        fail_usage "hardware steps require --hardware BOARD"
    fi
    acquire_release_workflow_lock
    initialize_test_environment
    export KASSIGNER_QA_CATALOG_ACTIVE=1
    run_catalog
}

main "$@"
