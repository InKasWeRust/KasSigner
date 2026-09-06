#!/usr/bin/env bash
# Generate, classify, and validate the repository CRAP report.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
# shellcheck source=qa/config/toolchains.env
source "$ROOT_DIR/qa/config/toolchains.env"
OUTPUT_DIR="${CRAP_OUTPUT_DIR:-${ROOT_DIR}/target/qa/crap}"
RATCHET_PATH="${CRAP_RATCHET_PATH:-${ROOT_DIR}/qa/contracts/quality/crap_ratchets.json}"
INPUT_REPORT=""
STRICT=false
RUSTC_VERSION=""
LLVM_COV_VERSION=""
CARGO_CRAP_VERSION=""
RUN_STARTED_AT=""
RUN_FINISHED_AT=""
COVERAGE_TOOLCHAIN="$KASSIGNER_STABLE_RUST"
BRANCH_COVERAGE=false
COVERAGE_DEV_OPT_LEVEL="${CRAP_DEV_OPT_LEVEL:-0}"
COVERAGE_TEST_OPT_LEVEL="${CRAP_TEST_OPT_LEVEL:-0}"
usage() {
    cat <<'USAGE'
Usage: scripts/linux/quality/crap.sh [options]
Generate coverage when the local analysis tools are available, calculate CRAP
scores, classify the report, refresh the current snapshot, persist the coverage
bundle, and validate policy.
Options:
  --input-report PATH  Classify an existing cargo-crap text or JSON report.
  --strict             Fail when the fresh report exceeds score limits.
  -h, --help           Show this help.
Environment overrides used by tests and CI:
  CRAP_OUTPUT_DIR             Generated artifact directory (default target/qa/crap).
  CRAP_RATCHET_PATH           Committed compact coverage ratchet (default qa/contracts/quality/crap_ratchets.json).
  CRAP_COVERAGE_TOOLCHAIN     Pinned host-coverage toolchain (default repository stable pin).
  CRAP_ENABLE_BRANCH          Set to 1 to request nightly branch coverage.
  CRAP_BRANCH_TOOLCHAIN       Pinned nightly toolchain used with CRAP_ENABLE_BRANCH.
USAGE
}
while (($#)); do
    case "$1" in
        --input-report)
            (($# >= 2)) || { printf 'ERROR: --input-report requires a path\n' >&2; exit 2; }
            INPUT_REPORT="$2"
            shift 2
            ;;
        --strict)
            STRICT=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'ERROR: unknown CRAP option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'ERROR: required command not found: %s\n' "$1" >&2
        exit 127
    }
}

generation_prerequisites() {
    local -a missing=()
    local toolchain="${CRAP_COVERAGE_TOOLCHAIN:-$KASSIGNER_STABLE_RUST}"
    local branch_requested="${CRAP_ENABLE_BRANCH:-0}"
    if [[ "$branch_requested" =~ ^(1|true|yes)$ ]]; then
        toolchain="${CRAP_BRANCH_TOOLCHAIN:-}"
        if [[ -z "$toolchain" ]]; then
            missing+=("CRAP_BRANCH_TOOLCHAIN (a pinned nightly toolchain)")
        else
            BRANCH_COVERAGE=true
        fi
    fi
    COVERAGE_TOOLCHAIN="$toolchain"
    command -v rustup >/dev/null 2>&1 || missing+=("rustup")
    command -v node >/dev/null 2>&1 || missing+=("node")
    if ((${#missing[@]} == 0)); then
        RUSTC_VERSION="$(rustup run "$toolchain" rustc --version 2>/dev/null)" \
            || missing+=("Rust toolchain $toolchain")
    fi
    if ((${#missing[@]} == 0)); then
        LLVM_COV_VERSION="$(rustup run "$toolchain" cargo llvm-cov --version 2>/dev/null)" \
            || missing+=("cargo llvm-cov for $toolchain")
        CARGO_CRAP_VERSION="$(rustup run "$toolchain" cargo crap --version 2>/dev/null)" \
            || missing+=("cargo crap for $toolchain")
        rustup component list --toolchain "$toolchain" --installed 2>/dev/null \
            | grep -Eq '^llvm-tools' \
            || missing+=("llvm-tools-preview for $toolchain")
    fi
    if $BRANCH_COVERAGE && [[ "$toolchain" != nightly* ]]; then
        missing+=("a pinned nightly toolchain for branch coverage")
    fi
    if ((${#missing[@]} == 0)); then
        printf '\nCRAP analysis tools detected:\n'
        printf '  Toolchain:      %s\n' "$COVERAGE_TOOLCHAIN"
        printf '  Rust:           %s\n' "$RUSTC_VERSION"
        printf '  cargo llvm-cov: %s\n' "$LLVM_COV_VERSION"
        printf '  cargo crap:     %s\n' "$CARGO_CRAP_VERSION"
        if $BRANCH_COVERAGE; then
            printf '  Branch data:    requested\n\n'
        else
            printf '  Branch data:    not requested\n\n'
        fi
        return 0
    fi
    if $BRANCH_COVERAGE; then
        printf '\nERROR: requested branch coverage could not run.\n' >&2
        printf 'The pinned branch-coverage prerequisites are incomplete:\n' >&2
        printf '  - %s\n' "${missing[@]}" >&2
        printf 'Run `scripts/linux/quality/branch-coverage-setup.sh`, then retry the strict QA pipeline.\n' >&2
        printf 'No branch manifest was generated at %s/run.json.\n\n' "$OUTPUT_DIR" >&2
        return 2
    fi
    printf '\nCRAP report generation skipped.\n'
    printf 'The optional local coverage tools are not fully available:\n'
    printf '  - %s\n' "${missing[@]}"
    printf 'The structural complexity and firmware-testability checks will still run.\n'
    printf 'The remaining QA catalog will continue normally.\n\n'
    return 1
}

source_label() {
    local timestamp revision
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if revision="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null)"; then
        printf 'git %s generated %s\n' "$revision" "$timestamp"
    else
        printf 'working tree generated %s\n' "$timestamp"
    fi
}

prepare_output() {
    local previous=""
    local previous_run=""
    local previous_health=""
    if [[ -f "$OUTPUT_DIR/current.json" ]]; then previous="$(mktemp)"; cp -f "$OUTPUT_DIR/current.json" "$previous"; fi
    if [[ -f "$OUTPUT_DIR/run.json" ]]; then previous_run="$(mktemp)"; cp -f "$OUTPUT_DIR/run.json" "$previous_run"; fi
    if [[ -f "$OUTPUT_DIR/health_summary.json" ]]; then previous_health="$(mktemp)"; cp -f "$OUTPUT_DIR/health_summary.json" "$previous_health"; fi
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    [[ -z "$previous" ]] || mv -f "$previous" "$OUTPUT_DIR/previous.json"
    [[ -z "$previous_run" ]] || mv -f "$previous_run" "$OUTPUT_DIR/previous_run.json"
    [[ -z "$previous_health" ]] || mv -f "$previous_health" "$OUTPUT_DIR/previous_health_summary.json"
}

verify_nonempty() {
    local path="$1" label="$2"
    [[ -s "$path" ]] || {
        printf 'ERROR: %s was not generated or is empty: %s\n' "$label" "$path" >&2
        return 1
    }
}

file_size() {
    wc -c < "$1" | tr -d '[:space:]'
}

write_run_manifest() {
    local -a branch_args=()
    if $BRANCH_COVERAGE; then
        branch_args+=(--branch-requested)
    fi
    python3 "$ROOT_DIR/qa/checks/quality/crap/coverage_manifest.py" \
        --output "$OUTPUT_DIR/run.json" \
        --started-at "$RUN_STARTED_AT" \
        --finished-at "$RUN_FINISHED_AT" \
        --toolchain "$COVERAGE_TOOLCHAIN" \
        --rustc-version "$RUSTC_VERSION" \
        --llvm-cov-version "$LLVM_COV_VERSION" \
        --cargo-crap-version "$CARGO_CRAP_VERSION" \
        --dev-opt-level "$COVERAGE_DEV_OPT_LEVEL" \
        --test-opt-level "$COVERAGE_TEST_OPT_LEVEL" \
        --root "$ROOT_DIR" \
        --lcov "$OUTPUT_DIR/lcov.info" \
        --cargo-crap-json "$OUTPUT_DIR/cargo_crap.json" \
        "${branch_args[@]}"
}

generate_report() {
    local lcov_path="$OUTPUT_DIR/lcov.info"
    local kassee_lcov_path="$OUTPUT_DIR/kassee_web_lcov.info"
    local json_path="$OUTPUT_DIR/cargo_crap.json"
    local host_json="$OUTPUT_DIR/cargo_crap_host.json"
    local firmware_json="$OUTPUT_DIR/cargo_crap_firmware.json"
    local kassee_json="$OUTPUT_DIR/cargo_crap_kassee_web.json"
    local human_path="$OUTPUT_DIR/crap_report_full.txt"
    local host_human="$OUTPUT_DIR/crap_report_host.txt"
    local firmware_human="$OUTPUT_DIR/crap_report_firmware.txt"
    local kassee_human="$OUTPUT_DIR/crap_report_kassee_web.txt"
    local coverage_log="$OUTPUT_DIR/coverage_run.txt" crap_log="$OUTPUT_DIR/crap_run.txt"
    printf 'KasSigner CRAP analysis log\nToolchain: %s\nScopes: root workspace (LCOV-backed), KasSee Web (LCOV-backed), signer firmware (complexity-only)\n' "$COVERAGE_TOOLCHAIN" > "$crap_log"
    RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'CRAP analysis is the first QA workload.\n'
    printf 'Generated artifacts will be available before the remaining catalog starts.\n'
    printf 'Working artifact directory: %s\n\n' "$OUTPUT_DIR"
    local root_coverage_ignore='unit_tests|online-watcher[\\/]src[\\/]wasm_api[\\/]mod\.rs$'; local -a coverage_args=(--workspace --lcov --ignore-filename-regex "$root_coverage_ignore" --output-path "$lcov_path")
    local -a kassee_coverage_args=(
        --manifest-path "$ROOT_DIR/apps/kassee-web/Cargo.toml"
        --workspace
        --lib
        --lcov --ignore-filename-regex unit_tests
        --output-path "$kassee_lcov_path"
    )
    if $BRANCH_COVERAGE; then
        coverage_args+=(--branch)
        kassee_coverage_args+=(--branch)
    fi
    printf '[CRAP 1/4] Running coverage for each host-testable Rust workspace...\n'
    printf 'Coverage profile: dev/test opt-level=0 for source-faithful LLVM function/branch mapping.\n'
    printf '  - Root Cargo workspace\n'
    (
        cd "$ROOT_DIR"
        CARGO_PROFILE_DEV_OPT_LEVEL="$COVERAGE_DEV_OPT_LEVEL" \
        CARGO_PROFILE_TEST_OPT_LEVEL="$COVERAGE_TEST_OPT_LEVEL" \
        rustup run "$COVERAGE_TOOLCHAIN" cargo llvm-cov "${coverage_args[@]}"
    ) 2>&1 | tee "$coverage_log"
    verify_nonempty "$lcov_path" "root workspace LCOV coverage data"
    printf '  - KasSee Web Rust shell\n'
    (
        cd "$ROOT_DIR"
        CARGO_PROFILE_DEV_OPT_LEVEL="$COVERAGE_DEV_OPT_LEVEL" \
        CARGO_PROFILE_TEST_OPT_LEVEL="$COVERAGE_TEST_OPT_LEVEL" \
        rustup run "$COVERAGE_TOOLCHAIN" cargo llvm-cov "${kassee_coverage_args[@]}"
    ) 2>&1 | tee -a "$coverage_log"
    verify_nonempty "$kassee_lcov_path" "KasSee Web LCOV coverage data"
    printf '[CRAP 1/4] PASS: scope-aligned coverage completed (root %s bytes; KasSee Web %s bytes).\n\n' \
        "$(file_size "$lcov_path")" "$(file_size "$kassee_lcov_path")"
    local -a common_crap=(
        --threshold 30
        --missing pessimistic
        --sort crap
    )
    printf '[CRAP 2/4] Calculating machine-readable CRAP scores by matching scope...\n'
    printf '  - Root Cargo workspace: coverage-backed CRAP\n'
    (
        cd "$ROOT_DIR"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --workspace \
            --lcov "$lcov_path" \
            --exclude '**/unit_tests/**' --exclude 'src/wasm/**' \
            "${common_crap[@]}" \
            --format json \
            --output "$host_json"
    ) 2>&1 | tee -a "$crap_log"
    verify_nonempty "$host_json" "root workspace cargo-crap JSON report"
    printf '  - KasSee Web Rust shell: coverage-backed CRAP\n'
    (
        cd "$ROOT_DIR"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --path apps/kassee-web \
            --lcov "$kassee_lcov_path" --exclude '**/unit_tests/**' \
            "${common_crap[@]}" \
            --format json \
            --output "$kassee_json"
    ) 2>&1 | tee -a "$crap_log"
    verify_nonempty "$kassee_json" "KasSee Web cargo-crap JSON report"
    printf '  - Signer firmware: complexity-only CRAP (host LCOV is not valid for Xtensa firmware)\n'
    (
        cd "$ROOT_DIR"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --path apps/signer-firmware \
            --no-default-excludes "${common_crap[@]}" \
            --format json \
            --output "$firmware_json"
    ) 2>&1 | tee -a "$crap_log"
    verify_nonempty "$firmware_json" "signer firmware cargo-crap JSON report"
    python3 "$ROOT_DIR/qa/checks/quality/crap/merge_reports.py" \
        --host-json "$host_json" \
        --firmware-json "$firmware_json" \
        --kassee-web-json "$kassee_json" \
        --output-json "$json_path"
    verify_nonempty "$json_path" "merged cargo-crap JSON report"
    printf '[CRAP 2/4] PASS: machine-readable CRAP scoring completed (%s bytes).\n\n' \
        "$(file_size "$json_path")"
    printf '[CRAP 3/4] Rendering the human-readable CRAP report by matching scope...\n'
    (
        cd "$ROOT_DIR"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --workspace \
            --lcov "$lcov_path" \
            --exclude '**/unit_tests/**' --exclude 'src/wasm/**' \
            "${common_crap[@]}" \
            --format human \
            --output "$host_human"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --path apps/kassee-web \
            --lcov "$kassee_lcov_path" --exclude '**/unit_tests/**' \
            "${common_crap[@]}" \
            --format human \
            --output "$kassee_human"
        NO_COLOR=1 rustup run "$COVERAGE_TOOLCHAIN" cargo crap \
            --path apps/signer-firmware \
            --no-default-excludes "${common_crap[@]}" \
            --format human \
            --output "$firmware_human"
    ) 2>&1 | tee -a "$crap_log"
    verify_nonempty "$host_human" "root workspace human cargo-crap report"
    verify_nonempty "$kassee_human" "KasSee Web human cargo-crap report"
    verify_nonempty "$firmware_human" "signer firmware human cargo-crap report"
    python3 "$ROOT_DIR/qa/checks/quality/crap/merge_reports.py" \
        --host-json "$host_json" \
        --firmware-json "$firmware_json" \
        --kassee-web-json "$kassee_json" \
        --output-json "$json_path" \
        --host-human "$host_human" \
        --firmware-human "$firmware_human" \
        --kassee-web-human "$kassee_human" \
        --output-human "$human_path"
    verify_nonempty "$human_path" "human-readable cargo-crap report"
    printf '[CRAP 3/4] PASS: human-readable report completed (%s bytes).\n\n' \
        "$(file_size "$human_path")"
    RUN_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    write_run_manifest
    INPUT_REPORT="$json_path"
}
generate_browser_recovery_coverage() {
    printf '[Browser recovery] Running KasSee recovery tests with V8 coverage...\n'
    python3 "$ROOT_DIR/qa/checks/web/run_web_recovery_coverage.py" \
        --output-dir "$OUTPUT_DIR/browser_recovery"
    verify_nonempty "$OUTPUT_DIR/browser_recovery/summary.json" \
        "browser recovery coverage summary"
    verify_nonempty "$OUTPUT_DIR/browser_recovery/v8-coverage.json" \
        "browser recovery V8 coverage"
    printf '[Browser recovery] PASS: coverage persisted.\n\n'
}

generate_web_runtime_coverage() {
    printf '[Web runtime] Mapping all reachable KasSee JS modules with merged V8 integration coverage...\n'
    python3 "$ROOT_DIR/qa/checks/web/run_web_runtime_coverage.py" \
        --output-dir "$OUTPUT_DIR/web_runtime"
    verify_nonempty "$OUTPUT_DIR/web_runtime/summary.json" \
        "web runtime coverage summary"
    verify_nonempty "$OUTPUT_DIR/web_runtime/v8-coverage.json" \
        "web runtime V8 coverage"
    printf '[Web runtime] PASS: 100%% reachable-module trace mapping persisted.\n\n'
}

classify_report() {
    local display_args=()
    if [[ -f "$OUTPUT_DIR/crap_report_full.txt" ]]; then
        display_args=(--display-report "$OUTPUT_DIR/crap_report_full.txt")
    fi
    printf '[CRAP 4/4] Classifying production, tests, external, and tools...\n'
    python3 "$ROOT_DIR/qa/checks/quality/crap/classify_report.py" \
        --input "$INPUT_REPORT" \
        --output-dir "$OUTPUT_DIR" \
        --source-label "$(source_label)" \
        "${display_args[@]}"
}

validate_report() {
    local -a args=(--report "$OUTPUT_DIR/current.json" --ratchet-contract "$RATCHET_PATH")
    $STRICT && args+=(--strict-report)
    [[ -f "$OUTPUT_DIR/lcov.info" && -f "$OUTPUT_DIR/run.json" ]] \
        && args+=(
            --lcov "$OUTPUT_DIR/lcov.info"
            --run-manifest "$OUTPUT_DIR/run.json"
            --browser-recovery-coverage "$OUTPUT_DIR/browser_recovery/summary.json"
            --web-runtime-coverage "$OUTPUT_DIR/web_runtime/summary.json"
            --health-output "$OUTPUT_DIR/health_summary.json"
        )
    [[ -f "$OUTPUT_DIR/previous.json" ]] \
        && args+=(--previous-report "$OUTPUT_DIR/previous.json")
    [[ -f "$OUTPUT_DIR/run.json" && -f "$OUTPUT_DIR/previous_run.json" ]] \
        && args+=(
            --previous-run-manifest "$OUTPUT_DIR/previous_run.json"
        )
    [[ -f "$OUTPUT_DIR/lcov.info" && -f "$OUTPUT_DIR/run.json" && -f "$OUTPUT_DIR/previous_health_summary.json" ]] \
        && args+=(--previous-health-summary "$OUTPUT_DIR/previous_health_summary.json")
    python3 "$ROOT_DIR/qa/checks/quality/crap/check.py" "${args[@]}"
}

validate_without_report() {
    python3 "$ROOT_DIR/qa/checks/quality/crap/check.py" --ignore-generated-report --ratchet-contract "$RATCHET_PATH"
}

print_artifacts() {
    local summary_line=""
    if [[ -f "$OUTPUT_DIR/crap_summary.json" ]]; then
        summary_line="$(python3 - "$OUTPUT_DIR/crap_summary.json" <<'PY'
import json
from pathlib import Path
import sys
summary = json.loads(Path(sys.argv[1]).read_text())
production = summary["scopes"]["production"]
status = production["status"]
print(
    f"{production['functions']} production functions; "
    f"{status['fail']} failures; {status['warning']} warnings"
)
PY
)"
    fi
    cat <<EOF_ARTIFACTS
[CRAP 4/4] PASS: reports classified and checked.
Fresh CRAP artifacts are ready while the remaining QA tests run:
  Full report:       $OUTPUT_DIR/crap_report_full.txt
  Production report: $OUTPUT_DIR/crap_report_prod.txt
  Tests report:      $OUTPUT_DIR/crap_report_tests.txt
  External report:   $OUTPUT_DIR/crap_report_external.txt
  Tools report:      $OUTPUT_DIR/crap_report_tools.txt
  Summary:           $OUTPUT_DIR/crap_summary.json
  Health audit:      $OUTPUT_DIR/health_summary.json
  LCOV data:         $OUTPUT_DIR/lcov.info
  Coverage log:      $OUTPUT_DIR/coverage_run.txt
  Run manifest:      $OUTPUT_DIR/run.json
  Browser recovery:  $OUTPUT_DIR/browser_recovery/summary.json
  Web runtime map:    $OUTPUT_DIR/web_runtime/summary.json
Committed quality ratchet:
  Contract:          $RATCHET_PATH
EOF_ARTIFACTS
    [[ -z "$summary_line" ]] || printf '  Production result: %s\n' "$summary_line"
    printf '\nThe CRAP analysis is complete. The remaining QA catalog starts now.\n\n'
}

main() {
    require_command python3
    if [[ -n "$INPUT_REPORT" ]]; then
        [[ -f "$INPUT_REPORT" ]] || {
            printf 'ERROR: CRAP input report does not exist: %s\n' "$INPUT_REPORT" >&2
            exit 2
        }
        prepare_output
    elif generation_prerequisites; then
        prepare_output
        generate_report
    else
        local prerequisite_status=$?
        if ((prerequisite_status == 2)); then
            return "$prerequisite_status"
        fi
        validate_without_report
        return 0
    fi
    if [[ -f "$OUTPUT_DIR/lcov.info" && -f "$OUTPUT_DIR/run.json" ]]; then
        generate_browser_recovery_coverage
        generate_web_runtime_coverage
    fi
    classify_report
    validate_report
    print_artifacts
}
main
