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

# Stable test catalog and step dispatch for run-all.sh.

declare -a STEPS=()
declare -A STEP_SCOPES=()
CATALOG_PATH="${ROOT_DIR}/qa/config/run_all_steps.tsv"
while IFS=$'\t' read -r scope category workspace id description; do
    [[ -n "$scope" && "$scope" != \#* ]] || continue
    STEPS+=("${category}|${workspace}|${id}|${description}")
    STEP_SCOPES["$id"]="$scope"
done < "$CATALOG_PATH"


run_step() {
    local id="$1"
    KASSIGNER_STEP_SKIPPED=false
    case "$id" in
        preflight.kassee-build)
            require_command rustup || return
            run_in_directory "$ROOT_DIR" bash scripts/linux/build/kassee-web-build.sh
            ;;
        preflight.firmware-source-contracts)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/firmware/check_firmware_source_contracts.py
            ;;
        preflight.repository-lockfiles)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/workspace/check_lockfile.py
            ;;
        preflight.crap-check)
            require_command bash || return
            run_in_directory "$ROOT_DIR" bash qa/linux/run-pinned-branch-coverage.sh
            ;;
        preflight.core-ci)
            run_core_ci_gate || return $?
            CORE_CI_TESTS_COMPLETE=true
            ;;
        preflight.security-assurance)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/security_invariants.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/watcher_only_apps.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/irreversible_action_policy.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/test_quality.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/repository_test_quality.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/security_control_evidence.py
            ;;
        preflight.cargo-resolution) run_all_cargo_resolutions ;;
        unit.shared-signer)
            run_cargo_test --manifest-path Cargo.toml -p shared-signer --all-features --locked ;;
        unit.signer-firmware-core)
            run_cargo_test --manifest-path Cargo.toml -p signer-firmware-core --all-features --locked ;;
        unit.offline-signer)
            run_cargo_test --manifest-path Cargo.toml -p offline-signer --all-features --locked ;;
        unit.online-watcher)
            run_cargo_test --manifest-path Cargo.toml -p online-watcher --all-features --locked ;;
        unit.kassee-web)
            run_cargo_test --manifest-path apps/kassee-web/Cargo.toml --lib --locked ;;
        unit.kassee-ios-core)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/ios/check_ios_architecture.py
            ;;
        unit.kassee-android-core)
            if command -v kotlinc >/dev/null 2>&1 && command -v java >/dev/null 2>&1 || $DRY_RUN; then
                run_in_directory "$ROOT_DIR" python3 qa/checks/android/run_core_tests.py
            else
                printf '  ~ SKIP: Kotlin/Java toolchain is unavailable; static Android architecture checks still run.\n'
            fi
            ;;
        unit.signer-firmware) run_firmware_unit_compilation ;;
        unit.external-rqrr)
            run_cargo_test --manifest-path external/rqrr-nostd/Cargo.toml --all-features --locked ;;
        unit.tools)
            # A resumed run can skip preflight.cargo-resolution, so revalidate
            # the independent tools lock before invoking cargo test --locked.
            run_cargo_metadata_check "$ROOT_DIR/tools" "Cargo.toml" || return $?
            run_cargo_test --manifest-path tools/Cargo.toml --lib --bins --locked ;;
        static.qa-orchestration-catalog)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/workspace/check_qa_orchestration.py
            ;;
        unit.repository-python-qa)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 -m unittest discover \
                -s qa/tests/tooling -p 'test_*.py' -v || return $?
            run_in_directory "$ROOT_DIR" python3 -m unittest discover \
                -s qa/tests/regression -p 'test_*.py' -v || return $?
            ;;
        integration.shared-signer-conformance)
            run_cargo_test --manifest-path qa/Cargo.toml --test conformance --locked ;;
        integration.repository-layout)
            run_cargo_test --manifest-path qa/Cargo.toml --test integration --locked ;;
        integration.offline-signer-firmware-signing)
            run_cargo_test --manifest-path qa/Cargo.toml --test tooling_firmware_signing --locked ;;
        integration.online-watcher-source)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/web/check_web_javascript.py
            ;;
        integration.kassee-web-generated)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 tools/build/web/build_web_index.py --check || return $?
            run_in_directory "$ROOT_DIR" python3 tools/build/web/build_app_css.py --check || return $?
            run_in_directory "$ROOT_DIR" python3 tools/build/web/build_constellation_assets.py --check || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/web/check_web_dom_contract.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/web/check_safe_html.py || return $?
            run_in_directory "$ROOT_DIR" node --test qa/checks/web/safe_html_hostile.test.mjs || return $?
            run_in_directory "$ROOT_DIR" node qa/checks/web/network_routing.test.mjs || return $?
            ;;
        integration.kassee-web-browser)
            require_command node || return
            run_in_directory "$ROOT_DIR" node qa/checks/web/check_web_runtime.mjs || return $?
            run_in_directory "$ROOT_DIR" node qa/checks/web/check_web_covenant_interactions.mjs || return $?
            run_in_directory "$ROOT_DIR" node qa/checks/web/covenant_sign_protocol.test.mjs || return $?
            run_in_directory "$ROOT_DIR" node qa/checks/web/check_web_critical_paths.mjs || return $?
            ;;
        integration.kassee-ios-quality)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/ios/run_xcode_application_tests.py || return $?
            if command -v swift >/dev/null 2>&1 || $DRY_RUN; then
                run_in_directory "$ROOT_DIR" python3 qa/checks/ios/swift_crap.py || return $?
            else
                printf '  ~ SKIP: Swift toolchain is unavailable; iOS CRAP execution cannot run on this host.\n'
            fi
            ;;
        integration.kassee-android-gradle)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 scripts/common/lib/make_tasks.py android test
            ;;
        integration.kassee-android-quality)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/android/check_android_architecture.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/android/kotlin_crap.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/android/run_instrumentation_tests.py || {
                local instrumentation_status=$?
                if ((instrumentation_status != 77)); then return "$instrumentation_status"; fi
                KASSIGNER_STEP_SKIPPED=true
                printf '  ~ SKIP: connected Android instrumentation requires an attached API-37 device/emulator.\n'
            }
            ;;
        static.firmware-assurance-contracts)
            require_command python3 || return
            local contract
            for contract in \
                qa/checks/firmware/board_partition_contract.py \
                qa/checks/firmware/m5stack_production_security.py \
                qa/checks/firmware/production_e2e_coverage.py \
                qa/checks/firmware/production_runtime_qualification.py \
                qa/checks/firmware/production_ui_graph.py \
                qa/checks/firmware/wallet_recovery_contract.py; do
                run_in_directory "$ROOT_DIR" python3 "$contract" || return $?
            done
            ;;
        coverage.critical-branch-targets)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/branch_ratchets.py || return $?
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/branch_ratchets.py --require-target
            ;;
        integration.real-node)
            run_in_directory "$ROOT_DIR" bash qa/linux/run-real-node-integration.sh
            ;;
        integration.funded-testnet-e2e)
            run_in_directory "$ROOT_DIR" bash qa/linux/run-funded-testnet-e2e.sh || {
                local funded_status=$?
                if ((funded_status != 77)); then return "$funded_status"; fi
                KASSIGNER_STEP_SKIPPED=true
                printf '  ~ SKIP: funded testnet E2E requires an interactive maintainer terminal.\n'
            }
            ;;
        mutation.kassee-ios)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/ios/run_mutation_tests.py || {
                local mutation_status=$?
                if ((mutation_status != 77)); then return "$mutation_status"; fi
                KASSIGNER_STEP_SKIPPED=true
                printf '  ~ SKIP: iOS mutation execution requires an eligible macOS/Xcode host.\n'
            }
            ;;
        mutation.kassee-android)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/android/run_mutation_tests.py || {
                local mutation_status=$?
                if ((mutation_status != 77)); then return "$mutation_status"; fi
                KASSIGNER_STEP_SKIPPED=true
                printf '  ~ SKIP: Android mutation execution requires Gradle plus Android SDK API 37.\n'
            }
            ;;
        mutation.repository-security-fresh)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/mutation.py run --fresh
            ;;
        mutation.repository-crypto-certification)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/security/mutation.py crypto-check
            ;;
        integration.signer-firmware-builds)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/firmware/check_firmware_builds.py
            ;;
        integration.signer-firmware-lints)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/firmware/check_firmware_lints.py
            ;;
        integration.repository-architecture)
            require_command python3 || return
            run_in_directory "$ROOT_DIR" python3 qa/checks/check_architecture.py || return $?
            ;;
        emulation.signer-firmware-qemu)
            run_in_directory "$ROOT_DIR" scripts/linux/qemu/test.sh ;;
        hardware.signer-firmware-device) run_firmware_hardware_tests ;;
        bench.shared-signer-protocol-throughput)
            require_command cargo || return
            # A resumed benchmark can bypass the global Cargo-resolution preflight.
            # Re-verify/repair the QA lock graph here so --locked remains fail-closed.
            run_cargo_metadata_check "$ROOT_DIR/qa" "Cargo.toml" || return $?
            run_in_directory "$ROOT_DIR" env CARGO_TARGET_DIR="$ROOT_DIR/target/qa" \
                cargo bench --manifest-path qa/Cargo.toml --bench protocol_throughput --locked
            ;;
        fuzz.repository-security-targets) run_fuzz_targets ;;
        *) printf 'ERROR: unknown catalog step: %s\n' "$id" >&2; return 2 ;;
    esac
}

step_supports_test_filter() {
    case "$1" in
        unit.shared-signer|unit.signer-firmware-core|unit.offline-signer|unit.online-watcher|unit.kassee-web|\
        unit.external-rqrr|unit.tools|integration.shared-signer-conformance|\
        integration.repository-layout|integration.offline-signer-firmware-signing)
            return 0 ;;
        *) return 1 ;;
    esac
}
