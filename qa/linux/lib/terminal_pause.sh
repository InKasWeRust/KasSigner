#!/usr/bin/env bash
# Shared terminal-exit behavior for user-facing Linux QA launchers.
#
# Direct interactive launches print an unambiguous PASS/FAIL result and pause
# before the terminal closes. Nested QA launchers, GNU Make recipes, CI jobs,
# and non-interactive invocations never pause.

if [[ "${KASSIGNER_QA_LAUNCHER_ACTIVE:-0}" == "1" ]]; then
    KASSIGNER_QA_LAUNCHER_TOP_LEVEL=false
else
    KASSIGNER_QA_LAUNCHER_TOP_LEVEL=true
    export KASSIGNER_QA_LAUNCHER_ACTIVE=1
fi

kassigner_qa_should_pause() {
    # run-all.sh keeps its documented --pause switch. An explicit request wins
    # even when stdin/stdout are not terminals, matching the old behavior.
    if [[ "${PAUSE_ON_EXIT:-false}" == "true" ]]; then
        return 0
    fi

    $KASSIGNER_QA_LAUNCHER_TOP_LEVEL || return 1
    [[ "${KASSIGNER_QA_NO_PAUSE:-0}" != "1" ]] || return 1
    [[ "${CI:-}" != "1" && "${CI:-}" != "true" ]] || return 1
    [[ "${MAKELEVEL:-0}" =~ ^0*$ ]] || return 1
    [[ -t 0 && -t 1 ]] || return 1
}

kassigner_qa_exit_handler() {
    local status=$?
    trap - EXIT

    if $KASSIGNER_QA_LAUNCHER_TOP_LEVEL; then
        {
            printf '\n================================================================================\n'
            if ((status == 0)); then
                printf 'PASS: %s completed successfully.\n' "$KASSIGNER_QA_LAUNCHER_LABEL"
            elif ((status == 77)); then
                printf 'SKIP: %s is not eligible in this environment (exit 77).\n' "$KASSIGNER_QA_LAUNCHER_LABEL"
            else
                printf 'FAIL: %s exited with code %s.\n' "$KASSIGNER_QA_LAUNCHER_LABEL" "$status"
            fi
            printf '================================================================================\n'
        } >&2
    fi

    if kassigner_qa_should_pause; then
        if [[ -t 0 ]]; then
            read -r -p 'Press Enter to close this terminal...' _ || true
        else
            printf 'Press Enter to close this terminal...'
            read -r _ || true
        fi
    fi

    exit "$status"
}

kassigner_qa_install_exit_handler() {
    KASSIGNER_QA_LAUNCHER_LABEL="$1"
    trap kassigner_qa_exit_handler EXIT
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    kassigner_qa_install_exit_handler "QA terminal helper"
    printf 'ERROR: %s is a support library and is not a standalone QA entrypoint.\n' \
        "${BASH_SOURCE[0]}" >&2
    exit 2
fi
