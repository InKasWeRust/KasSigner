# Shared terminal explanation and sudo helpers.

explain_admin_access() {
    local reason="$1"

    printf '\n' >&2
    printf 'KasSigner needs administrator access.\n' >&2
    printf 'Reason: %s\n' "${reason}" >&2
    printf 'The next prompt is from sudo and requires your user password.\n' >&2
    printf 'KasSigner does not read, store, or transmit the password.\n\n' >&2
}

request_admin_access() {
    local reason="$1"

    command -v sudo >/dev/null 2>&1 || {
        printf 'ERROR: administrator access is required, but sudo is unavailable.\n' >&2
        return 127
    }

    # A valid cached credential means no password prompt will be shown.
    if sudo -n true >/dev/null 2>&1; then
        return
    fi

    explain_admin_access "${reason}"
    sudo -v
}

run_as_root() {
    local reason="$1"
    shift

    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
        return
    fi

    request_admin_access "${reason}"
    sudo "$@"
}
