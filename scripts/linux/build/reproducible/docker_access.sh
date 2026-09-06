#!/usr/bin/env bash

# Docker access bootstrap for the one-command reproducible build.
#
# The common Linux failure mode is that /etc/group already contains the user in
# the docker group, but the terminal was opened before that membership became
# active. In that case the build re-execs itself under `sg docker` so the user
# does not need to run newgrp, log out, or manually probe the daemon.

REPRO_DOCKER_REEXEC_STATUS=11

repro_docker_error_kind() {
    local text="${1,,}"
    if [[ "$text" == *"permission denied"* || "$text" == *"operation not permitted"* ]]; then
        printf 'permission\n'
    elif [[ "$text" == *"cannot connect to the docker daemon"* \
        || "$text" == *"is the docker daemon running"* \
        || "$text" == *"connection refused"* \
        || "$text" == *"no such file or directory"* ]]; then
        printf 'daemon\n'
    else
        printf 'other\n'
    fi
}

repro_start_docker() {
    printf '\nDocker is installed but the daemon is not available. Starting it automatically.\n'
    if command -v service >/dev/null 2>&1; then
        run_as_root "start the Docker daemon for the reproducible build" service docker start
    elif command -v systemctl >/dev/null 2>&1; then
        run_as_root "start the Docker daemon for the reproducible build" systemctl start docker
    else
        printf 'ERROR: no supported Docker service manager was found (service/systemctl).\n' >&2
        return 2
    fi
}

repro_docker_group_state() {
    local user_name="${USER:-$(id -un)}"
    local current_groups configured_groups
    current_groups="$(id -nG 2>/dev/null || true)"
    configured_groups="$(id -nG "$user_name" 2>/dev/null || true)"

    if [[ " $current_groups " == *" docker "* ]]; then
        printf 'active\n'
    elif [[ " $configured_groups " == *" docker "* ]]; then
        printf 'configured\n'
    else
        printf 'absent\n'
    fi
}

repro_enable_docker_group() {
    local user_name="${USER:-$(id -un)}"

    printf '\nDocker is running, but %s does not currently have socket access.\n' "$user_name"
    printf 'KasSigner will add %s to the docker group and continue this same build automatically.\n' "$user_name"
    printf 'Docker-group membership is root-equivalent on this machine; administrator access may be requested.\n'
    run_as_root "add $user_name to the docker group for reproducible builds" \
        usermod -aG docker "$user_name"
}

repro_reexec_with_docker_group() {
    local script="$1"
    shift

    if [[ "${KASSIGNER_DOCKER_GROUP_REEXEC:-0}" == "1" ]]; then
        printf 'ERROR: Docker socket access is still unavailable after activating the docker group for this build.\n' >&2
        printf 'Current identity: ' >&2
        id >&2 || true
        [[ ! -e /var/run/docker.sock ]] || ls -l /var/run/docker.sock >&2 || true
        [[ -z "${DOCKER_HOST:-}" ]] || printf 'DOCKER_HOST=%s\n' "$DOCKER_HOST" >&2
        return 2
    fi

    command -v sg >/dev/null 2>&1 || {
        printf 'ERROR: docker group activation is required, but the `sg` command is unavailable.\n' >&2
        return 2
    }

    local command_text
    printf -v command_text '%q ' env KASSIGNER_DOCKER_GROUP_REEXEC=1 "$script" "$@"
    printf '\nDocker group membership is configured but not active in this terminal.\n'
    printf 'KasSigner is activating it for this build automatically; no newgrp/login step is required.\n'
    exec sg docker -c "$command_text"
}

repro_ensure_docker_access() {
    command -v docker >/dev/null 2>&1 || {
        printf 'ERROR: Docker is required for reproducible builds, but the docker command is not installed.\n' >&2
        return 2
    }

    local output kind state
    if output="$(docker info 2>&1)"; then
        return 0
    fi
    kind="$(repro_docker_error_kind "$output")"

    if [[ "$kind" == "daemon" ]]; then
        repro_start_docker || return $?
        if output="$(docker info 2>&1)"; then
            return 0
        fi
        kind="$(repro_docker_error_kind "$output")"
    fi

    if [[ "$kind" == "permission" ]]; then
        state="$(repro_docker_group_state)"
        case "$state" in
            configured)
                return "$REPRO_DOCKER_REEXEC_STATUS"
                ;;
            absent)
                repro_enable_docker_group || return $?
                return "$REPRO_DOCKER_REEXEC_STATUS"
                ;;
            active)
                printf 'ERROR: Docker socket access failed even though this process already has the docker group active.\n' >&2
                printf 'Current identity: ' >&2
                id >&2 || true
                [[ ! -e /var/run/docker.sock ]] || ls -l /var/run/docker.sock >&2 || true
                [[ -z "${DOCKER_HOST:-}" ]] || printf 'DOCKER_HOST=%s\n' "$DOCKER_HOST" >&2
                return 2
                ;;
        esac
    fi

    printf 'ERROR: Docker is available but KasSigner could not use it:\n%s\n' "$output" >&2
    return 2
}
