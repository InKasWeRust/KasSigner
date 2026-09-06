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

# Toolchain environment discovery for terminal and desktop-launched test runs.

prepend_path_once() {
    local directory="$1"
    [[ -d "$directory" ]] || return 0
    case ":${PATH}:" in
        *":${directory}:"*) ;;
        *) PATH="${directory}:${PATH}" ;;
    esac
}

source_environment_file() {
    local environment_file="$1"
    [[ -r "$environment_file" ]] || return 0
    # Generated Rust/ESP export files are user-local toolchain configuration.
    # shellcheck disable=SC1090
    if ! source "$environment_file"; then
        printf 'WARNING: could not load toolchain environment: %s\n' \
            "$environment_file" >&2
    fi
}

initialize_test_environment() {
    # Load the repository-pinned tool versions before any runner helper uses them.
    source_environment_file "${ROOT_DIR}/qa/config/toolchains.env"
    # Graphical launchers commonly omit user-local tool directories from PATH.
    prepend_path_once "${HOME}/.local/bin"
    prepend_path_once "${CARGO_HOME:-${HOME}/.cargo}/bin"
    source_environment_file "${CARGO_HOME:-${HOME}/.cargo}/env"

    # The native Linux bootstrap installs deterministic managed Java/Android
    # tooling under the user profile. Load those locations directly so a fresh
    # install can be followed immediately by qa/linux/run-all.sh without reopening
    # the terminal or sourcing ~/.profile manually.
    local managed_jdk="${HOME}/.local/share/kassigner/jdk-${KASSIGNER_ANDROID_JDK}"
    local managed_android="${ANDROID_SDK_ROOT:-${HOME}/Android/Sdk}"
    if [[ -x "${managed_jdk}/bin/java" ]]; then
        export JAVA_HOME="${managed_jdk}"
        prepend_path_once "${managed_jdk}/bin"
    fi
    if [[ -d "${managed_android}" ]]; then
        export ANDROID_SDK_ROOT="${managed_android}"
        export ANDROID_HOME="${managed_android}"
        prepend_path_once "${managed_android}/platform-tools"
        prepend_path_once "${managed_android}/cmdline-tools/latest/bin"
    fi

    # Firmware stages also need the environment emitted by espup. Support both
    # current locations used by the repository installer.
    source_environment_file "${HOME}/export-esp.sh"
    source_environment_file "${HOME}/.espup/export-esp.sh"

    export PATH
    hash -r
}

print_missing_command_guidance() {
    local command_name="$1"
    case "$command_name" in
        cargo)
            cat >&2 <<EOF_GUIDANCE
ERROR: required command not found: cargo
The runner loaded the normal Rust locations, including:
  ${CARGO_HOME:-${HOME}/.cargo}/env
  ${CARGO_HOME:-${HOME}/.cargo}/bin

If Rust is already installed, verify this works in a terminal:
  source \"${CARGO_HOME:-${HOME}/.cargo}/env\"
  cargo --version

If Rust is not installed, install rustup and reopen the runner:
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Firmware stages additionally require the ESP toolchain:
  cargo install espup
  espup install
EOF_GUIDANCE
            ;;
        *)
            printf 'ERROR: required command not found: %s\n' "$command_name" >&2
            ;;
    esac
}
