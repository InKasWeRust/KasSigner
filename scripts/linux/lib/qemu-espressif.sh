# Install and expose Espressif's ESP32-S3-capable QEMU build.

resolve_idf_path() {
    if [[ -n "${KASSIGNER_IDF_PATH:-}" ]]; then
        if [[ ! -f "${KASSIGNER_IDF_PATH}/tools/idf_tools.py" ]]; then
            printf 'ERROR: invalid KASSIGNER_IDF_PATH: %s\n' \
                "${KASSIGNER_IDF_PATH}" >&2
            return 2
        fi
        printf '%s\n' "${KASSIGNER_IDF_PATH}"
        return
    fi

    mkdir -p "${QEMU_STATE_DIR}"
    if [[ ! -d "${MANAGED_IDF_PATH}/.git" ]]; then
        if [[ -e "${MANAGED_IDF_PATH}" ]]; then
            rm -rf "${MANAGED_IDF_PATH}"
        fi
        git clone --filter=blob:none --depth 1 --branch "${ESP_IDF_VERSION}" \
            https://github.com/espressif/esp-idf.git "${MANAGED_IDF_PATH}"
    fi
    printf '%s\n' "${MANAGED_IDF_PATH}"
}

idf_tools_root() {
    printf '%s\n' "${IDF_TOOLS_PATH:-${HOME}/.espressif}"
}

find_installed_xtensa_qemu() {
    local tools_root search_root qemu_binary
    tools_root="$(idf_tools_root)"
    search_root="${tools_root}/tools/qemu-xtensa"

    if [[ -d "${search_root}" ]]; then
        qemu_binary="$(
            find -L "${search_root}" -type f -name qemu-system-xtensa \
                -perm -u+x -print 2>/dev/null | sort -V | tail -n 1
        )"
        if [[ -n "${qemu_binary}" ]]; then
            printf '%s\n' "${qemu_binary}"
            return
        fi
    fi

    command -v qemu-system-xtensa >/dev/null 2>&1 || return 1
    command -v qemu-system-xtensa
}

install_espressif_qemu() {
    local idf_path idf_tools qemu_binary
    idf_path="$(resolve_idf_path)"
    idf_tools="${idf_path}/tools/idf_tools.py"
    export IDF_TOOLS_PATH="$(idf_tools_root)"

    # Only QEMU is needed. Activating the complete ESP-IDF environment would
    # require unrelated C/C++ compilers, GDB, OpenOCD, and ROM packages even
    # though this firmware is compiled by the ESP Rust toolchain.
    python3 "${idf_tools}" install qemu-xtensa

    qemu_binary="$(find_installed_xtensa_qemu)" || {
        printf 'ERROR: Espressif QEMU was installed, but qemu-system-xtensa ' >&2
        printf 'could not be located under %s.\n' "$(idf_tools_root)" >&2
        return 1
    }
    [[ -x "${qemu_binary}" ]] || {
        printf 'ERROR: QEMU executable is not runnable: %s\n' \
            "${qemu_binary}" >&2
        return 1
    }

    export IDF_PATH="${idf_path}"
    export QEMU_SYSTEM_XTENSA="${qemu_binary}"
    export PATH="$(dirname "${qemu_binary}"):${PATH}"
    printf 'Espressif QEMU ready: %s\n' "${QEMU_SYSTEM_XTENSA}"
}
