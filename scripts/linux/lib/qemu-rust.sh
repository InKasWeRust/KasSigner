# Install and load Rust, the ESP Xtensa toolchain, and espflash.

esp_toolchain_dir() {
    printf '%s/toolchains/esp\n' "${RUSTUP_HOME:-${HOME}/.rustup}"
}

load_esp_environment() {
    source_if_present "${CARGO_HOME:-${HOME}/.cargo}/env"
    source_if_present "${HOME}/export-esp.sh"
    source_if_present "${HOME}/.espup/export-esp.sh"
}

esp_toolchain_version() {
    local toolchain_dir
    toolchain_dir="$(esp_toolchain_dir)"

    if rustup run esp rustc --version >/dev/null 2>&1; then
        rustup run esp rustc --version
        return
    fi

    if [[ -x "${toolchain_dir}/bin/rustc" ]]; then
        "${toolchain_dir}/bin/rustc" --version
        return
    fi

    return 1
}

firmware_cargo_uses_esp_toolchain() {
    (
        cd "${ROOT_DIR}/apps/signer-firmware"
        cargo --version >/dev/null 2>&1
    )
}

install_rustup_if_missing() {
    if command -v cargo >/dev/null 2>&1 \
        && command -v rustup >/dev/null 2>&1; then
        return
    fi

    require_command curl
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal
    source_if_present "${CARGO_HOME:-${HOME}/.cargo}/env"
    require_command cargo
    require_command rustup
}

install_esp_rust_toolchain() {
    local version

    load_esp_environment
    require_command cargo
    require_command rustup

    if ! version="$(esp_toolchain_version 2>/dev/null)"; then
        local espup_actual
        espup_actual="$(espup --version 2>/dev/null || true)"
        if [[ "$espup_actual" != *"$KASSIGNER_ESPUP_VERSION"* ]]; then
            cargo install espup --version "$KASSIGNER_ESPUP_VERSION" --locked --force
        fi
        require_command espup
        espup install --toolchain-version "$KASSIGNER_ESP_RUST" --export-file "$HOME/export-esp.sh"
        load_esp_environment
        version="$(esp_toolchain_version 2>/dev/null)" || {
            printf 'ERROR: espup completed, but no usable ESP Rust toolchain was found.\n' >&2
            printf 'Checked rustup toolchain "esp" and: %s\n' "$(esp_toolchain_dir)" >&2
            return 1
        }
    fi

    firmware_cargo_uses_esp_toolchain || {
        printf 'ERROR: Cargo cannot activate the ESP toolchain selected by ' >&2
        printf 'apps/signer-firmware/rust-toolchain.toml.\n' >&2
        printf 'Detected toolchain: %s\n' "${version}" >&2
        return 1
    }

    printf 'ESP Rust toolchain ready: %s\n' "${version}"
}

install_espflash() {
    require_command cargo
    local actual
    actual="$(espflash --version 2>/dev/null || true)"
    if [[ "$actual" != *"$KASSIGNER_ESPFLASH_VERSION"* ]]; then
        cargo install espflash --version "$KASSIGNER_ESPFLASH_VERSION" --locked --force
    fi
    require_command espflash
}
