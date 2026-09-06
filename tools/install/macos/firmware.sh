# ══════════════════════════════════════════════════════
#   Build / download firmware
# ══════════════════════════════════════════════════════

# Always clean previous build
rm -rf ~/KasSigner_build 2>/dev/null

# Re-source after setup
source ~/export-esp.sh 2>/dev/null
source ~/.espup/export-esp.sh 2>/dev/null
source "$HOME/.cargo/env" 2>/dev/null

# Detect toolchain for build path
# apps/signer-firmware/rust-toolchain.toml (channel = "esp") will
# automatically switch to the ESP toolchain for firmware Cargo commands.
# We just need to verify the toolchain EXISTS, not that it's active.
CAN_BUILD=false
CAN_FLASH_ELF=false

if [ -d "$HOME/.rustup/toolchains/esp" ] && command -v cargo >/dev/null 2>&1; then
    CAN_BUILD=true
fi
command -v espflash >/dev/null 2>&1 && CAN_FLASH_ELF=true

BIN_FILE=""
FLASH_MODE=""

if $CAN_BUILD && $CAN_FLASH_ELF; then
    # ── BUILD FROM SOURCE ──
    ask "Step 3 of 4 — Build firmware" \
        "Compiling firmware from source — takes about 2-5 minutes."
    if [ $? -ne 0 ]; then
        die "Build step is required."
    fi

    # Prefer the source tree that launched install.sh. Current releases are
    # shipped as flat archives, so no wrapper directory is required.
    PROJECT_DIR="$INSTALL_ROOT/apps/signer-firmware"
    if [ ! -f "$PROJECT_DIR/Cargo.toml" ]; then
        ZIP_FILE=$(ls -t ~/Downloads/KasSigner_KasSee*.zip 2>/dev/null | head -1)
        [ -z "$ZIP_FILE" ] && ZIP_FILE=$(ls -t ~/Downloads/KasSigner*.zip 2>/dev/null | head -1)
        if [ -z "$ZIP_FILE" ]; then
            die "KasSigner source tree not found." \
                "Run install.sh from an extracted KasSigner repository or place a release zip in ~/Downloads/."
        fi

        note "Unzipping $(basename "$ZIP_FILE")..."
        mkdir -p ~/KasSigner_build
        cd ~/KasSigner_build
        unzip -o "$ZIP_FILE" >/dev/null 2>&1

        if [ -f ~/KasSigner_build/apps/signer-firmware/Cargo.toml ]; then
            PROJECT_DIR=~/KasSigner_build/apps/signer-firmware
        else
            CARGO_FILE=$(find ~/KasSigner_build -maxdepth 4 -type f -path '*/apps/signer-firmware/Cargo.toml' -print | head -1)
            [ -n "$CARGO_FILE" ] && PROJECT_DIR=$(dirname "$CARGO_FILE")
        fi
        if [ -z "$PROJECT_DIR" ] || [ ! -f "$PROJECT_DIR/Cargo.toml" ]; then
            die "Firmware project not found in zip."
        fi
    fi

    cd "$PROJECT_DIR"
    rm -rf target 2>/dev/null

    note "Compiling firmware from source..."
    echo ""

    BUILD_START=$SECONDS
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --locked --release 2>&1

    if [ $? -ne 0 ]; then
        die "Build failed.\n  Try: espup update"
    fi

    BT=$((SECONDS - BUILD_START))
    ok "Compiled in ${BT}s"
    BIN_FILE="$PROJECT_DIR/target/xtensa-esp32s3-none-elf/release/kassigner-firmware"
    FLASH_MODE="elf"

else
    # ── DOWNLOAD PRE-BUILT ──
    ask "Step 3 of 4 — Download firmware" \
        "Downloading pre-built firmware from GitHub."
    if [ $? -ne 0 ]; then
        die "Firmware download is required."
    fi

    GITHUB_RELEASE="https://github.com/InKasWeRust/KasSigner/releases/latest/download"
    mkdir -p ~/KasSigner_build

    ZIP_FILE=$(ls -t ~/Downloads/KasSigner_KasSee*.zip 2>/dev/null | head -1)
    if [ -n "$ZIP_FILE" ]; then
        unzip -o "$ZIP_FILE" -d ~/KasSigner_build >/dev/null 2>&1
        BIN_FILE=$(find ~/KasSigner_build -name "kassigner-waveshare.bin" 2>/dev/null | head -1)
    fi

    if [ -z "$BIN_FILE" ] || [ ! -f "$BIN_FILE" ]; then
        note "Downloading from GitHub..."
        curl -L --progress-bar -o ~/KasSigner_build/kassigner-waveshare.bin \
            "$GITHUB_RELEASE/kassigner-waveshare.bin"

        if [ $? -ne 0 ] || [ ! -f ~/KasSigner_build/kassigner-waveshare.bin ]; then
            die "Download failed.\n  Manual: https://github.com/InKasWeRust/KasSigner/releases"
        fi
        BIN_FILE=~/KasSigner_build/kassigner-waveshare.bin
    fi

    if ! command -v espflash >/dev/null 2>&1; then
        die "espflash is required to install firmware.\n  Run: cargo install espflash"
    fi

    ok "Firmware ready"
    FLASH_MODE="bin"
fi
