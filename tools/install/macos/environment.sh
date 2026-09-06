# ══════════════════════════════════════════════════════
#   Environment check & setup
# ══════════════════════════════════════════════════════
# shellcheck source=qa/config/toolchains.env
source "$INSTALL_ROOT/qa/config/toolchains.env"
echo -e "  ${B}Scanning your environment...${X}"
echo ""

# Load any existing environment
source ~/export-esp.sh 2>/dev/null
source ~/.espup/export-esp.sh 2>/dev/null
source "$HOME/.cargo/env" 2>/dev/null

# ── Detect what's installed ──
HAS_XCODE=false
HAS_RUST=false
HAS_ESPUP=false
HAS_XTENSA=false
HAS_ESPFLASH=false
RUST_VER=""

xcode-select -p >/dev/null 2>&1 && HAS_XCODE=true
if command -v rustc >/dev/null 2>&1; then
    RUST_VER=$(rustc --version 2>&1 | head -1)
    HAS_RUST=true
fi
command -v espup >/dev/null 2>&1 && HAS_ESPUP=true
if [ -d "$HOME/.rustup/toolchains/esp" ]; then
    if echo "$RUST_VER" | grep -qi "esp"; then
        HAS_XTENSA=true
    elif [ -f "$HOME/.rustup/toolchains/esp/bin/rustc" ]; then
        HAS_XTENSA=true
    elif command -v xtensa-esp32s3-elf-gcc >/dev/null 2>&1; then
        HAS_XTENSA=true
    fi
fi
command -v espflash >/dev/null 2>&1 && HAS_ESPFLASH=true

# ── Show status ──
$HAS_XCODE   && ok "Xcode Command Line Tools" || bad "Xcode Command Line Tools"
$HAS_RUST    && ok "Rust: $RUST_VER" || bad "Rust: not found"
$HAS_ESPUP   && ok "espup: $(espup --version 2>&1 | head -1)" || bad "espup: not found"
$HAS_XTENSA  && ok "Xtensa toolchain" || bad "Xtensa toolchain: not found"
$HAS_ESPFLASH && ok "espflash: $(espflash --version 2>&1 | head -1)" || bad "espflash: not found"

# ── Count missing required tools ──
SETUP_NEEDED=false
(! $HAS_XCODE || ! $HAS_RUST || ! $HAS_ESPUP || ! $HAS_XTENSA || ! $HAS_ESPFLASH) && SETUP_NEEDED=true

if $SETUP_NEEDED; then
    echo ""
    echo -e "  ${Y}${B}Some build tools are missing — installing them first.${X}"

    # ── Xcode CLT ──
    if ! $HAS_XCODE; then
        ask "Setup — Install Xcode Command Line Tools" \
            "Basic build tools that macOS needs.\n  A system popup will appear — click 'Install' and wait."
        if [ $? -ne 0 ]; then
            die "Xcode tools are required."
        fi

        xcode-select --install 2>/dev/null
        note "Waiting for installation... (click 'Install' on the popup)"
        while ! xcode-select -p >/dev/null 2>&1; do
            sleep 5
            echo -e "  ${D}  Still installing...${X}"
        done
        ok "Xcode Command Line Tools installed"
    fi

    # ── Rust ──
    if ! $HAS_RUST; then
        ask "Setup — Install Rust" \
            "The programming language KasSigner is written in."
        if [ $? -ne 0 ]; then
            die "Rust is required."
        fi

        note "Installing Rust..."
        echo ""
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
        sh /tmp/rustup-init.sh -y --default-toolchain "$KASSIGNER_STABLE_RUST" </dev/tty
        rm -f /tmp/rustup-init.sh
        source "$HOME/.cargo/env" 2>/dev/null

        if command -v rustc >/dev/null 2>&1; then
            ok "Rust installed: $(rustc --version 2>&1)"
        else
            die "Rust installation failed." \
                "Try manually:\n  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        fi
    fi

    # ── espup ──
    if ! $HAS_ESPUP; then
        ask "Setup — Install espup" \
            "Manages the ESP32 Rust toolchain.\n  Takes about 1-2 minutes."
        if [ $? -ne 0 ]; then
            die "espup is required."
        fi

        source "$HOME/.cargo/env" 2>/dev/null
        note "Installing espup..."
        echo ""
        cargo install espup --version "$KASSIGNER_ESPUP_VERSION" --locked --force 2>&1

        if command -v espup >/dev/null 2>&1; then
            ok "espup installed"
        else
            die "espup installation failed.\n  Try: cargo install espup --version $KASSIGNER_ESPUP_VERSION --locked"
        fi
    fi

    # ── Xtensa toolchain ──
    if ! $HAS_XTENSA; then
        ask "Setup — Install ESP32 Xtensa toolchain" \
            "The Rust compiler for the ESP32-S3 chip.\n  Downloads ~1 GB — takes 5-15 minutes."
        if [ $? -ne 0 ]; then
            die "Xtensa toolchain is required."
        fi

        source "$HOME/.cargo/env" 2>/dev/null
        note "Installing Xtensa toolchain..."
        echo ""
        espup install --toolchain-version "$KASSIGNER_ESP_RUST" --export-file "$HOME/export-esp.sh" 2>&1

        if [ $? -ne 0 ]; then
            die "Toolchain installation failed.\n  Try: espup install --toolchain-version $KASSIGNER_ESP_RUST"
        fi

        # Source the export file
        [ -f ~/export-esp.sh ] && source ~/export-esp.sh
        [ -f ~/.espup/export-esp.sh ] && source ~/.espup/export-esp.sh

        # Add to shell profile if not already there
        SHELL_RC=""
        [ -f ~/.zshrc ] && SHELL_RC=~/.zshrc
        [ -z "$SHELL_RC" ] && [ -f ~/.bash_profile ] && SHELL_RC=~/.bash_profile
        [ -z "$SHELL_RC" ] && [ -f ~/.bashrc ] && SHELL_RC=~/.bashrc

        if [ -n "$SHELL_RC" ] && ! grep -q "export-esp.sh" "$SHELL_RC" 2>/dev/null; then
            echo '' >> "$SHELL_RC"
            echo '# KasSigner ESP toolchain' >> "$SHELL_RC"
            echo 'source ~/export-esp.sh 2>/dev/null' >> "$SHELL_RC"
            ok "Added to $SHELL_RC"
        fi

        ok "Xtensa toolchain installed"
    fi

    # ── espflash ──
    if ! $HAS_ESPFLASH; then
        ask "Setup — Install espflash" \
            "Sends firmware to your device over USB.\n  Takes about 1-2 minutes."
        if [ $? -ne 0 ]; then
            die "espflash is required."
        fi

        source "$HOME/.cargo/env" 2>/dev/null
        note "Installing espflash..."
        echo ""
        cargo install espflash --version "$KASSIGNER_ESPFLASH_VERSION" --locked --force 2>&1

        if command -v espflash >/dev/null 2>&1; then
            ok "espflash installed"
        else
            die "espflash installation failed.\n  Try: cargo install espflash --version $KASSIGNER_ESPFLASH_VERSION --locked"
        fi
    fi

    echo ""
    echo -e "  ${G}${B}Environment ready.${X}"
    echo ""

    # Reload everything
    source ~/export-esp.sh 2>/dev/null
    source ~/.espup/export-esp.sh 2>/dev/null
    source "$HOME/.cargo/env" 2>/dev/null
else
    echo ""
    echo -e "  ${G}${B}All build tools present.${X}"
    echo ""
fi
