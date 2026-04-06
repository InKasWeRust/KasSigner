#!/bin/bash
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
# ══════════════════════════════════════════════════════════════
#
#   KasSigner — One-Step Installer (macOS only)
#
#   Installs the toolchain (if needed) and flashes firmware
#   for the Waveshare ESP32-S3-Touch-LCD-2.
#   Everything in one script. Just answer Y or N.
#
#   M5Stack users: see README.md for manual build instructions.
#
#   Usage — from the extracted KasSigner folder, run:
#
#     bash KasSigner_Install_v1_0_1.sh
#
# ══════════════════════════════════════════════════════════════

cd ~

# ── Colors ──
G='\033[0;32m'
R='\033[0;31m'
C='\033[0;36m'
Y='\033[1;33m'
B='\033[1m'
D='\033[2m'
X='\033[0m'

SECONDS=0

# ── Helpers ──
ask() {
    echo ""
    echo -e "  ${B}$1${X}"
    echo -e "  ${D}$2${X}"
    echo ""
    while true; do
        read -p "  Ready? [Y/N]: " yn </dev/tty
        case $yn in
            [Yy]* ) echo ""; return 0;;
            [Nn]* ) echo -e "\n  ${Y}Skipped.${X}\n"; return 1;;
            * ) echo "  Type Y or N and press Enter.";;
        esac
    done
}

ok()   { echo -e "  ${G}✓${X} $1"; }
warn() { echo -e "  ${Y}⚠${X} $1"; }
bad()  { echo -e "  ${R}✗${X} $1"; }
note() { echo -e "  ${C}→${X} $1"; }

die() {
    echo ""
    echo -e "  ${R}${B}$1${X}"
    [ -n "$2" ] && echo -e "  ${D}$2${X}"
    echo ""
    exit 1
}

# ── Banner ──
clear
echo ""
echo ""
echo -e "  ${B}┌──────────────────────────────────────────┐${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│        KasSigner Installer                │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│   Sets up your environment if needed,     │${X}"
echo -e "  ${B}│   then builds and flashes firmware.       │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}│   Just answer Y or N at each step.        │${X}"
echo -e "  ${B}│                                          │${X}"
echo -e "  ${B}└──────────────────────────────────────────┘${X}"
echo ""

# ══════════════════════════════════════════════════════
#   PHASE 1 — Environment check & setup
# ══════════════════════════════════════════════════════
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
HAS_ESPTOOL=false
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
(command -v esptool.py >/dev/null 2>&1 || command -v esptool >/dev/null 2>&1 || python3 -m esptool version >/dev/null 2>&1) && HAS_ESPTOOL=true

# ── Show status ──
$HAS_XCODE   && ok "Xcode Command Line Tools" || bad "Xcode Command Line Tools"
$HAS_RUST    && ok "Rust: $RUST_VER" || bad "Rust: not found"
$HAS_ESPUP   && ok "espup: $(espup --version 2>&1 | head -1)" || bad "espup: not found"
$HAS_XTENSA  && ok "Xtensa toolchain" || bad "Xtensa toolchain: not found"
$HAS_ESPFLASH && ok "espflash: $(espflash --version 2>&1 | head -1)" || bad "espflash: not found"
$HAS_ESPTOOL && ok "esptool: installed" || warn "esptool: not found (optional)"

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
        sh /tmp/rustup-init.sh -y --default-toolchain stable </dev/tty
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
        cargo install espup 2>&1

        if command -v espup >/dev/null 2>&1; then
            ok "espup installed"
        else
            die "espup installation failed.\n  Try: cargo install espup"
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
        espup install 2>&1

        if [ $? -ne 0 ]; then
            die "Toolchain installation failed.\n  Try: espup install"
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
        cargo install espflash 2>&1

        if command -v espflash >/dev/null 2>&1; then
            ok "espflash installed"
        else
            die "espflash installation failed.\n  Try: cargo install espflash"
        fi
    fi

    # ── esptool (optional, auto-install quietly) ──
    if ! $HAS_ESPTOOL; then
        pip3 install esptool --break-system-packages -q 2>/dev/null || \
        pip3 install esptool -q 2>/dev/null || true
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

# ══════════════════════════════════════════════════════
#   PHASE 2 — Connect device
# ══════════════════════════════════════════════════════
ask "Step 1 of 4 — Plug in your device" \
    "Connect the Waveshare ESP32-S3 to your Mac with a USB-C cable."
if [ $? -ne 0 ]; then
    die "You need to connect the device to continue."
fi

PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
if [ -z "$PORT" ]; then
    note "Looking for device..."
    for i in 1 2 3 4 5; do
        sleep 2
        PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
        [ -n "$PORT" ] && break
        echo -e "  ${D}  Waiting... ($((i*2))s)${X}"
    done
fi
if [ -z "$PORT" ]; then
    die "Device not found." \
        "Try a different USB-C cable — some only charge, no data."
fi
ok "Device found at $PORT"

# ══════════════════════════════════════════════════════
#   PHASE 2 — Erase device
# ══════════════════════════════════════════════════════
ask "Step 2 of 4 — Erase device" \
    "This clears the device so we can install fresh firmware.\n  All existing data on the device will be removed."
if [ $? -ne 0 ]; then
    die "Erase is required before installing new firmware."
fi

ERASE_OK=1
if command -v esptool.py >/dev/null 2>&1; then
    esptool.py --port "$PORT" erase_flash 2>&1 | grep -v "DEPRECATED\|Deprecated"
    ERASE_OK=${PIPESTATUS[0]}
elif command -v esptool >/dev/null 2>&1; then
    esptool --port "$PORT" erase-flash 2>&1
    ERASE_OK=$?
elif python3 -m esptool version >/dev/null 2>&1; then
    python3 -m esptool --port "$PORT" erase_flash 2>&1 | grep -v "DEPRECATED\|Deprecated"
    ERASE_OK=${PIPESTATUS[0]}
elif command -v espflash >/dev/null 2>&1; then
    espflash erase-flash --port "$PORT" 2>&1
    ERASE_OK=$?
else
    die "No erase tool found.\n  Run: pip3 install esptool"
fi

if [ $ERASE_OK -ne 0 ]; then
    die "Erase failed." \
        "Unplug the device, wait 5 seconds, plug it back in, and try again."
fi

sleep 2
ok "Device erased"

# ══════════════════════════════════════════════════════
#   PHASE 2 — Build / download firmware
# ══════════════════════════════════════════════════════

# Always clean previous build
rm -rf ~/KasSigner_build 2>/dev/null

# Re-source after setup phase
source ~/export-esp.sh 2>/dev/null
source ~/.espup/export-esp.sh 2>/dev/null
source "$HOME/.cargo/env" 2>/dev/null

# Detect toolchain for build path
# The rust-toolchain.toml in the project (channel = "esp") will
# automatically switch to the ESP toolchain when cargo runs.
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

    ZIP_FILE=$(ls -t ~/Downloads/KasSigner_KasSee*.zip 2>/dev/null | head -1)
    [ -z "$ZIP_FILE" ] && ZIP_FILE=$(ls -t ~/Downloads/KasSigner*.zip 2>/dev/null | head -1)
    if [ -z "$ZIP_FILE" ]; then
        die "KasSigner zip not found in ~/Downloads/" \
            "Download it from GitHub Releases and put it in Downloads."
    fi

    note "Unzipping $(basename "$ZIP_FILE")..."
    mkdir -p ~/KasSigner_build
    cd ~/KasSigner_build
    unzip -o "$ZIP_FILE" >/dev/null 2>&1

    PROJECT_DIR=$(ls -d ~/KasSigner_build/KasSigner*/bootloader 2>/dev/null | head -1)
    if [ -z "$PROJECT_DIR" ]; then
        die "Bootloader not found in zip."
    fi

    cd "$PROJECT_DIR"
    rm -rf target 2>/dev/null

    note "Compiling... (sit tight, this takes a few minutes)"
    echo ""

    BUILD_START=$SECONDS
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features skip-tests 2>&1

    if [ $? -ne 0 ]; then
        die "Build failed.\n  Try: espup update"
    fi

    BT=$((SECONDS - BUILD_START))
    ok "Compiled in ${BT}s"
    BIN_FILE="$PROJECT_DIR/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"
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

    if ! command -v espflash >/dev/null 2>&1 && ! command -v esptool.py >/dev/null 2>&1 && ! command -v esptool >/dev/null 2>&1 && ! python3 -m esptool version >/dev/null 2>&1; then
        die "No flash tool found.\n  Run: pip3 install esptool"
    fi

    ok "Firmware ready"
    FLASH_MODE="bin"
fi

# ══════════════════════════════════════════════════════
#   PHASE 2 — Flash
# ══════════════════════════════════════════════════════
ask "Step 4 of 4 — Install on device" \
    "Sending firmware to your device.\n  Don't unplug the USB cable!"
if [ $? -ne 0 ]; then
    die "Flash step is required."
fi

# Re-check device
if [ ! -e "$PORT" ]; then
    PORT=$(ls /dev/cu.usbmodem* 2>/dev/null | head -1)
    [ -z "$PORT" ] && die "Device disconnected."
fi

note "Installing firmware..."
echo ""

FLASH_OK=1
if [ "$FLASH_MODE" = "elf" ] && command -v espflash >/dev/null 2>&1; then
    espflash flash --port "$PORT" "$BIN_FILE" 2>&1
    FLASH_OK=$?
elif command -v espflash >/dev/null 2>&1; then
    espflash write-bin --port "$PORT" 0x0 "$BIN_FILE" 2>&1
    FLASH_OK=$?
elif command -v esptool.py >/dev/null 2>&1; then
    esptool.py --port "$PORT" --baud 460800 write_flash 0x0 "$BIN_FILE" 2>&1 | grep -v "DEPRECATED\|Deprecated"
    FLASH_OK=${PIPESTATUS[0]}
elif command -v esptool >/dev/null 2>&1; then
    esptool --port "$PORT" --baud 460800 write-flash 0x0 "$BIN_FILE" 2>&1
    FLASH_OK=$?
elif python3 -m esptool version >/dev/null 2>&1; then
    python3 -m esptool --port "$PORT" --baud 460800 write_flash 0x0 "$BIN_FILE" 2>&1 | grep -v "DEPRECATED\|Deprecated"
    FLASH_OK=${PIPESTATUS[0]}
fi

if [ $FLASH_OK -ne 0 ]; then
    die "Flash failed." \
        "Unplug the device, wait 5 seconds, plug it back in, and try again."
fi

# ══════════════════════════════════════════════════════
#   Done!
# ══════════════════════════════════════════════════════
T=$SECONDS
M=$((T / 60))
S=$((T % 60))

echo ""
echo ""
echo -e "  ${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}"
echo -e "  ${G}${B}  KasSigner installed successfully!${X}"
echo -e "  ${G}  Total time: ${M}m ${S}s${X}"
echo -e "  ${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${X}"
echo ""
echo -e "  ${D}Your device is ready. You can close this window.${X}"
echo ""
