# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
#
# Reproducible firmware build (both platforms) + KasSee WASM verification
#
# Usage:
#   Without signing key (anyone — unsigned reproducible build):
#     docker build --platform linux/amd64 -t kassigner-build .
#
#   With signing key (developer only — signed reproducible build):
#     docker build --platform linux/amd64 --secret id=signkey,src=dev_signing_key.bin -t kassigner-build .
#
# Output files (firmware only — KasSee is browser-deployed via gh-pages):
#   kassigner-waveshare.bin       — app-only image (for developers, hash verification)
#   kassigner-m5stack.bin         — app-only image (for developers, hash verification)
#   kassigner-waveshare-full.bin  — merged full-flash image (bootloader + partition table + app)
#   kassigner-m5stack-full.bin    — merged full-flash image (bootloader + partition table + app)
#
# Flashing:
#   Full image (new users):  python3 -m esptool --port <PORT> --baud 460800 write_flash 0x0 kassigner-waveshare-full.bin
#   App-only (developers):   python3 -m esptool --port <PORT> --baud 460800 write_flash 0x10000 kassigner-waveshare.bin

FROM --platform=linux/amd64 kassigner-toolchain:v2

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner

# ════════════════════════════════════════════════════
#  Copy only code folders (no docs, no gh-pages assets)
# ════════════════════════════════════════════════════
COPY bootloader/ bootloader/
COPY kassee/ kassee/
COPY rqrr_nostd/ rqrr_nostd/
COPY tools/ tools/
COPY rust-toolchain.toml .

ENV SOURCE_DATE_EPOCH=0

# Install espflash for image generation
RUN source /root/esp-env.sh && \
    cargo install espflash --version 3.3.0

# ════════════════════════════════════════════════════
#  Verify KasSee WASM compiles (no output retained)
# ════════════════════════════════════════════════════
RUN source /root/esp-env.sh && \
    rustup target add wasm32-unknown-unknown --toolchain 1.85.0 && \
    cd kassee && \
    cargo build --target wasm32-unknown-unknown --release 2>&1 | tail -3 && \
    echo "============================================" && \
    echo "  KasSee WASM build verified" && \
    echo "============================================"

# Build gen-hash tool (uses host toolchain, not Xtensa)
RUN cargo build --manifest-path tools/Cargo.toml --bin gen-hash --release 2>&1 | tail -1

# ════════════════════════════════════════════════════
#  Waveshare build with hash convergence
# ════════════════════════════════════════════════════

# Pass 1: Initial compilation
RUN source /root/esp-env.sh && \
    cd bootloader && \
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features skip-tests

# Pass 1: Generate .bin, compute hash, write firmware_hash.rs
RUN --mount=type=secret,id=signkey,required=false \
    source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/ws-pass1.bin 2>&1 | grep -v INFO && \
    if [ -f /run/secrets/signkey ]; then \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass1.bin /run/secrets/signkey 2>&1; \
    else \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass1.bin 2>&1; \
    fi && \
    echo "=== Pass 1 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 2: Recompile with embedded hash
RUN source /root/esp-env.sh && \
    cd bootloader && \
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features skip-tests

# Pass 2: Recompute hash — should converge
RUN --mount=type=secret,id=signkey,required=false \
    source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/ws-pass2.bin 2>&1 | grep -v INFO && \
    if [ -f /run/secrets/signkey ]; then \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass2.bin /run/secrets/signkey 2>&1; \
    else \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass2.bin 2>&1; \
    fi && \
    echo "=== Pass 2 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 3: Final recompile + verify convergence
RUN source /root/esp-env.sh && \
    cd bootloader && \
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features skip-tests

# Final app-only image (unchanged — preserves existing hash)
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-waveshare.bin 2>&1 | grep -v INFO && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner Waveshare Build Complete" && \
    echo "============================================" && \
    sha256sum /build/kassigner-waveshare.bin && \
    ls -la /build/kassigner-waveshare.bin && \
    echo "============================================"

# Merged full-flash image (bootloader + partition table + app)
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 --merge --flash-size 16mb \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-waveshare-full.bin 2>&1 | grep -v INFO && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner Waveshare Full Image" && \
    echo "============================================" && \
    sha256sum /build/kassigner-waveshare-full.bin && \
    ls -la /build/kassigner-waveshare-full.bin && \
    echo "============================================"

# ════════════════════════════════════════════════════
#  M5Stack build with hash convergence
# ════════════════════════════════════════════════════

# Pass 1: Initial compilation
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release --no-default-features --features m5stack

# Pass 1: Generate .bin, compute hash, write firmware_hash.rs
RUN --mount=type=secret,id=signkey,required=false \
    source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/m5-pass1.bin 2>&1 | grep -v INFO && \
    if [ -f /run/secrets/signkey ]; then \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass1.bin /run/secrets/signkey 2>&1; \
    else \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass1.bin 2>&1; \
    fi && \
    echo "=== M5 Pass 1 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 2: Recompile with embedded hash
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release --no-default-features --features m5stack

# Pass 2: Recompute hash
RUN --mount=type=secret,id=signkey,required=false \
    source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/m5-pass2.bin 2>&1 | grep -v INFO && \
    if [ -f /run/secrets/signkey ]; then \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass2.bin /run/secrets/signkey 2>&1; \
    else \
        cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass2.bin 2>&1; \
    fi && \
    echo "=== M5 Pass 2 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 3: Final recompile + verify convergence
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release --no-default-features --features m5stack

# Final app-only image (unchanged — preserves existing hash)
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-m5stack.bin 2>&1 | grep -v INFO && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner M5Stack Build Complete" && \
    echo "============================================" && \
    sha256sum /build/kassigner-m5stack.bin && \
    ls -la /build/kassigner-m5stack.bin && \
    echo "============================================"

# Merged full-flash image (bootloader + partition table + app)
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 --merge --flash-size 16mb \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-m5stack-full.bin 2>&1 | grep -v INFO && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner M5Stack Full Image" && \
    echo "============================================" && \
    sha256sum /build/kassigner-m5stack-full.bin && \
    ls -la /build/kassigner-m5stack-full.bin && \
    echo "============================================"

CMD ["bash", "-c", "\
    echo '=== Waveshare (app-only) ===' && sha256sum /build/kassigner-waveshare.bin && \
    echo '=== Waveshare (full flash) ===' && sha256sum /build/kassigner-waveshare-full.bin && \
    echo '=== M5Stack (app-only) ===' && sha256sum /build/kassigner-m5stack.bin && \
    echo '=== M5Stack (full flash) ===' && sha256sum /build/kassigner-m5stack-full.bin"]
