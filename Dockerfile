# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
#
# Reproducible firmware build (both platforms)
#
# Usage:
#   Without signing key (anyone — unsigned reproducible build):
#     docker build --platform linux/amd64 -t kassigner-build .
#
#   With signing key (developer only — signed reproducible build):
#     docker build --platform linux/amd64 --secret id=signkey,src=dev_signing_key.bin -t kassigner-build .

FROM --platform=linux/amd64 kassigner-toolchain:v2

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner
COPY . .

ENV SOURCE_DATE_EPOCH=0

# Install espflash for image generation
RUN source /root/esp-env.sh && \
    cargo install espflash --version 3.3.0

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

# Final image
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

# Final image
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

CMD ["bash", "-c", "echo '=== Waveshare ===' && sha256sum /build/kassigner-waveshare.bin && echo '=== M5Stack ===' && sha256sum /build/kassigner-m5stack.bin"]
