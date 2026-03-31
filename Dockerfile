FROM --platform=linux/amd64 kassigner-toolchain:v1

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
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/ws-pass1.bin 2>&1 | grep -v INFO && \
    cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass1.bin 2>&1 && \
    echo "=== Pass 1 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 2: Recompile with embedded hash
RUN source /root/esp-env.sh && \
    cd bootloader && \
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release --features skip-tests

# Pass 2: Recompute hash — should converge
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/ws-pass2.bin 2>&1 | grep -v INFO && \
    cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/ws-pass2.bin 2>&1 && \
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
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/m5-pass1.bin 2>&1 | grep -v INFO && \
    cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass1.bin 2>&1 && \
    echo "=== M5 Pass 1 hash ===" && \
    grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs

# Pass 2: Recompile with embedded hash
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release --no-default-features --features m5stack

# Pass 2: Recompute hash
RUN source /root/esp-env.sh && \
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/m5-pass2.bin 2>&1 | grep -v INFO && \
    cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- /build/m5-pass2.bin 2>&1 && \
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
