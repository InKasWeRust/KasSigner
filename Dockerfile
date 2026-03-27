FROM --platform=linux/amd64 kassigner-toolchain:v1

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner
COPY . .

ENV SOURCE_DATE_EPOCH=0

# Build Waveshare (default) — requires PSRAM octal mode
RUN source /root/esp-env.sh && \
    cd bootloader && \
    ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release

RUN source /root/esp-env.sh && \
    xtensa-esp32s3-elf-objcopy -O binary \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-waveshare.bin && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner Waveshare Build Complete" && \
    echo "============================================" && \
    echo "" && \
    sha256sum /build/kassigner-waveshare.bin && \
    echo "============================================"

# Build M5Stack
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release --no-default-features --features m5stack

RUN source /root/esp-env.sh && \
    xtensa-esp32s3-elf-objcopy -O binary \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-m5stack.bin && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner M5Stack Build Complete" && \
    echo "============================================" && \
    echo "" && \
    sha256sum /build/kassigner-m5stack.bin && \
    echo "============================================"

CMD ["bash", "-c", "echo '=== Waveshare ===' && sha256sum /build/kassigner-waveshare.bin && echo '=== M5Stack ===' && sha256sum /build/kassigner-m5stack.bin"]
