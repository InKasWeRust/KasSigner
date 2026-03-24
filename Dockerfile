FROM --platform=linux/amd64 kassigner-toolchain:v1

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner
COPY . .

ENV SOURCE_DATE_EPOCH=0
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release 2>&1 && \
    echo "=== FIND ALL BINARIES ===" && \
    find /build/KasSigner/bootloader/target -maxdepth 4 -type f -perm -111 ! -name "*.so" ! -name "build*" | head -20 && \
    echo "=== FIND kassigner ===" && \
    find /build/KasSigner/bootloader/target -name "kassigner*" -type f ! -name "*.d" ! -name "*.json" 2>/dev/null && \
    echo "=== LS XTENSA RELEASE ===" && \
    ls -la /build/KasSigner/bootloader/target/xtensa-esp32s3-none-elf/release/ 2>/dev/null || echo "No xtensa release dir"

CMD ["bash", "-c", "echo done"]
