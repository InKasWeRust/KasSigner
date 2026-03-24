FROM --platform=linux/amd64 kassigner-toolchain:v1

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner
COPY . .

ENV SOURCE_DATE_EPOCH=0
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release

RUN source /root/esp-env.sh && \
    xtensa-esp32s3-elf-objcopy -O binary \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-raw.bin && \
    echo "" && \
    echo "============================================" && \
    echo "  KasSigner Reproducible Build Complete" && \
    echo "============================================" && \
    echo "" && \
    sha256sum /build/kassigner-raw.bin && \
    echo "============================================"

CMD ["bash", "-c", "sha256sum /build/kassigner-raw.bin"]
