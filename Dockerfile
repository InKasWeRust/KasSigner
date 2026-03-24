# ============================================================
# KasSigner — Reproducible Build (x86_64 canonical)
# ============================================================
# Anyone, anywhere, any OS → same hash.
#
#   docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v1 .
#   docker build --platform linux/amd64 -t kassigner-build .
#   docker run --rm kassigner-build
# ============================================================

FROM --platform=linux/amd64 kassigner-toolchain:v1

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner
COPY . .

ENV SOURCE_DATE_EPOCH=0
RUN source /root/esp-env.sh && \
    cd bootloader && \
    CARGO_BUILD_RUSTFLAGS="-Csymbol-mangling-version=v0" \
    cargo build --release 2>&1 | tail -5

RUN source /root/esp-env.sh && \
    xtensa-esp32s3-elf-objcopy -O binary \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        /build/kassigner-raw.bin

RUN echo "" && \
    echo "============================================" && \
    echo "  KasSigner Reproducible Build Complete" && \
    echo "============================================" && \
    echo "" && \
    sha256sum /build/kassigner-raw.bin && \
    echo "============================================"

CMD ["bash", "-c", "sha256sum /build/kassigner-raw.bin"]
