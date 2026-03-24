# ============================================================
# KasSigner — Reproducible Build
# ============================================================
# Uses the frozen toolchain base image. The base image never
# changes, so the same source always produces the same binary.
#
# First time setup (once):
#   docker build -f Dockerfile.base -t kassigner-toolchain:v1 .
#
# Verify a build (anytime):
#   docker build -t kassigner-build .
#   docker run --rm kassigner-build
#
# Compare the SHA-256 hash with the published release hash.
# ============================================================

FROM kassigner-toolchain:v1

SHELL ["/bin/bash", "-c"]

# ---- Copy project source ----
WORKDIR /build/KasSigner
COPY . .

# ---- Build firmware (release mode) ----
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release 2>&1 | tail -5

# ---- Output verification hash ----
RUN echo "" && \
    echo "============================================" && \
    echo "  KasSigner Reproducible Build Complete" && \
    echo "============================================" && \
    echo "" && \
    sha256sum bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader && \
    echo "" && \
    echo "Compare this hash with the published release hash." && \
    echo "If they match, the binary is built from this source." && \
    echo "============================================"

CMD ["bash", "-c", "sha256sum /build/KasSigner/bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"]
