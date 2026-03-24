FROM ubuntu:24.04

# ============================================================
# KasSigner — Reproducible Build Environment
# ============================================================
# This container produces byte-identical firmware binaries
# from the public source code. Anyone can verify that the
# released signed binary matches what this source builds.
#
# Usage:
#   docker build -t kassigner-build .
#   docker run --rm kassigner-build
#
# The output is the SHA-256 hash of the unsigned firmware.
# Compare it with the hash published in the release notes.
# If they match, the binary provably comes from this source.
# ============================================================

# Prevent interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ---- Pinned versions (DO NOT change without re-verifying reproducibility) ----
ENV ESPUP_VERSION=0.16.0
ENV ESPTOOL_VERSION=5.2.0
ENV ESPFLASH_VERSION=4.1.0

# ---- System dependencies ----
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    gcc \
    g++ \
    pkg-config \
    libssl-dev \
    libusb-1.0-0-dev \
    libudev-dev \
    python3 \
    python3-pip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- Install espup (pinned version) ----
RUN curl -L "https://github.com/esp-rs/espup/releases/download/v${ESPUP_VERSION}/espup-x86_64-unknown-linux-gnu" \
    -o /usr/local/bin/espup \
    && chmod +x /usr/local/bin/espup

# ---- Install Xtensa Rust toolchain via espup ----
# This installs the exact Rust fork (1.92.0.0) + Xtensa LLVM
ENV HOME=/root
RUN espup install --export-file /root/esp-env.sh

# ---- Source the ESP environment for all subsequent commands ----
ENV PATH="/root/.rustup/toolchains/esp/bin:${PATH}"
ENV LIBCLANG_PATH="/root/.rustup/toolchains/esp/lib"
SHELL ["/bin/bash", "-c"]

# ---- Install espflash (pinned version) ----
RUN source /root/esp-env.sh && \
    cargo install espflash@${ESPFLASH_VERSION}

# ---- Install esptool (pinned version) ----
RUN pip3 install --break-system-packages esptool==${ESPTOOL_VERSION}

# ---- Copy project source ----
WORKDIR /build/KasSigner
COPY . .

# ---- Build firmware ----
RUN source /root/esp-env.sh && \
    cd bootloader && \
    cargo build --release 2>&1 | tail -5

# ---- Output verification hash ----
# This hash must match the one published with the release.
# The signed binary adds a signature sector but the unsigned
# content before signing must be identical.
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

# Default command: print the hash
CMD ["bash", "-c", "sha256sum /build/KasSigner/bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader"]
