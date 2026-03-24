FROM ubuntu:24.04

# ============================================================
# KasSigner — Reproducible Build Environment
# ============================================================
# Usage:
#   docker build -t kassigner-build .
#   docker run --rm kassigner-build
#
# Compare the output SHA-256 hash with the published release hash.
# If they match, the binary provably comes from this source.
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive

# ---- Pinned versions ----
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

# ---- Install rustup first (espup requires it) ----
ENV HOME=/root
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# ---- Detect architecture and install espup (pinned version) ----
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        ESPUP_ARCH="x86_64-unknown-linux-gnu"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        ESPUP_ARCH="aarch64-unknown-linux-gnu"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -L "https://github.com/esp-rs/espup/releases/download/v${ESPUP_VERSION}/espup-${ESPUP_ARCH}" \
        -o /usr/local/bin/espup && \
    chmod +x /usr/local/bin/espup

# ---- Install Xtensa Rust toolchain via espup ----
RUN espup install --export-file /root/esp-env.sh

# ---- Source the ESP environment for all subsequent commands ----
SHELL ["/bin/bash", "-c"]
ENV PATH="/root/.rustup/toolchains/esp/bin:${PATH}"

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
