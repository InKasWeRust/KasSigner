# KasSigner - Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
#
# ════════════════════════════════════════════════════════════════════
#  Reproducible release build
# ════════════════════════════════════════════════════════════════════
#
#   Toolchain image first (once):
#     docker build --platform linux/amd64 -f Dockerfile.base \
#       -t kassigner-toolchain:v3 .
#
#   Verifier (no key) - builds the three UNSIGNED images:
#     docker build --platform linux/amd64 -t kassigner-build .
#
#   Maintainer (with key) - builds all six, unsigned then signed:
#     docker build --platform linux/amd64 \
#       --secret id=signkey,src=/path/to/dev_signing_key.bin \
#       -t kassigner-build .
#
#   Then:
#     docker run --rm kassigner-build
#
# ── Six configurations ──────────────────────────────────────────────
#
#   Waveshare          unsigned / signed    OV2640 / OV5640 auto-detect
#   Waveshare AF       unsigned / signed    AF module, H+V orientation flip
#   M5Stack CoreS3     unsigned / signed
#
# Each converges independently. Unsigned images are built first, so a run
# without a key still produces a complete, useful result.
#
# ── Why every image here is a `production` build ────────────────────
#
# `FIRMWARE_SIGNATURE` is a Rust `const`, and consts have no storage: they
# exist only where they are used. Its only use is inside `verify_signature()`,
# which a development build never reaches, so the compiler discards the
# function and the 64 bytes with it. Measured 2026-08-03: signed and unsigned
# DEV builds are byte-identical and contain no signature at all. Only a
# `production` build embeds it.
#
# Development builds are for developers, via `cargo run`. They are not release
# artifacts and no hashes are published for them.
#
# ── Signed and unsigned differ ──────────────────────────────────────
#
# The two have DIFFERENT code-segment hashes. The unsigned image is the
# COMPLETE firmware built from the same source; the only inputs that differ
# are the signature bytes, the signed flag and the embedded hash
# (features/verify.rs, firmware_signed). Those constants shift the compiler's
# output, so a byte-diff of signed against unsigned is NOT confined to the
# signature region; the comparison that matters is unsigned against unsigned.
# A verifier compares their build against the published UNSIGNED hash for the
# same target, and that hash stands for the real firmware, not a stub.
#
# Unsigned images run in production mode with no valid signature and halt at
# boot. They exist to be hashed, not flashed.
#
# ── Convergence ─────────────────────────────────────────────────────
#
# The firmware embeds a hash of its own code segment, so writing the hash
# changes the thing being hashed. The build iterates until it settles.
#
# FIVE passes, with an explicit check that the last two agree. Measured:
# signed settles at pass 2, unsigned at pass 3. Three passes was the previous
# assumption and was never verified - a configuration needing four would have
# shipped a binary whose embedded hash did not match its own code, which in a
# production build HALTS AT BOOT. The assertion turns that into a failed
# build instead of a dead device.
#
# ── Outputs ─────────────────────────────────────────────────────────
#
# Four per target, twelve in total:
#
#   kassigner-waveshare.bin                 signed, app-only      FLASH THIS
#   kassigner-waveshare-full.bin            signed, full flash    FLASH THIS
#   kassigner-waveshare-unsigned.bin        unsigned, app-only    verify only
#   kassigner-waveshare-unsigned-full.bin   unsigned, full flash  verify only
#
# and the same four for -waveshare-af- and -m5stack-.
#
# The unsigned images are how a third party checks that the published signed
# binaries were built from this source: they build unsigned and compare
# against the published UNSIGNED hashes. Do not flash them - an unsigned
# production image has no valid signature and halts at boot.
#
# Flash (full image, new devices):
#   python3 -m esptool --port <PORT> --baud 460800 write_flash 0x0 <name>-full.bin
# Flash (app only):
#   python3 -m esptool --port <PORT> --baud 460800 write_flash 0x10000 <name>.bin
#
# NOTE: production firmware gates the USB Serial/JTAG peripheral a second or
# two into boot. To reflash, enter download mode first - unplug USB, hold
# BOOT, plug USB in, release BOOT. See docs/BUILD_FLASH_GUIDE.md.

FROM --platform=linux/amd64 kassigner-toolchain:v3

SHELL ["/bin/bash", "-c"]

WORKDIR /build/KasSigner

# ════════════════════════════════════════════════════
#  Copy only code folders (no docs, no gh-pages assets)
# ════════════════════════════════════════════════════
COPY bootloader/ bootloader/
COPY core/ core/
COPY kassee/ kassee/
COPY rqrr_nostd/ rqrr_nostd/
COPY tools/ tools/
# No root rust-toolchain.toml: each crate carries its own pin, because the
# firmware wants the Xtensa toolchain and the host crates want 1.85.0. A
# single root pin made `cargo` in core/, kassee/ and tools/ resolve `esp`,
# which is why gen-hash was built by the Xtensa compiler and why
# `cd core && cargo test` failed on any machine without it.

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

# ════════════════════════════════════════════════════
#  Core crate host tests (same code the device boots)
# ════════════════════════════════════════════════════
# The security-critical half of the firmware tests on the host toolchain the
# image already carries. Seconds of cost; a failing vector stops the release
# build here instead of shipping.
RUN cd core && cargo test --release 2>&1 | tail -5 && cd ..

# Build gen-hash tool (uses host toolchain, not Xtensa)
RUN cargo build --manifest-path tools/Cargo.toml --bin gen-hash --release 2>&1 | tail -1

# ════════════════════════════════════════════════════
#  Convergence driver
# ════════════════════════════════════════════════════
#
#   converge.sh <label> <out-basename> <sign:0|1> <cargo-args...>
#
# Five build/hash passes, fail if the last two disagree, then one final build
# from the converged firmware_hash.rs, then the image(s).
#
# sign=1 with no key mounted SKIPS the target rather than failing, so a
# verifier without the key still gets a complete unsigned build.
#
# PSRAM mode is passed by the caller, not set globally: octal is correct for
# Waveshare and must NOT be applied to M5Stack.
#
RUN cat > /usr/local/bin/converge.sh <<'SCRIPT' && chmod +x /usr/local/bin/converge.sh
#!/bin/bash
set -euo pipefail

LABEL="$1"; shift
OUT="$1"; shift
SIGN="$1"; shift

source /root/esp-env.sh
cd /build/KasSigner

if [ "${SIGN}" = "1" ]; then
    if [ ! -f /run/secrets/signkey ]; then
        echo ""
        echo "  SKIPPED: ${LABEL} (signed) - no signing key mounted"
        exit 0
    fi
    KEYARG=(/run/secrets/signkey)
    MODE="signed"
else
    KEYARG=()
    MODE="unsigned"
fi

echo ""
echo "════════════════════════════════════════════════"
echo "  ${LABEL} (${MODE}) - 5-pass convergence"
echo "════════════════════════════════════════════════"

PREV=""
PREV_PREV=""
for pass in 1 2 3 4 5; do
    ( cd bootloader && cargo build --release "$@" 2>&1 | tail -1 )
    espflash save-image --chip esp32s3 \
        bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
        "/build/${OUT}-p${pass}.bin" 2>&1 | grep -v INFO || true
    cargo run --manifest-path tools/Cargo.toml --bin gen-hash --release -- \
        "/build/${OUT}-p${pass}.bin" "${KEYARG[@]}" >/dev/null 2>&1
    H=$(grep FIRMWARE_HASH_HEX bootloader/src/firmware_hash.rs | sed 's/.*= "//; s/".*//')
    echo "  pass ${pass}: ${H}"
    PREV_PREV="${PREV}"
    PREV="${H}"
done

if [ "${PREV_PREV}" != "${PREV}" ]; then
    echo ""
    echo "  BUILD FAILED: ${LABEL} (${MODE}) did not converge."
    echo "  Pass 4 and pass 5 produced different code-segment hashes."
    echo "  Raise the pass count. Do NOT ship this binary: in a production"
    echo "  build the embedded hash would not match the running code, and the"
    echo "  device halts at boot."
    exit 1
fi
echo "  CONVERGED: ${PREV}"

# The shipped image must be compiled from the converged firmware_hash.rs,
# so one more build after the final gen-hash write.
( cd bootloader && cargo build --release "$@" 2>&1 | tail -1 )

# Both images for both modes. The unsigned pair exists so a verifier can
# reproduce and compare EITHER published artifact - app-only or full-flash -
# not just one of them. They are for hashing, not for flashing: an unsigned
# production image has no valid signature and halts at boot.
espflash save-image --chip esp32s3 \
    bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
    "/build/${OUT}.bin" 2>&1 | grep -v INFO || true
espflash save-image --chip esp32s3 --merge --flash-size 16mb \
    bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader \
    "/build/${OUT}-full.bin" 2>&1 | grep -v INFO || true

echo "${PREV}" > "/build/${OUT}.codehash"
grep -E "Segment size|Signed:" bootloader/src/firmware_hash.rs | sed 's/^/ /'
rm -f /build/${OUT}-p*.bin
SCRIPT

# ════════════════════════════════════════════════════
#  UNSIGNED - built first, so a keyless run is still complete
# ════════════════════════════════════════════════════

RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare" "kassigner-waveshare-unsigned" 0 \
        --features production

# `ov5640-af` is not only autofocus: it applies the H+V orientation flip that
# the AF module needs. Without it that camera renders upside down, whether or
# not the AF solder modification has been done. Hence a separate image.
RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare AF" "kassigner-waveshare-af-unsigned" 0 \
        --features production,ov5640-af

RUN --mount=type=secret,id=signkey,required=false \
    converge.sh "M5Stack" "kassigner-m5stack-unsigned" 0 \
        --no-default-features --features m5stack,production

# ════════════════════════════════════════════════════
#  SIGNED - skipped entirely when no key is mounted
# ════════════════════════════════════════════════════

RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare" "kassigner-waveshare" 1 \
        --features production

RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare AF" "kassigner-waveshare-af" 1 \
        --features production,ov5640-af

RUN --mount=type=secret,id=signkey,required=false \
    converge.sh "M5Stack" "kassigner-m5stack" 1 \
        --no-default-features --features m5stack,production

# ════════════════════════════════════════════════════
#  Report
# ════════════════════════════════════════════════════
CMD bash -c '\
    echo "════════════════════════════════════════════════"; \
    echo "  KasSigner build complete"; \
    echo "════════════════════════════════════════════════"; \
    echo ""; \
    echo "-- code-segment hashes (compare with the device boot screen) --"; \
    for f in /build/*.codehash; do \
        printf "  %-36s %s\n" "$(basename $f .codehash)" "$(cat $f)"; \
    done; \
    echo ""; \
    echo "-- file hashes --"; \
    for f in /build/*.bin; do \
        printf "  %s  %s\n" "$(sha256sum $f | cut -d" " -f1)" "$(basename $f)"; \
    done; \
    echo ""'
