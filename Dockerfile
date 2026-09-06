# KasSigner — reproducible v2.0.0 release build
#
# The supported reproducible-build path is Docker-only. The convenience runner:
#   ./scripts/linux/build/reproducible-build.sh
# provisions the pinned toolchain image, performs this build, and exports the
# artifacts. No release build step flashes or contacts a hardware device.
#
# Manual toolchain image build:
#   docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v3 .
# Manual verifier export (unsigned images):
#   DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --target artifacts \
#     --output type=local,dest=release .
# Manual maintainer export (signed + unsigned images):
#   DOCKER_BUILDKIT=1 docker build --platform linux/amd64 --target artifacts \
#     --secret id=signkey,src=/path/to/dev_signing_key.bin \
#     --output type=local,dest=release .
#
# Six independently converged configurations produce twelve firmware images:
# signed/unsigned x app-only/full-flash x Waveshare/Waveshare-AF/M5Stack.
FROM --platform=linux/amd64 kassigner-toolchain:v3 AS builder

SHELL ["/bin/bash", "-c"]
WORKDIR /build/KasSigner

COPY Cargo.toml Cargo.lock ./
COPY apps/ apps/
COPY crates/ crates/
COPY external/ external/
COPY qa/ qa/
COPY tools/ tools/
ARG KASSIGNER_GIT_COMMIT=
ENV KASSIGNER_GIT_COMMIT=${KASSIGNER_GIT_COMMIT}
ENV SOURCE_DATE_EPOCH=0
ENV TZ=UTC
ENV LC_ALL=C
ENV LANG=C
ENV CARGO_INCREMENTAL=0

# Capture immutable source inputs before five-pass convergence intentionally
# rewrites apps/signer-firmware/src/firmware_hash.rs.
RUN find Cargo.toml Cargo.lock apps crates external qa tools \
        -type f \
        ! -path '*/target/*' \
        ! -path 'apps/signer-firmware/src/firmware_hash.rs' \
        -print0 \
    | sort -z \
    | xargs -0 sha256sum \
    > /build/SOURCE-SHA256SUMS

# Verify the browser companion using the pinned host Rust toolchain. Firmware
# release artifacts are produced below with the pinned ESP toolchain.
RUN source /etc/kassigner/toolchains.env && \
    rustup target list --toolchain "$KASSIGNER_REPRO_HOST_RUST" --installed | grep -qx wasm32-unknown-unknown && \
    cd apps/kassee-web && \
    cargo "+$KASSIGNER_REPRO_HOST_RUST" build --offline --locked --target wasm32-unknown-unknown --release

RUN source /etc/kassigner/toolchains.env && \
    cargo "+$KASSIGNER_REPRO_HOST_RUST" build --offline --locked --manifest-path tools/Cargo.toml --bin gen-hash --release

# converge.sh <label> <output-basename> <board> <signed:0|1> <cargo arguments...>
# Five build/hash passes are mandatory. Generated hash/signature bytes live in
# flash rodata rather than executable code, so passes two through five must all
# agree. One final build is then made from the converged firmware_hash.rs. Board-specific
# partition policy is applied to every image-generation pass and final image.
RUN cat > /usr/local/bin/converge.sh <<'SCRIPT' && chmod +x /usr/local/bin/converge.sh
#!/bin/bash
set -euo pipefail
LABEL="$1"; shift
OUT="$1"; shift
BOARD="$1"; shift
SIGNED="$1"; shift
source /etc/kassigner/toolchains.env
source /root/esp-env.sh
cd /build/KasSigner

python3 tools/build/firmware/board_layout.py check --board "${BOARD}"
mapfile -t BOARD_ESPFLASH_ARGS < <(
    python3 tools/build/firmware/board_layout.py espflash-args --board "${BOARD}"
)
FULL_FLASH_ARGS=("${BOARD_ESPFLASH_ARGS[@]}")
if [[ " ${FULL_FLASH_ARGS[*]} " != *" --flash-size "* ]]; then
    FULL_FLASH_ARGS+=(--flash-size 16mb)
fi

if [[ "${SIGNED}" == "1" ]]; then
    if [[ ! -f /run/secrets/signkey ]]; then
        echo "SKIPPED: ${LABEL} signed build — no signing key mounted"
        exit 0
    fi
    KEY_SIZE=$(stat -c '%s' /run/secrets/signkey)
    [[ "${KEY_SIZE}" == "32" ]] || {
        echo "BUILD FAILED: signing key must be exactly 32 bytes; got ${KEY_SIZE}"
        exit 1
    }
    KEY_ARGS=(/run/secrets/signkey)
    MODE=signed
else
    KEY_ARGS=()
    MODE=unsigned
fi

printf '\n%s\n' "${LABEL} (${MODE}) — five-pass convergence"
HASHES=()
for PASS in 1 2 3 4 5; do
    (cd apps/signer-firmware && cargo build --offline --locked --release "$@")
    PASS_IMAGE="/build/${OUT}-pass${PASS}.bin"
    espflash save-image --chip esp32s3 "${BOARD_ESPFLASH_ARGS[@]}" \
        apps/signer-firmware/target/xtensa-esp32s3-none-elf/release/kassigner-firmware \
        "${PASS_IMAGE}" 2>&1 | sed '/INFO/d'
    cargo "+$KASSIGNER_REPRO_HOST_RUST" run --offline --locked --manifest-path tools/Cargo.toml --bin gen-hash --release -- \
        "${PASS_IMAGE}" "${KEY_ARGS[@]}" >/dev/null
    HASH=$(tools/build/firmware/build_with_hash.sh --read-generated-hash \
        apps/signer-firmware/src/firmware_hash.rs) || {
        echo "BUILD FAILED: failed to read generated EXPECTED_FIRMWARE_HASH"
        exit 1
    }
    HASHES+=("${HASH}")
    echo "  pass ${PASS}: ${HASH}"
done

if [[ "${HASHES[1]}" != "${HASHES[2]}" || "${HASHES[2]}" != "${HASHES[3]}" || "${HASHES[3]}" != "${HASHES[4]}" ]]; then
    echo "BUILD FAILED: ${LABEL} ${MODE} did not converge on passes 2 through 5"
    exit 1
fi

(cd apps/signer-firmware && cargo build --offline --locked --release "$@")
ELF=apps/signer-firmware/target/xtensa-esp32s3-none-elf/release/kassigner-firmware
espflash save-image --chip esp32s3 "${BOARD_ESPFLASH_ARGS[@]}" "${ELF}" "/build/${OUT}.bin" 2>&1 | sed '/INFO/d'
python3 tools/build/firmware/verify_image_hash.py \
    "/build/${OUT}.bin" apps/signer-firmware/src/firmware_hash.rs
espflash save-image --chip esp32s3 --merge "${FULL_FLASH_ARGS[@]}" "${ELF}" \
    "/build/${OUT}-full.bin" 2>&1 | sed '/INFO/d'
printf '%s\n' "${HASHES[4]}" > "/build/${OUT}.codehash"
rm -f "/build/${OUT}-pass"*.bin
echo "  CONVERGED: ${HASHES[4]}"
SCRIPT

# Unsigned builds come first so any verifier can reproduce the complete public
# comparison set without possessing the private release signing key. Production
# images execute boot-time known-answer tests; skip-tests is prohibited.
RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare" "kassigner-waveshare-unsigned" waveshare 0 \
        --no-default-features --features waveshare,production
RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare AF" "kassigner-waveshare-af-unsigned" waveshare-af 0 \
        --no-default-features --features waveshare,production,ov5640-af
RUN --mount=type=secret,id=signkey,required=false \
    converge.sh "M5Stack" "kassigner-m5stack-unsigned" m5stack 0 \
        --no-default-features --features m5stack,production

RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare" "kassigner-waveshare" waveshare 1 \
        --no-default-features --features waveshare,production
RUN --mount=type=secret,id=signkey,required=false \
    ESP_HAL_CONFIG_PSRAM_MODE=octal \
    converge.sh "Waveshare AF" "kassigner-waveshare-af" waveshare-af 1 \
        --no-default-features --features waveshare,production,ov5640-af
RUN --mount=type=secret,id=signkey,required=false \
    converge.sh "M5Stack" "kassigner-m5stack" m5stack 1 \
        --no-default-features --features m5stack,production

# Canonical signed KSFU v3 update manifests bind the complete release identity,
# not just the app hash. They are emitted only when the offline Schnorr release
# key is mounted, matching the signed firmware artifact set above.
RUN --mount=type=secret,id=signkey,required=false \
    set -euo pipefail; \
    if [[ -f /run/secrets/signkey ]]; then \
      source /etc/kassigner/toolchains.env; \
      source apps/signer-firmware/release-policy.env; \
      cargo "+$KASSIGNER_REPRO_HOST_RUST" run --offline --locked --manifest-path tools/Cargo.toml --bin gen-update-manifest --release -- \
        /build/kassigner-waveshare.bin /run/secrets/signkey waveshare 2.0.0 "$KASSIGNER_UPDATE_SEQUENCE" "$KASSIGNER_SECURITY_VERSION" none /build/kassigner-waveshare-update.ksfu; \
      cargo "+$KASSIGNER_REPRO_HOST_RUST" run --offline --locked --manifest-path tools/Cargo.toml --bin gen-update-manifest --release -- \
        /build/kassigner-waveshare-af.bin /run/secrets/signkey waveshare-af 2.0.0 "$KASSIGNER_UPDATE_SEQUENCE" "$KASSIGNER_SECURITY_VERSION" none /build/kassigner-waveshare-af-update.ksfu; \
    fi

# Assemble every release artifact and provenance manifest inside Docker. The
# host-side runner only asks BuildKit to export this directory; it does not
# compile firmware, calculate release hashes, or synthesize manifests itself.
RUN set -euo pipefail; \
    mkdir -p /release; \
    cp /build/kassigner-*.bin /release/; \
    cp /build/kassigner-*.codehash /release/; \
    find /build -maxdepth 1 -type f -name 'kassigner-*-update.ksfu' -exec cp {} /release/ \; ; \
    cp apps/signer-firmware/partitions/m5stack-cores3.csv /release/kassigner-m5stack-partitions.csv; \
    cp /build/SOURCE-SHA256SUMS /release/SOURCE-SHA256SUMS; \
    cp /opt/kassigner/input/BUILD-INPUT-SHA256SUMS /release/BUILD-INPUT-SHA256SUMS; \
    cp /opt/kassigner/input/BUILD-INPUT-MANIFEST.json /release/BUILD-INPUT-MANIFEST.json; \
    cd /release; \
    find . -maxdepth 1 -type f \( -name '*.bin' -o -name '*.codehash' -o -name '*.csv' -o -name '*.ksfu' \) \
        -printf '%f\n' \
        | sort \
        | xargs sha256sum \
        > SHA256SUMS; \
    source /etc/kassigner/toolchains.env; \
    HOST_RUST="$(rustc +"$KASSIGNER_REPRO_HOST_RUST" --version)"; \
    ESP_RUST="$(source /root/esp-env.sh && rustc --version)"; \
    ESPFLASH_VERSION="$(source /root/esp-env.sh && espflash --version | head -1)"; \
    [[ "$ESPFLASH_VERSION" == *"$KASSIGNER_ESPFLASH_VERSION"* ]] || { echo "BUILD FAILED: espflash version drift: $ESPFLASH_VERSION"; exit 1; }; \
    BUILD_COMMIT="${KASSIGNER_GIT_COMMIT:-source-archive}"; \
    M5_PARTITION_SHA="$(sha256sum kassigner-m5stack-partitions.csv | awk '{print $1}')"; \
    SIGNED_IMAGES="$(find . -maxdepth 1 -type f -name 'kassigner-*.bin' ! -name '*-unsigned*' | wc -l | tr -d '[:space:]')"; \
    printf '%s\n' \
        'KasSigner reproducible firmware build' \
        'format-version=2' \
        'builder=docker' \
        'platform=linux/amd64' \
        'toolchain-image=kassigner-toolchain:v3' \
        "source-date-epoch=${SOURCE_DATE_EPOCH}" \
        "build-commit=${BUILD_COMMIT}" \
        "host-rust=${HOST_RUST}" \
        "esp-rust=${ESP_RUST}" \
        "espflash=${ESPFLASH_VERSION}" \
        "espflash-policy=${KASSIGNER_ESPFLASH_VERSION}" \
        'unsigned-images=6' \
        "signed-images=${SIGNED_IMAGES}" \
        'firmware-targets=waveshare,waveshare-af,m5stack' \
        'release-modes=app-only,full-flash' \
        'hash-convergence=5-pass;passes-2-through-5-must-match;identity-bytes=flash-rodata-static' \
        'final-codehash-verification=required;address+length+sha256' \
        'm5stack-partition-table=kassigner-m5stack-partitions.csv' \
        'm5stack-update-manifest=not-emitted-by-normal-release;secure-provisioning-is-separate' \
        "m5stack-partition-table-sha256=${M5_PARTITION_SHA}" \
        'm5stack-ota-apps=ota_0:0x10000+0x200000,ota_1:0x210000+0x200000' \
        'm5stack-persistent-state=offset:0xFFC000,size:0x4000' \
        'hardware-flashing=never' \
        > BUILD-MANIFEST.txt; \
    printf '{\n  "artifacts": [\n' > ARTIFACT-MANIFEST.json; \
    FIRST=1; \
    while IFS= read -r FILE; do \
        HASH="$(sha256sum "$FILE" | awk '{print $1}')"; \
        SIZE="$(stat -c '%s' "$FILE")"; \
        if [[ "$FIRST" == "0" ]]; then printf ',\n' >> ARTIFACT-MANIFEST.json; fi; \
        printf '    {"file":"%s","sha256":"%s","size":%s}' "$FILE" "$HASH" "$SIZE" >> ARTIFACT-MANIFEST.json; \
        FIRST=0; \
    done < <(find . -maxdepth 1 -type f \( -name '*.bin' -o -name '*.codehash' -o -name '*.csv' -o -name '*.ksfu' \) -printf '%f\n' | sort); \
    printf '\n  ],\n  "format_version": 1\n}\n' >> ARTIFACT-MANIFEST.json; \
    sha256sum ARTIFACT-MANIFEST.json BUILD-MANIFEST.txt SOURCE-SHA256SUMS \
        BUILD-INPUT-SHA256SUMS BUILD-INPUT-MANIFEST.json \
        > MANIFEST-SHA256SUMS

# BuildKit exports this stage directly to the caller-selected host directory.
# It contains only Docker-produced release artifacts and deterministic manifests.
FROM scratch AS artifacts
COPY --from=builder /release/ /

# Preserve the historical inspectable image target for maintainers who build
# Dockerfile manually without --target artifacts.
FROM builder AS image
CMD bash -c '\
    echo "KasSigner reproducible build outputs"; \
    echo "-- code-segment hashes --"; \
    for f in /release/*.codehash; do printf "%-42s %s\n" "$(basename "$f")" "$(cat "$f")"; done; \
    echo "-- image SHA-256 hashes --"; \
    cat /release/SHA256SUMS'
