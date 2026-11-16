# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0-or-later
#
# ════════════════════════════════════════════════════════════════════════
#  The release build
# ════════════════════════════════════════════════════════════════════════
#
# From the repository root:
#
#   docker build --platform linux/amd64 -f release/Dockerfile \
#     --output type=local,dest=release-out .
#
# `release-out/` then holds the release's files, `SHA256SUMS`, the hash
# list, and `SIGN.TXT`, the line that gets signed. The same source gives the
# same bytes, whoever builds it, wherever and whenever.
#
#   kassigner-<version>-<board>.bin
#                               the app image, at 0x10000; its SHA-256 is
#                               what the verification screen shows
#   kassigner-<version>-<board>-full.bin
#                               plain bootloader, partition table and app,
#                               for an unprovisioned unit
#   kassigner-<version>-esp32s3-secure-bootloader.bin
#                               the S3's Secure Boot bootloader, unsigned,
#                               for each owner to sign with their own key
#                               and provision with; at 0x0
#   kassigner-<version>-esp32p4-secure-bootloader.bin
#                               the P4's, likewise; at 0x2000
#   kassigner-<version>-partition-table.bin
#                               `release/partitions.csv`, at 0x8000
#   kassigner-<version>-partition-table-p4-secure.bin
#                               `release/partitions-p4-secure.csv`, at 0xC000
#                               on a P4 with the Secure Boot bootloader,
#                               which reaches past 0x8000
#   COPYING                     the firmware's license, GPL-3.0 or later
#   THIRD_PARTY_NOTICES         the licenses of the third-party software
#                               in the images above, as each one requires
#                               them to travel with it
#   kassigner-sdk-<version>-web.tar.gz
#                               the SDK's browser package, full (`pkg/`)
#                               and watch-only (`pkg-watch/`), each with
#                               its own license (MPL-2.0) and notices
#   kassigner-sdk-<version>-bindings.tar.gz
#                               the SDK's Swift, Kotlin and Python
#                               bindings, with their license and notices;
#                               the library they call is built per target
#                               from this source (`release/sdk.sh`)
#   SHA256SUMS                  the SHA-256 of every file above
#   SIGN.TXT                    `KasSigner v<version> SHA256SUMS <hash>`,
#                               the hash being `SHA256SUMS`'s own, with no
#                               line break at the end: the text a unit's
#                               Sign Message signs with the release address
#                               (it refuses a text ending in a line break).
#                               Not in `SHA256SUMS`, since it carries that
#                               list's hash. The unit's signed copy is
#                               published as `KasSg<digits>.txt`, the
#                               version's digits without its dots
#
# for <board> in m5stack, waveshare, p4, and <version> the root
# `Cargo.toml`'s (`release/version.sh`), so two releases' files never share
# a name. No key of any kind enters this build or is needed to reproduce it.
#
# The SDK's two archives are built beside the firmware and not from it: the
# firmware's stages do not read them, so their being here changes no other line
# of `SHA256SUMS`. One signature covers both.
#
# ── Pinned ──────────────────────────────────────────────────────────────
#
# Every input is fixed by content: base images by digest, downloads by
# SHA-256, system packages by exact version from an archive snapshot,
# crates by `Cargo.lock`. A file republished under the same name fails the
# build. `--platform linux/amd64` is required on every host, an ARM Mac
# included, so the output does not depend on the machine.
#
# ── Checking the build ──────────────────────────────────────────────────
#
# Build it twice from nothing and compare:
#
#   docker builder prune -af
#   docker build --no-cache --platform linux/amd64 -f release/Dockerfile \
#     --output type=local,dest=release-out-2 .
#   diff release-out/SHA256SUMS release-out-2/SHA256SUMS
#
# Any difference means an input is not pinned; do not use the files until it
# is found.

# The app descriptor's build date (`esp-bootloader-esp-idf` reads it), fixed
# so builds do not differ by time.
ARG SOURCE_DATE_EPOCH=0

# ════════════════════════════════════════════════════════════════════════
#  The firmware's toolchain
# ════════════════════════════════════════════════════════════════════════

# Ubuntu 24.04 by content digest: `ubuntu:24.04` is republished under the
# same name.
FROM --platform=linux/amd64 ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS toolchain

ENV DEBIAN_FRONTEND=noninteractive HOME=/root
SHELL ["/bin/sh", "-eu", "-c"]

# System packages from snapshot.ubuntu.com: Ubuntu's archive as it stood at
# the instant `APT_SNAPSHOT` names, where no superseded version is dropped.
# A version pinned below that the snapshot does not serve fails the build.
#
# The base image has no CA store until ca-certificates is installed, so for
# this step only TLS peer checking for the snapshot host is off. So is apt's
# Valid-Until check: a snapshot's Release files are never refreshed, so any
# expiry date in them has passed. Integrity rests on apt's checks of the
# archive's GPG signature and of every package against the signed hashes.
#
# The snapshot host refuses a request now and then (500, 503), so a failed
# download is tried again, up to five times, before the build gives up. What
# is installed does not change: the same versions, checked the same way.
#
#   ca-certificates, curl  the downloads below
#   gcc, libc6-dev         host build scripts and proc-macros link with
#                          them; `gcc` only recommends the C library's
#                          files, and recommends are not installed
#   xz-utils, unzip        the toolchain archives and espflash
#   patch                  the P4's esp-hal fork (fork.sh)
ARG APT_SNAPSHOT=20261024T090000Z
RUN sed -i "s#http://archive.ubuntu.com/ubuntu/#http://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}/#g; s#http://security.ubuntu.com/ubuntu/#http://snapshot.ubuntu.com/ubuntu/${APT_SNAPSHOT}/#g" \
        /etc/apt/sources.list.d/ubuntu.sources \
    && grep -q snapshot.ubuntu.com /etc/apt/sources.list.d/ubuntu.sources \
    && printf 'Acquire::https::snapshot.ubuntu.com::Verify-Peer "false";\nAcquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' \
        > /etc/apt/apt.conf.d/99-snapshot-bootstrap \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20260816ubuntu0.24.04.1 \
        curl=8.5.0-2ubuntu10.16 \
        gcc=4:13.2.0-7ubuntu1 \
        libc6-dev=2.39-0ubuntu8.9 \
        patch=2.7.6-7build3 \
        unzip=6.0-28ubuntu4.1 \
        xz-utils=5.6.1+really5.4.5-1ubuntu0.4 \
    && rm -f /etc/apt/apt.conf.d/99-snapshot-bootstrap \
    && rm -rf /var/lib/apt/lists/*

# Each download, by its SHA-256.
WORKDIR /tmp/dl
RUN fetch() { curl -sSfL -o "$2" "$1" && echo "$3  $2" | sha256sum -c -; } \
    # esp-rs's Rust 1.95.0.0 with the Xtensa targets, and its source for
    # `-Z build-std`, fetched from the release rather than through espup,
    # which asks GitHub's API what to fetch. It also builds and links
    # (rust-lld) the P4's RISC-V firmware.
    && fetch https://github.com/esp-rs/rust-build/releases/download/v1.95.0.0/rust-1.95.0.0-x86_64-unknown-linux-gnu.tar.xz \
        rust.tar.xz aad2fb24baeab6ad61c41f002f136fe0b416ef39a501d29750ab66c18a699433 \
    && fetch https://github.com/esp-rs/rust-build/releases/download/v1.95.0.0/rust-src-1.95.0.0.tar.xz \
        rust-src.tar.xz 708bee337ac2d41c0e861af93047bffec91a052fbcb4957925d840a41f327717 \
    # GCC for the S3: the linker the Xtensa targets name.
    && fetch https://github.com/espressif/crosstool-NG/releases/download/esp-14.2.0_20241119/xtensa-esp-elf-14.2.0_20241119-x86_64-linux-gnu.tar.xz \
        gcc.tar.xz e3e6dcf3d275c3c9ab0e4c8a9d93fd10e7efc035d435460576c9d95b4140c676 \
    # espflash 4.6.0: the images, and the plain bootloader in the full ones,
    # which comes with this version.
    && fetch https://github.com/esp-rs/espflash/releases/download/v4.6.0/espflash-x86_64-unknown-linux-gnu.zip \
        espflash.zip c4fcfa32ddc3155608f003a230e6f3c184eff9641ec9cfa8eb54f1b515d403e7 \
    && tar xf rust.tar.xz \
    && tar xf rust-src.tar.xz \
    && ./rust-nightly-x86_64-unknown-linux-gnu/install.sh --destdir=/opt/esp --prefix= \
        --components=rustc,rust-std-x86_64-unknown-linux-gnu,cargo >/dev/null \
    && ./rust-src-nightly/install.sh --destdir=/opt/esp --prefix= >/dev/null \
    && tar xf gcc.tar.xz -C /opt \
    && unzip -q espflash.zip -d /usr/local/bin \
    && cd / && rm -rf /tmp/dl

ENV PATH=/opt/esp/bin:/opt/xtensa-esp-elf/bin:/usr/local/bin:/usr/bin:/bin \
    CARGO_HOME=/opt/cargo
RUN rustc --version && cargo --version && espflash --version

# ════════════════════════════════════════════════════════════════════════
#  The firmware
# ════════════════════════════════════════════════════════════════════════

FROM toolchain AS firmware
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# A fixed folder: Rust writes source paths into panic messages, so the
# folder is part of the bytes.
WORKDIR /build/kassigner
COPY . .
RUN sh release/build.sh /out

# ════════════════════════════════════════════════════════════════════════
#  The SDK's toolchain
# ════════════════════════════════════════════════════════════════════════

# The SDK is built with the Rust project's own Rust 1.95.0, the compiler CI
# tests it with, not esp-rs's, which this stage's path leaves out. Each
# download by its SHA-256, as above.
FROM toolchain AS sdk-toolchain
WORKDIR /tmp/dl
RUN fetch() { curl -sSfL -o "$2" "$1" && echo "$3  $2" | sha256sum -c -; } \
    # Rust 1.95.0 for this machine, and its standard library for the
    # browser's target.
    && fetch https://static.rust-lang.org/dist/rust-1.95.0-x86_64-unknown-linux-gnu.tar.xz \
        rust.tar.xz 2e0338f18ecbaa4a0f631b9e80e8b8e26bb6fe77dd5454fba8a70cf96c1e84a1 \
    && fetch https://static.rust-lang.org/dist/rust-std-1.95.0-wasm32-unknown-unknown.tar.xz \
        rust-std-wasm32.tar.xz 5587b89ff69623d09e476439d44a24453b4e4ea3d5e0b53a5c0a935151ff3fd1 \
    # wasm-bindgen 0.2.100, the version `Cargo.lock` pins for the crate:
    # the browser package's `build.sh` refuses any other.
    && fetch https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.100/wasm-bindgen-0.2.100-x86_64-unknown-linux-musl.tar.gz \
        wasm-bindgen.tar.gz 63d6a38deb65bd7023c02bdf382ab66b0d2c0241c8582fd3413b5a808b8aeb5b \
    # Binaryen 133, for `wasm-opt`: the version that `build.sh` pins.
    && fetch https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-linux.tar.gz \
        binaryen.tar.gz 2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489 \
    && tar xf rust.tar.xz \
    && tar xf rust-std-wasm32.tar.xz \
    && ./rust-1.95.0-x86_64-unknown-linux-gnu/install.sh --destdir=/opt/rust --prefix= \
        --components=rustc,rust-std-x86_64-unknown-linux-gnu,cargo >/dev/null \
    && ./rust-std-1.95.0-wasm32-unknown-unknown/install.sh --destdir=/opt/rust --prefix= >/dev/null \
    && tar xf wasm-bindgen.tar.gz \
    && cp wasm-bindgen-0.2.100-x86_64-unknown-linux-musl/wasm-bindgen /usr/local/bin/ \
    && tar xf binaryen.tar.gz \
    && cp binaryen-version_133/bin/wasm-opt /usr/local/bin/ \
    && cd / && rm -rf /tmp/dl

ENV PATH=/opt/rust/bin:/usr/local/bin:/usr/bin:/bin
RUN rustc --version && cargo --version && wasm-bindgen --version && wasm-opt --version

# ════════════════════════════════════════════════════════════════════════
#  The SDK
# ════════════════════════════════════════════════════════════════════════

FROM sdk-toolchain AS sdk
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# The firmware's folder, though the bytes do not depend on it here: both
# `build.sh` write `/kassigner` in its place.
WORKDIR /build/kassigner
COPY . .
RUN sh release/sdk.sh /out

# ════════════════════════════════════════════════════════════════════════
#  The Secure Boot bootloaders, the S3's and the P4's
# ════════════════════════════════════════════════════════════════════════

# Espressif's ESP-IDF v6.1 image by digest. The bootloader, like the plain
# one espflash puts in the full images, is Espressif's C: the only code in a
# unit's flash that is neither ours nor Rust. The repository holds only its
# settings, `release/bootloader-<chip>/sdkconfig.defaults`.
#
# ESP-IDF builds a bootloader only inside a project, so its `hello_world`
# example is copied to a fixed folder and `idf.py bootloader` compiles the
# bootloader alone; the example itself is never compiled.
FROM --platform=linux/amd64 espressif/idf:v6.1@sha256:81893c71bb5e570088901f21def8684c25cd2a9020281bd01b843a7655edb18c AS bootloader
# No `-u`: ESP-IDF's export.sh reads variables that may be unset.
SHELL ["/bin/bash", "-e", "-o", "pipefail", "-c"]
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
COPY release/bootloader-esp32s3/sdkconfig.defaults /build/settings/esp32s3/sdkconfig.defaults
COPY release/bootloader-esp32p4/sdkconfig.defaults /build/settings/esp32p4/sdkconfig.defaults
COPY Cargo.toml release/version.sh /build/version/
RUN . "$IDF_PATH/export.sh" >/dev/null \
    && name="kassigner-$(sh /build/version/version.sh /build/version/Cargo.toml)" \
    && mkdir -p /out \
    && for chip in esp32s3 esp32p4; do \
        cp -r "$IDF_PATH/examples/get-started/hello_world" "/build/bootloader-$chip" \
        && cd "/build/bootloader-$chip" \
        && idf.py -DSDKCONFIG_DEFAULTS="/build/settings/$chip/sdkconfig.defaults" \
            set-target "$chip" >/dev/null \
        && idf.py bootloader \
        && cp build/bootloader/bootloader.bin "/out/$name-$chip-secure-bootloader.bin" \
        || exit 1; \
    done

# ════════════════════════════════════════════════════════════════════════
#  The hash list, and the line to be signed
# ════════════════════════════════════════════════════════════════════════

# `SHA256SUMS` first, over every file there; `SIGN.TXT` after it, so the
# list never names it. Each value is set on its own, so a failure stops the
# build rather than writing a line with a part missing.
FROM toolchain AS sums
COPY --from=firmware /out/ /out/
COPY --from=bootloader /out/ /out/
COPY --from=sdk /out/ /out/
COPY Cargo.toml release/version.sh /build/version/
RUN cd /out \
    && sha256sum $(ls | sort) > SHA256SUMS \
    && cat SHA256SUMS \
    && version="$(sh /build/version/version.sh /build/version/Cargo.toml)" \
    && sums="$(sha256sum SHA256SUMS | cut -d' ' -f1)" \
    && printf 'KasSigner v%s SHA256SUMS %s' "$version" "$sums" > SIGN.TXT \
    && cat SIGN.TXT && echo

FROM scratch AS release
COPY --from=sums /out/ /
