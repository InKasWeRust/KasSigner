<!-- KasSigner — Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0 -->

# KasSigner — Reproducible Build Verification

## Don't Trust, Verify

This guide lets you independently verify that the KasSigner firmware binary
was built from the public source code — no trust required.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed
- ~5GB disk space for the build container
- ~15 minutes for the first build (subsequent builds are cached)

## Steps

### 1. Clone the repository

```bash
git clone https://github.com/InKasWeRust/KasSigner.git
cd KasSigner
git checkout <release-tag>  # e.g. v1.0.3 — use the tag you're verifying
```

### 2. Build in Docker

```bash
docker build -t kassigner-build .
```

The build will output a SHA-256 hash at the end:

```
============================================
  KasSigner Reproducible Build Complete
============================================

<hash>  bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader

Compare this hash with the published release hash.
If they match, the binary is built from this source.
============================================
```

### 3. Compare the hash

Check the hash against the one published in the [release notes](https://github.com/InKasWeRust/KasSigner/releases).

**If they match:** The binary provably comes from this exact source code.
No hidden code, no backdoors — what you read is what runs.

**If they don't match:** Something is wrong. Do NOT use that binary.
Open an issue on GitHub.

## What This Proves

| Claim | Verified? |
|-------|-----------|
| Binary is built from this source code | ✅ Yes |
| No hidden code in the firmware | ✅ Yes |
| The signing key is secure | ❌ No (you trust the developer) |
| The hardware is not tampered | ❌ No (physical security is on you) |

## How It Works

The Dockerfile pins every component of the build environment:

- **Ubuntu 24.04** — base OS
- **Rust 1.85.0** — host Rust compiler
- **espup 0.16.0** — installs exact Xtensa Rust toolchain
- **Xtensa Rust (esp fork)** — the cross-compiler (version pinned by espup)
- **Cargo.lock** — pins every dependency version
- **espflash 4.3.0** — image creation tool

Because every input is frozen, the output is deterministic.
Same source + same tools = same binary, every time.

## Re-running

To get just the hash without rebuilding:

```bash
docker run --rm kassigner-build
```

## Extracting the Binary

To pull the built binary out of the container:

```bash
docker create --name ks-extract kassigner-build
docker cp ks-extract:/build/KasSigner/bootloader/target/xtensa-esp32s3-none-elf/release/kassigner-bootloader ./kassigner-bootloader
docker rm ks-extract
sha256sum kassigner-bootloader
```
