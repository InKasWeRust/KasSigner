<!-- KasSigner: Air-gapped offline signing device for Kaspa -->
<!-- Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me) -->
<!-- License: GPL-3.0-only -->

# KasSigner: Reproducible Build Verification

## Don't Trust, Verify

This guide lets you check, without trusting anyone, that the released
KasSigner firmware was built from the public source in this repository.

You do not need the signing key. You build the **unsigned** images and compare
them against the published unsigned hashes.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- ~5 GB disk space
- ~25 minutes for a first build from scratch

## 1. Clone the repository

```bash
git clone https://github.com/InKasWeRust/KasSigner.git
cd KasSigner
git checkout v1.0.6      # the tag you are verifying
```

## 2. Build the toolchain image

The firmware compiles inside a frozen toolchain image, which does not exist
until you build it. Skipping this step fails immediately with
`kassigner-toolchain:v3 not found`.

```bash
docker build --platform linux/amd64 -f Dockerfile.base -t kassigner-toolchain:v3 .
```

Everything in that image is pinned:

| Component | Pinned as |
|---|---|
| Ubuntu base image | content digest, not the mutable `24.04` tag |
| System packages | exact versions, all eight |
| Host Rust | 1.85.0 |
| espup | 0.16.0 |
| Xtensa Rust cross-compiler | 1.95.0.0, passed explicitly to espup |
| Rust dependencies | `Cargo.lock` |

Two things matter here:

- `--platform linux/amd64` is **required**, including on an ARM Mac. It is what
  makes the output identical regardless of host architecture.
- The tag is **v3**. An older `kassigner-toolchain:v2` predates the pinning,
  was built from a mutable base, and will not reproduce these hashes. The tag
  is bumped whenever a pinned input changes, so an old and a new toolchain can
  never share a name.

## 3. Build the firmware

```bash
docker build --platform linux/amd64 -t kassigner-build .
docker run --rm kassigner-build
```

Without a signing key this builds the three **unsigned** targets (Waveshare,
Waveshare AF, and M5Stack) and skips the signed ones. That is the correct and
complete result for a verifier.

Each target runs five build-and-hash passes and asserts that the last two
agree. If a target ever fails to converge the build stops with an error rather
than producing a binary.

The run prints the code-segment hash for each target and the SHA-256 of every
image produced.

## 4. Compare

There are two hashes, and they answer different questions.

### The file hash

The `sha256sum` of each `.bin`. Compare your unsigned outputs against the
**unsigned** hashes published with the release.

**Signed and unsigned images are different files with different hashes.** The
developer signature is embedded in the firmware and changes the code segment,
so an unsigned build will never match a signed hash. That mismatch means
nothing. Compare unsigned against unsigned.

### The code-segment hash

A SHA-256 over the firmware's executable code segment. This is the value the
device displays on its own boot screen, and it is the stronger check, because
it verifies the code **running on your device** rather than a file on disk.

```bash
docker run --rm kassigner-build cat /build/kassigner-waveshare-unsigned.codehash
```

**This is only meaningful on a `production` build.** Released binaries are
production builds: firmware verification is enforced, so if the embedded hash
did not match the running code the device would halt instead of booting.
Reaching the UI is itself the proof that they match, and the screen shows a
teal confirmation.

A development build (`cargo run`) displays a hash too, but does not enforce
anything. The serial log will say `[DEV] WARNING: Hash mismatch ...
continuing`, and the screen marks the build in orange. Do not verify against a
development build.

Note the signed and unsigned code-segment hashes also differ, for the same
reason as the file hashes. Compare against the published unsigned value.

## 5. If the hashes do not match

Check these first, in order:

1. **Comparing the wrong pair.** Your unsigned build against a signed
   published hash.
2. **Stale toolchain.** An old `kassigner-toolchain:v2` present. Build v3.
3. **Missing platform flag.** Both `docker build` commands need
   `--platform linux/amd64`.
4. **Wrong target.** Waveshare against M5Stack, or the AF variant against the
   plain one. The AF image exists because that camera module is mounted
   flipped and needs an orientation correction; it is a different binary.
5. **Building the wrong commit.** Check out the release tag you are
   verifying, not the branch tip.
6. **Stale build cache.** `docker builder prune -af` and rebuild.

If none apply, please open an issue with your hashes, your host OS and
architecture, and the release tag. Every input to this build is pinned; a
genuine mismatch is a real finding and we want to know.

## What This Proves

| Claim | Verified? |
|---|---|
| The released binary was built from this source | Yes |
| No hidden code in the firmware | Yes |
| The code on your device matches what you built | Yes, via the code-segment hash on a production build |
| The signing key is secure | No. The code-segment comparison does not depend on it |
| The hardware is not tampered with | No. Physical security is yours |

## How It Works

Every input is pinned, so the same source compiled in that environment
produces the same bytes on any host. Verified 2026-08-03: a full rebuild after
`docker builder prune -af` produced byte-identical results for every target.

The firmware embeds a hash of its own code segment, which is circular:
writing the hash changes the binary, which changes the hash. The build
resolves it by iterating: compile, hash the image, write the hash into
`firmware_hash.rs`, recompile, hash again. It converges when the embedded
value equals the hash of the image containing it.

**Five passes, with the last two asserted equal.** Measured: signed settles at
pass 2, unsigned at pass 3. Three passes was the previous assumption and had
never been verified. A configuration needing four would have shipped a binary
whose embedded hash did not match its own code, which in a production build
halts at boot. The assertion turns that into a failed build.

The same build also compile-verifies the KasSee WASM as a project-integrity
check. That confirms the WASM compiles from source, but is **not** a
hash-reproducibility check: KasSee's `web/pkg/` bundle is served via
gh-pages and is not hash-pinned here.

## Note on signed builds

Only the maintainer can produce signed binaries, and only a `production` build
carries the signature at all.

`FIRMWARE_SIGNATURE` is a Rust `const`, and consts have no storage: they
exist only where they are used. Its only use is inside `verify_signature()`,
which a development build never reaches, so the compiler discards the function
and the 64 bytes with it. Measured: signed and unsigned *development* builds
are byte-identical and contain no signature at all.

This is why every released image is a production build.

## Re-running

To reprint the hashes without rebuilding:

```bash
docker run --rm kassigner-build
```

## Extracting the binaries

```bash
docker create --name ks-extract kassigner-build
docker cp ks-extract:/build/kassigner-waveshare-unsigned.bin .
docker rm ks-extract
shasum -a 256 kassigner-waveshare-unsigned.bin
```

**Do not flash an unsigned image.** It runs in production mode with no valid
signature, fails verification, and halts at boot. Unsigned images exist to be
hashed, not flashed.
