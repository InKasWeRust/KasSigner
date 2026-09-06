#!/usr/bin/env bash
# Build and export the complete KasSigner reproducible firmware release matrix.
# Network access, when a verified cache is not already present, happens only in
# the host prefetch phase. Every Docker build is explicitly network-disabled.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_OUTPUT="$ROOT/release"
OUTPUT_DIR="$DEFAULT_OUTPUT"
SIGNING_KEY="${KASSIGNER_SIGNING_KEY:-}"
TOOLCHAIN_IMAGE="kassigner-toolchain:v3"
UBUNTU_IMAGE="kassigner-ubuntu-rootfs:v1"
PLATFORM="linux/amd64"
PREFETCH_ROOT="$ROOT/target/qa/state/reproducible-build-inputs"

# Load the authoritative pinned host toolchain before any Docker bootstrap.
# This must happen before repro_ensure_docker_access(), because that helper may
# re-exec this script under `sg docker`; the fresh process must initialize the
# same pinned configuration before the first use of KASSIGNER_STABLE_RUST.
# shellcheck source=qa/config/toolchains.env
source "$ROOT/qa/config/toolchains.env"
export KASSIGNER_STABLE_RUST KASSIGNER_REPRO_HOST_RUST

# shellcheck source=scripts/linux/lib/admin.sh
source "$ROOT/scripts/linux/lib/admin.sh"
# shellcheck source=scripts/linux/build/reproducible/docker_access.sh
source "$ROOT/scripts/linux/build/reproducible/docker_access.sh"
# shellcheck source=scripts/linux/lib/cargo_locks.sh
source "$ROOT/scripts/linux/lib/cargo_locks.sh"

usage() {
    cat <<USAGE
Usage: $(basename "$0") [--output-dir DIR] [--signing-key FILE] [--refresh-inputs]

Builds the complete KasSigner reproducible firmware release matrix inside the
repository's pinned Docker environment and exports firmware, source hashes,
SHA-256 manifests, build-input provenance, and the build manifest.

All internet access is completed by the host prefetch phase before Docker image
import/build steps begin. Docker builds run with --network=none.

Options:
  --output-dir DIR    Export directory (default: $DEFAULT_OUTPUT)
  --signing-key FILE  32-byte Schnorr firmware signing key
  --refresh-inputs    Discard the verified input cache and prefetch again
  -h, --help          Show this help
USAGE
}

ORIGINAL_ARGS=("$@")
REFRESH_INPUTS=0
while (($#)); do
    case "$1" in
        --output-dir)
            (($# >= 2)) || { echo "ERROR: --output-dir requires a path" >&2; exit 2; }
            OUTPUT_DIR="$2"; shift 2 ;;
        --signing-key)
            (($# >= 2)) || { echo "ERROR: --signing-key requires a path" >&2; exit 2; }
            SIGNING_KEY="$2"; shift 2 ;;
        --refresh-inputs)
            REFRESH_INPUTS=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if repro_ensure_docker_access; then
    :
else
    status=$?
    if ((status == REPRO_DOCKER_REEXEC_STATUS)); then
        repro_reexec_with_docker_group "$ROOT/scripts/linux/build/reproducible-build.sh" "${ORIGINAL_ARGS[@]}"
        exit $?
    fi
    exit "$status"
fi

command -v flock >/dev/null 2>&1 || {
    echo "ERROR: flock is required to serialize QA and reproducible-release workflows." >&2
    exit 2
}
mkdir -p "$ROOT/target/qa/state"
exec 9>"$ROOT/target/qa/state/release-workflow.lock"
if ! flock -n 9; then
    echo "Another KasSigner QA/reproducible-release workflow is active; waiting for it to finish."
    flock 9
fi

command -v python3 >/dev/null 2>&1 || {
    echo "ERROR: python3 is required for reproducible-build input prefetching." >&2
    exit 2
}

printf '==> Reconciling/verifying host Cargo.lock files under pinned Cargo %s\n' "$KASSIGNER_STABLE_RUST"
kassigner_reconcile_host_locks "$ROOT"

if [[ -n "$SIGNING_KEY" ]]; then
    [[ -f "$SIGNING_KEY" ]] || { echo "ERROR: signing key not found: $SIGNING_KEY" >&2; exit 2; }
    key_size=$(wc -c < "$SIGNING_KEY" | tr -d '[:space:]')
    [[ "$key_size" == "32" ]] || {
        echo "ERROR: signing key must be exactly 32 bytes; got ${key_size}" >&2
        exit 2
    }
    SIGNING_KEY="$(cd "$(dirname "$SIGNING_KEY")" && pwd)/$(basename "$SIGNING_KEY")"
fi

build_commit="${KASSIGNER_GIT_COMMIT:-}"
if [[ -z "$build_commit" ]] && command -v git >/dev/null 2>&1 \
    && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    build_commit="$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null || true)"
fi
if [[ -n "$build_commit" && ! "$build_commit" =~ ^[0-9A-Fa-f]{7,40}$ ]]; then
    echo "ERROR: KASSIGNER_GIT_COMMIT must be 7-40 hexadecimal characters." >&2
    exit 2
fi

mkdir -p "$(dirname "$OUTPUT_DIR")"
OUTPUT_PARENT="$(cd "$(dirname "$OUTPUT_DIR")" && pwd)"
OUTPUT_DIR="$OUTPUT_PARENT/$(basename "$OUTPUT_DIR")"
STAGING_DIR=""
cleanup() {
    [[ -z "$STAGING_DIR" ]] || rm -rf "$STAGING_DIR"
}
trap cleanup EXIT INT TERM

printf '==> Prefetching/verifying every external build input on the host\n'
prefetch_args=(
    "$ROOT/scripts/linux/build/reproducible/prefetch.py"
    --root "$ROOT"
    --output "$PREFETCH_ROOT"
)
((REFRESH_INPUTS == 0)) || prefetch_args+=(--refresh)
python3 "${prefetch_args[@]}"

printf '==> Verifying KasSee lock with frozen reproducible Rust %s\n' "$KASSIGNER_REPRO_HOST_RUST"
REPRO_HOME="$PREFETCH_ROOT/root-home"
REPRO_ENV=(
    HOME="$REPRO_HOME"
    CARGO_HOME="$REPRO_HOME/.cargo"
    RUSTUP_HOME="$REPRO_HOME/.rustup"
    PATH="$REPRO_HOME/.cargo/bin:$PATH"
    RUSTUP_TOOLCHAIN="$KASSIGNER_REPRO_HOST_RUST"
    CARGO_NET_OFFLINE=true
)
env "${REPRO_ENV[@]}" \
    cargo metadata \
        --manifest-path "$ROOT/apps/kassee-web/Cargo.toml" \
        --format-version 1 \
        --filter-platform wasm32-unknown-unknown \
        --locked \
        --offline \
        >/dev/null || {
    echo "ERROR: KasSee Cargo.lock is not compatible with frozen reproducible Rust $KASSIGNER_REPRO_HOST_RUST." >&2
    echo "The lock must be reconciled for the reproducible MSRV before Docker can run." >&2
    exit 2
}

printf '==> Preflighting KasSee WASM release with frozen reproducible Rust %s\n' "$KASSIGNER_REPRO_HOST_RUST"
rm -rf "$PREFETCH_ROOT/kassee-msrv-target"
env "${REPRO_ENV[@]}" \
    CARGO_TARGET_DIR="$PREFETCH_ROOT/kassee-msrv-target" \
    cargo build \
        --manifest-path "$ROOT/apps/kassee-web/Cargo.toml" \
        --target wasm32-unknown-unknown \
        --release \
        --locked \
        --offline || {
    echo "ERROR: KasSee WASM does not build with frozen reproducible Rust $KASSIGNER_REPRO_HOST_RUST." >&2
    echo "Docker was not started; the host preflight above contains the exact compiler/dependency error." >&2
    exit 2
}

# The prefetched Docker context hard-links the isolated Rust/Cargo home to keep
# disk usage bounded. Cargo may update cache bookkeeping during the host MSRV
# preflight above, which changes bytes visible through those hardlinks. Rebuild
# both SHA-256 inventories from the exact context Docker will receive now.
printf '==> Finalizing post-preflight Docker input manifests\n'
python3 "$ROOT/scripts/linux/build/reproducible/prefetch.py" \
    --root "$ROOT" \
    --output "$PREFETCH_ROOT" \
    --finalize-context-manifests

# No network-backed operation is allowed after this line. The pinned Ubuntu
# rootfs was downloaded and digest-verified by the host prefetcher.
printf '\n==> Host network phase complete; all Docker operations are networkless\n'
export DOCKER_BUILDKIT=1

docker image rm --force "$UBUNTU_IMAGE" >/dev/null 2>&1 || true
docker import --platform "$PLATFORM" "$PREFETCH_ROOT/ubuntu-rootfs-layer.tar.gz" "$UBUNTU_IMAGE" >/dev/null

printf '==> Building pinned KasSigner toolchain image with Docker networking disabled\n'
docker build \
    --network=none \
    --pull=false \
    --platform "$PLATFORM" \
    --file "$ROOT/Dockerfile.base" \
    --tag "$TOOLCHAIN_IMAGE" \
    "$PREFETCH_ROOT/context"

# Keep the default release staging tree inside target/qa/state so repository
# inventory/architecture checks can run concurrently without mistaking a
# runner-owned temporary directory for source.  Custom output directories keep
# staging adjacent so the final rename stays on the same filesystem.
if [[ "$OUTPUT_DIR" == "$ROOT"/* ]]; then
    STAGING_DIR="$ROOT/target/qa/state/reproducible-release-stage.$$"
else
    STAGING_DIR="${OUTPUT_DIR}.tmp.$$"
fi
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"

printf '\n==> Building and exporting release artifacts with Docker networking disabled\n'
build_args=(
    --network=none
    --pull=false
    --platform "$PLATFORM"
    --file "$ROOT/Dockerfile"
    --target artifacts
    --output "type=local,dest=$STAGING_DIR"
)
[[ -z "$build_commit" ]] || build_args+=(--build-arg "KASSIGNER_GIT_COMMIT=$build_commit")
[[ -z "$SIGNING_KEY" ]] || build_args+=(--secret "id=signkey,src=$SIGNING_KEY")
build_args+=("$ROOT")
docker build "${build_args[@]}"

required=(
    SHA256SUMS SOURCE-SHA256SUMS BUILD-MANIFEST.txt ARTIFACT-MANIFEST.json
    MANIFEST-SHA256SUMS BUILD-INPUT-SHA256SUMS BUILD-INPUT-MANIFEST.json
    kassigner-waveshare-unsigned.bin kassigner-waveshare-unsigned-full.bin kassigner-waveshare-unsigned.codehash
    kassigner-waveshare-af-unsigned.bin kassigner-waveshare-af-unsigned-full.bin kassigner-waveshare-af-unsigned.codehash
    kassigner-m5stack-unsigned.bin kassigner-m5stack-unsigned-full.bin kassigner-m5stack-unsigned.codehash
    kassigner-m5stack-partitions.csv
)
for artifact in "${required[@]}"; do
    [[ -f "$STAGING_DIR/$artifact" ]] || {
        echo "ERROR: Docker build did not export required artifact: $artifact" >&2
        exit 1
    }
done

if [[ -n "$SIGNING_KEY" ]]; then
    signed_required=(
        kassigner-waveshare.bin kassigner-waveshare-full.bin kassigner-waveshare.codehash
        kassigner-waveshare-af.bin kassigner-waveshare-af-full.bin kassigner-waveshare-af.codehash
        kassigner-m5stack.bin kassigner-m5stack-full.bin kassigner-m5stack.codehash
        kassigner-waveshare-update.ksfu kassigner-waveshare-af-update.ksfu
    )
    for artifact in "${signed_required[@]}"; do
        [[ -f "$STAGING_DIR/$artifact" ]] || {
            echo "ERROR: signed Docker build did not export required artifact: $artifact" >&2
            exit 1
        }
    done
fi

(cd "$STAGING_DIR" && sha256sum -c MANIFEST-SHA256SUMS && sha256sum -c SHA256SUMS)
rm -rf "$OUTPUT_DIR"
mv "$STAGING_DIR" "$OUTPUT_DIR"
trap - EXIT INT TERM

printf '\nKasSigner reproducible Docker build complete.\n'
printf 'Artifacts: %s\n' "$OUTPUT_DIR"
printf 'Firmware images: %s\n' "$(find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.bin' | wc -l | tr -d '[:space:]')"
printf 'Docker networking: disabled for every build step.\n'
printf 'No device was flashed or contacted.\n'
