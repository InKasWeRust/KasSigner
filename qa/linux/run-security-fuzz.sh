#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export CARGO_TARGET_DIR="$ROOT/target/qa"
# shellcheck source=qa/linux/lib/terminal_pause.sh
source "$ROOT/qa/linux/lib/terminal_pause.sh"
kassigner_qa_install_exit_handler "Security fuzzing"
cd "$ROOT"

# shellcheck source=qa/config/toolchains.env
source "$ROOT/qa/config/toolchains.env"
# shellcheck source=scripts/linux/lib/rustup_bootstrap.sh
source "$ROOT/scripts/linux/lib/rustup_bootstrap.sh"
kassigner_ensure_rustup || exit $?
VERSION="$KASSIGNER_CARGO_FUZZ_VERSION"
INSTALLER_TOOLCHAIN="$KASSIGNER_STABLE_RUST"
EXECUTION_TOOLCHAIN="$KASSIGNER_BRANCH_RUST"
SECONDS_PER_TARGET="${FUZZ_SECONDS:-300}"
OUTPUT="target/qa/fuzz"
STATUS_FILE="$OUTPUT/statuses.tsv"
ARTIFACT_ROOT="$OUTPUT/artifacts"
CORPUS_ROOT="$OUTPUT/corpus"
SEED_ROOT="qa/fuzz/seeds"
LEGACY_FUZZ_ARTIFACTS="$ROOT/qa/fuzz/artifacts"
LEGACY_FUZZ_CORPUS="$ROOT/qa/fuzz/corpus"
cleanup_source_fuzz_scratch() {
  rm -rf "$LEGACY_FUZZ_ARTIFACTS" "$LEGACY_FUZZ_CORPUS"
}
cleanup_source_fuzz_scratch
trap cleanup_source_fuzz_scratch EXIT

if ! rustup run "$INSTALLER_TOOLCHAIN" rustc --version >/dev/null 2>&1; then
  rustup toolchain install "$INSTALLER_TOOLCHAIN" --profile minimal || exit $?
fi
if ! rustup run "$EXECUTION_TOOLCHAIN" rustc --version >/dev/null 2>&1; then
  rustup toolchain install "$EXECUTION_TOOLCHAIN" --profile minimal || exit $?
fi
actual="$(rustup run "$EXECUTION_TOOLCHAIN" cargo fuzz --version 2>/dev/null || true)"
if [[ "$actual" != *"cargo-fuzz $VERSION"* ]]; then
  rustup run "$INSTALLER_TOOLCHAIN" cargo install cargo-fuzz --version "$VERSION" --locked --force || exit $?
  actual="$(rustup run "$EXECUTION_TOOLCHAIN" cargo fuzz --version 2>/dev/null || true)"
fi
[[ "$actual" == *"cargo-fuzz $VERSION"* ]] || {
  echo "ERROR: expected cargo-fuzz $VERSION, received: $actual" >&2
  exit 2
}

target_list="$(python3 qa/checks/security/fuzz_targets.py --validate)" || exit $?
mapfile -t targets <<<"$target_list"
((${#targets[@]} > 0)) || { echo "ERROR: no fuzz targets are registered" >&2; exit 1; }

rm -rf "$OUTPUT"
mkdir -p "$OUTPUT" "$ARTIFACT_ROOT" "$CORPUS_ROOT"
: > "$STATUS_FILE"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

for target in "${targets[@]}"; do
  echo "=== fuzz: $target (${SECONDS_PER_TARGET}s) ==="
  seed_dir="$ROOT/$SEED_ROOT/$target"
  corpus_dir="$ROOT/$CORPUS_ROOT/$target"
  artifact_dir="$ROOT/$ARTIFACT_ROOT/$target"
  [[ -d "$seed_dir" ]] || {
    echo "ERROR: authored fuzz seeds are missing for $target: $seed_dir" >&2
    printf '%s\t%s\n' "$target" 2 >> "$STATUS_FILE"
    continue
  }
  mkdir -p "$corpus_dir" "$artifact_dir"
  cp -a "$seed_dir"/. "$corpus_dir"/
  (
    cd "$ROOT/qa/fuzz"
    rustup run "$EXECUTION_TOOLCHAIN" cargo fuzz run "$target" -- \
      "-max_total_time=$SECONDS_PER_TARGET" \
      -print_final_stats=1 \
      "-artifact_prefix=$artifact_dir/" \
      "$corpus_dir"
  ) 2>&1 | tee "$OUTPUT/$target.log"
  target_status=${PIPESTATUS[0]}
  printf '%s\t%s\n' "$target" "$target_status" >> "$STATUS_FILE"
  if ((target_status != 0)); then
    echo "FAIL: fuzz target $target (exit $target_status)" >&2
  fi
done

completed="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 qa/checks/security/fuzz_results.py \
  --statuses "$STATUS_FILE" \
  --tool "$actual" \
  --started "$started" \
  --completed "$completed" \
  --seconds "$SECONDS_PER_TARGET"
