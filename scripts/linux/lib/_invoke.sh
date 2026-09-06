#!/usr/bin/env bash
# Shared Linux wrapper dispatcher. Canonical script logic stays at its logical path.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

(($# >= 1)) || {
    printf 'ERROR: internal wrapper target is required\n' >&2
    exit 2
}

TARGET="$1"
shift
TARGET_PATH="${ROOT_DIR}/${TARGET}"

[[ "$TARGET" != /* && "$TARGET" != *".."* ]] || {
    printf 'ERROR: invalid wrapper target: %s\n' "$TARGET" >&2
    exit 2
}
[[ -f "$TARGET_PATH" ]] || {
    printf 'ERROR: canonical script not found: %s\n' "$TARGET" >&2
    exit 2
}

exec bash "$TARGET_PATH" "$@"
