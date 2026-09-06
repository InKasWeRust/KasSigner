#!/bin/bash
# Finder-friendly wrapper for the KasSee iOS macOS developer bootstrap.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
exec "${ROOT_DIR}/apps/kassee-ios/setup-macos.command" "$@"
