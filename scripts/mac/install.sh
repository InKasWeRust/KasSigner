#!/bin/bash
# KasSigner iOS/macOS developer dependency installer.
# Installs/verifies only the dependencies required by make ios / make ios-qa.
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
exec "${ROOT_DIR}/apps/kassee-ios/setup-macos.command" --no-pause "$@"
