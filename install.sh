#!/usr/bin/env bash
# KasSigner developer bootstrap façade.
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "$(uname -s)" in
    Linux) exec "$ROOT_DIR/scripts/linux/install/install.sh" "$@" ;;
    Darwin)
        # Preserve the historical macOS firmware build/flash path outside the Linux/Windows script trees.
        # These modules intentionally use explicit status checks like the original installer,
        # so do not impose the Linux façade's errexit/nounset semantics on them.
        set +e
        set +u
        export INSTALL_ROOT="$ROOT_DIR"
        source "$ROOT_DIR/tools/install/macos/common.sh"
        source "$ROOT_DIR/tools/install/macos/environment.sh"
        source "$ROOT_DIR/tools/install/macos/device.sh"
        source "$ROOT_DIR/tools/install/macos/firmware.sh"
        source "$ROOT_DIR/tools/install/macos/flash.sh"
        ;;
    *)
        echo 'ERROR: on native Windows run .\\install.ps1 from PowerShell.' >&2
        exit 2
        ;;
esac
