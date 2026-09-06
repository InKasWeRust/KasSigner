#!/usr/bin/env bash
# Provision, build, and run the automated ESP32-S3 QEMU hardware test suite.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/run.sh" --test-only
