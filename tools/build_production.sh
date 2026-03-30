#!/bin/bash
# Production build: delegates to the unified build script with "production" flag
exec "$(dirname "$0")/build_with_hash.sh" production
