#!/bin/bash
# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
# Production build: delegates to the unified build script with "production" flag
exec "$(dirname "$0")/build_with_hash.sh" production
