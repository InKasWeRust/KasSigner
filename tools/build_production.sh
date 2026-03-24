#!/bin/bash
# Build de producción: delega al script unificado con flag "production"
exec "$(dirname "$0")/build_with_hash.sh" production
