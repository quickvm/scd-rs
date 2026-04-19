#!/usr/bin/env bash
# Debug wrapper for development use only.
#
# Resolves the scd-rs binary relative to the script's own location so it
# works from any clone path. Supplies reasonable defaults for log file,
# PIN cache TTL, and card-handle pool TTL (env-var overrides win).
#
# Production installs should point gpg-agent directly at an installed
# scd-rs binary and set env vars via the shell rc / systemd user
# session; see the Configuration section of README.md.
#
# Env vars you can tune (all optional):
#   SCD_RS_BIN            - override binary path (default: ../target/release/scd-rs)
#   SCD_RS_LOG            - log file (default /tmp/scd-rs.log)
#   SCD_RS_PIN_TTL        - PIN cache TTL, e.g. 8h (default 10m)
#   SCD_RS_CARD_POOL_TTL  - card-handle pool TTL, e.g. 5s (default 0 = off)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SCD_RS_BIN:-$SCRIPT_DIR/../target/release/scd-rs}"

exec env \
    SCD_RS_LOG="${SCD_RS_LOG:-/tmp/scd-rs.log}" \
    SCD_RS_PIN_TTL="${SCD_RS_PIN_TTL:-10m}" \
    SCD_RS_CARD_POOL_TTL="${SCD_RS_CARD_POOL_TTL:-5s}" \
    "$BIN" "$@"
