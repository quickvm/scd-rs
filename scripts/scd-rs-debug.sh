#!/usr/bin/env bash
# Debug wrapper for scd-rs: points gpg-agent at the daemon and forces logs
# to /tmp/scd-rs.log (override with $SCD_RS_LOG) since scdaemon-program in
# gpg-agent.conf doesn't accept flags.
#
# Env vars you can tune (all optional):
#   SCD_RS_LOG            - log file (default /tmp/scd-rs.log)
#   SCD_RS_PIN_TTL        - PIN cache TTL, e.g. 8h (default 10m)
#   SCD_RS_CARD_POOL_TTL  - card-handle pool TTL, e.g. 5s (default 0 = off)

set -euo pipefail
exec env \
    SCD_RS_LOG="${SCD_RS_LOG:-/tmp/scd-rs.log}" \
    SCD_RS_PIN_TTL="${SCD_RS_PIN_TTL:-10m}" \
    SCD_RS_CARD_POOL_TTL="${SCD_RS_CARD_POOL_TTL:-5s}" \
    /home/jdoss/src/personal/scd-rs-agent/target/release/scd-rs "$@"
