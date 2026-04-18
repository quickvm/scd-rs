#!/usr/bin/env bash
# Debug wrapper for scd-rs: points gpg-agent at the daemon and forces logs
# to /tmp/scd-rs.log (override with $SCD_RS_LOG) since scdaemon-program in
# gpg-agent.conf doesn't accept flags.

set -euo pipefail
# SCD_RS_DRY_SIGN=1: PKSIGN runs the full INQUIRE NEEDPIN → PIN-reception flow
# but skips the card verify. Use while debugging PIN-length / encoding issues
# so bad PINs don't decrement the card's retry counter.
exec env \
    SCD_RS_LOG="${SCD_RS_LOG:-/tmp/scd-rs.log}" \
    SCD_RS_DRY_SIGN="${SCD_RS_DRY_SIGN:-}" \
    /home/jdoss/src/personal/scd-rs-agent/target/debug/scd-rs "$@"
