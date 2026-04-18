#!/usr/bin/env bash
# Debug wrapper for scd-rs: points gpg-agent at the daemon and forces logs
# to /tmp/scd-rs.log (override with $SCD_RS_LOG) since scdaemon-program in
# gpg-agent.conf doesn't accept flags.

set -euo pipefail
exec env SCD_RS_LOG="${SCD_RS_LOG:-/tmp/scd-rs.log}" \
    /home/jdoss/src/personal/scd-rs-agent/target/debug/scd-rs "$@"
