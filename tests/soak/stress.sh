#!/usr/bin/env bash
# Stress-test scd-rs-probe's handle discipline under perturbed PC/SC state.
#
# While the probe runs a high-iteration loop, a parallel worker thrashes
# PC/SC by running `opensc-tool --list-readers` on a short interval. This
# exercises the "other PC/SC client" scenario that kills stock scdaemon.
#
# Optional: set PCSCD_RESTART=1 to periodically restart pcscd via sudo.
# That requires passwordless sudo (visudo) or an interactive terminal.
#
# Usage:
#   tests/soak/stress.sh [--ident <AID>] [--count N] [--delay-ms N]
#
# Defaults match the user's Nitrokey 3.

set -euo pipefail

IDENT="D276000124010304000FE9B8A8420000"
COUNT=200
DELAY_MS=25
PCSC_INTERFERE_SEC=3
PCSCD_RESTART_SEC=30

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ident)
            IDENT="$2"
            shift 2
            ;;
        --count)
            COUNT="$2"
            shift 2
            ;;
        --delay-ms)
            DELAY_MS="$2"
            shift 2
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROBE="$ROOT/target/debug/scd-rs-probe"
if [[ ! -x "$PROBE" ]]; then
    echo "+++ building scd-rs-probe"
    (cd "$ROOT" && cargo build --bin scd-rs-probe)
fi

workers=()
cleanup() {
    echo
    echo "--- cleaning up background workers"
    for pid in "${workers[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

echo "+++ starting PC/SC interference (opensc-tool every ${PCSC_INTERFERE_SEC}s)"
(
    while true; do
        opensc-tool --list-readers >/dev/null 2>&1 || true
        sleep "$PCSC_INTERFERE_SEC"
    done
) &
workers+=($!)

if [[ "${PCSCD_RESTART:-0}" == "1" ]]; then
    echo "+++ starting pcscd restart loop (every ${PCSCD_RESTART_SEC}s)"
    (
        while true; do
            sleep "$PCSCD_RESTART_SEC"
            sudo -n systemctl restart pcscd.socket pcscd.service >/dev/null 2>&1 \
                && echo "  [pcscd restarted]"
        done
    ) &
    workers+=($!)
fi

echo "+++ probe loop: count=$COUNT delay_ms=$DELAY_MS"
"$PROBE" loop --ident "$IDENT" --count "$COUNT" --delay-ms "$DELAY_MS"
