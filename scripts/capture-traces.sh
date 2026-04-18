#!/usr/bin/env bash
# Capture real Assuan traces between gpg-agent and stock scdaemon for the
# workflows scd-rs must replicate. Traces go to docs/assuan-traces/.
#
# Enables `debug ipc` + `log-file` in ~/.gnupg/{scdaemon,gpg-agent}.conf
# transiently. Backups are restored on exit (trap EXIT).
#
# Requires an OpenPGP card (Nitrokey 3) inserted with usable signing and
# encryption subkeys. Will prompt via pinentry.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRACE_DIR="$ROOT/docs/assuan-traces"
mkdir -p "$TRACE_DIR"

SCD_LOG="$HOME/.gnupg/scdaemon.trace.log"
AGENT_LOG="$HOME/.gnupg/gpg-agent.trace.log"
SCD_CONF="$HOME/.gnupg/scdaemon.conf"
AGENT_CONF="$HOME/.gnupg/gpg-agent.conf"
SCD_BAK="$SCD_CONF.scd-rs-trace-backup"
AGENT_BAK="$AGENT_CONF.scd-rs-trace-backup"

scd_created=0
agent_created=0

cleanup() {
    echo
    echo "--- Restoring configs"
    if [ "$scd_created" = "1" ]; then
        rm -f "$SCD_CONF"
    elif [ -f "$SCD_BAK" ]; then
        mv -f "$SCD_BAK" "$SCD_CONF"
    fi
    if [ "$agent_created" = "1" ]; then
        rm -f "$AGENT_CONF"
    elif [ -f "$AGENT_BAK" ]; then
        mv -f "$AGENT_BAK" "$AGENT_CONF"
    fi
    gpgconf --kill scdaemon gpg-agent >/dev/null 2>&1 || true
    rm -f "$SCD_LOG" "$AGENT_LOG"
}
trap cleanup EXIT

if [ -f "$SCD_CONF" ]; then
    cp "$SCD_CONF" "$SCD_BAK"
else
    touch "$SCD_CONF"
    scd_created=1
fi
if [ -f "$AGENT_CONF" ]; then
    cp "$AGENT_CONF" "$AGENT_BAK"
else
    touch "$AGENT_CONF"
    agent_created=1
fi

{
    echo "debug ipc"
    echo "log-file $SCD_LOG"
    echo "verbose"
} >> "$SCD_CONF"
{
    echo "debug ipc"
    echo "log-file $AGENT_LOG"
    echo "verbose"
} >> "$AGENT_CONF"

gpgconf --kill scdaemon gpg-agent

SIGN_FPR=$(gpg --card-status --with-colons 2>/dev/null | awk -F: '/^fpr:/ {print $2; exit}' || true)
if [ -z "$SIGN_FPR" ]; then
    echo "ERROR: no signing key found via gpg --card-status" >&2
    exit 1
fi
echo "Card signing key: $SIGN_FPR"

capture() {
    local name="$1"; shift
    echo "+++ $name"
    : > "$SCD_LOG"
    : > "$AGENT_LOG"
    if ! "$@"; then
        echo "  (workflow exited non-zero; continuing)"
    fi
    sleep 0.5
    cp "$SCD_LOG" "$TRACE_DIR/$name.scdaemon.log"
    cp "$AGENT_LOG" "$TRACE_DIR/$name.gpg-agent.log"
    echo "  -> $TRACE_DIR/$name.{scdaemon,gpg-agent}.log"
}

capture card-status gpg --card-status

capture clearsign bash -c "echo 'scd-rs trace test' | gpg --clearsign -u $SIGN_FPR -o /tmp/scd-rs-trace.sig"

TMP_PLAIN="$(mktemp --suffix=.txt)"
TMP_ENC="$(mktemp --suffix=.gpg)"
echo 'scd-rs decrypt test' > "$TMP_PLAIN"
gpg --yes --batch --trust-model always --encrypt --armor \
    --recipient "$SIGN_FPR" --output "$TMP_ENC" "$TMP_PLAIN"

capture decrypt gpg --decrypt "$TMP_ENC"

rm -f "$TMP_PLAIN" "$TMP_ENC" /tmp/scd-rs-trace.sig

echo
echo "Done. Inspect $TRACE_DIR/ before committing."
