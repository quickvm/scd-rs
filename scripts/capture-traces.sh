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

# This script captures STOCK scdaemon traffic — if the user has
# scdaemon-program pointing at scd-rs (or any other replacement), gpg-agent
# would invoke that instead and the stock log-file never gets written.
# Neutralize the override for the duration of the capture; the EXIT trap
# restores the original config from $AGENT_BAK.
sed -i 's|^scdaemon-program |#scdrs-trace# scdaemon-program |' "$AGENT_CONF"
echo "--- gpg-agent.conf scdaemon-program line during capture:"
grep -E '^#?.*scdaemon-program' "$AGENT_CONF" || echo "(none; stock scdaemon will be used)"

# `gpgconf --kill` only tells gpg-agent to release its scdaemon subprocess;
# the subprocess itself often survives, and so can a prior gpg-agent. If any
# scd-rs or scdaemon is still alive from a previous capture session, a new
# gpg-agent may not re-read the config as expected. Force-kill everything.
gpgconf --kill scdaemon gpg-agent >/dev/null 2>&1 || true
sleep 0.2
pkill -9 -x -u "$USER" gpg-agent 2>/dev/null || true
pkill -9 -x -u "$USER" scdaemon 2>/dev/null || true
pkill -9 -f -u "$USER" 'target/(debug|release)/scd-rs' 2>/dev/null || true
sleep 0.3
if pgrep -af -u "$USER" 'gpg-agent|scdaemon|scd-rs' >/dev/null; then
    echo "!!! gpg-agent / scdaemon / scd-rs survived kill; traces may fail:"
    pgrep -af -u "$USER" 'gpg-agent|scdaemon|scd-rs' | sed 's/^/    /'
fi

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
# gpg refuses `--encrypt --recipient <signkey-fpr>` (key usage = sign, not
# encrypt) with "Unusable public key", so the capture would exit before the
# PKDECRYPT round. Pick the actual encryption-capable subkey fingerprint.
ENC_FPR=$(gpg -K --with-colons --with-subkey-fingerprints 2>/dev/null |
    awk -F: '/^ssb:/ { want = ($12 ~ /e/) } /^fpr:/ && want { print $10; exit }')
if [ -z "$ENC_FPR" ]; then
    echo "ERROR: no encryption-capable subkey found in secret keyring" >&2
    exit 1
fi
echo "Encryption subkey: $ENC_FPR"
gpg --yes --batch --trust-model always --encrypt --armor \
    --recipient "$ENC_FPR" --output "$TMP_ENC" "$TMP_PLAIN"

capture decrypt gpg --decrypt "$TMP_ENC"

rm -f "$TMP_PLAIN" "$TMP_ENC" /tmp/scd-rs-trace.sig

echo
echo "Done. Inspect $TRACE_DIR/ before committing."
