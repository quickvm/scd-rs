#!/usr/bin/env bash
# Capture Assuan traces emitted by scd-rs for the workflows stock scdaemon
# was captured against in Phase 0. Traces go to
# docs/assuan-traces/scdrs-{card-status,clearsign,decrypt}.log and use the
# same `<- ` / `-> ` direction convention as normalize-trace.py expects.
#
# Temporarily points gpg-agent's scdaemon-program at a wrapper that invokes
# scd-rs with `--trace-file`. Restores the original config on exit.
#
# Requires: scd-rs built (`cargo build --release` or `cargo build`), an
# OpenPGP card inserted with usable signing and encryption subkeys. Will
# prompt via pinentry.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TRACE_DIR="$ROOT/docs/assuan-traces"
mkdir -p "$TRACE_DIR"

SCD_RS_BIN="${SCD_RS_BIN:-$ROOT/target/release/scd-rs}"
if [ ! -x "$SCD_RS_BIN" ]; then
    SCD_RS_BIN="$ROOT/target/debug/scd-rs"
fi
if [ ! -x "$SCD_RS_BIN" ]; then
    echo "ERROR: scd-rs binary not found. Run 'cargo build --release' first." >&2
    exit 1
fi

AGENT_CONF="$HOME/.gnupg/gpg-agent.conf"
AGENT_BAK="$AGENT_CONF.scdrs-trace-backup"
WRAPPER="$(mktemp --suffix=.sh)"
WIRE_LOG="$(mktemp --suffix=.wire)"

cleanup() {
    echo
    echo "--- Restoring gpg-agent.conf"
    if [ -f "$AGENT_BAK" ]; then
        mv -f "$AGENT_BAK" "$AGENT_CONF"
    fi
    gpgconf --kill scdaemon gpg-agent >/dev/null 2>&1 || true
    rm -f "$WRAPPER" "$WIRE_LOG" "$WIRE_LOG.stderr"
}
trap cleanup EXIT

if [ ! -f "$AGENT_CONF" ]; then
    echo "ERROR: $AGENT_CONF does not exist; expected scd-rs already wired up" >&2
    exit 1
fi
cp "$AGENT_CONF" "$AGENT_BAK"

cat >"$WRAPPER" <<EOF
#!/usr/bin/env bash
exec "$SCD_RS_BIN" --trace-file "$WIRE_LOG" "\$@" 2>>"$WIRE_LOG.stderr"
EOF
chmod +x "$WRAPPER"

echo "--- Wrapper contents ($WRAPPER):"
cat "$WRAPPER"

# Replace any existing scdaemon-program line with our wrapper; append if none.
if grep -q '^scdaemon-program ' "$AGENT_CONF"; then
    sed -i "s|^scdaemon-program .*|scdaemon-program $WRAPPER|" "$AGENT_CONF"
else
    echo "scdaemon-program $WRAPPER" >>"$AGENT_CONF"
fi

echo "--- Updated gpg-agent.conf scdaemon line:"
grep '^scdaemon-program' "$AGENT_CONF" || echo "(none?)"

echo "--- GNUPGHOME=${GNUPGHOME:-<unset; defaults to ~/.gnupg>}"

gpgconf --kill scdaemon gpg-agent
# gpgconf --kill sometimes returns before the process actually exits, and on
# systems with socket-activated gpg-agent the unit can get respawned with the
# stale config before we notice. Wait and force-kill any stragglers.
for _ in 1 2 3 4 5; do
    if ! pgrep -x -u "$USER" gpg-agent >/dev/null 2>&1 &&
        ! pgrep -x -u "$USER" scdaemon >/dev/null 2>&1 &&
        ! pgrep -f -u "$USER" 'target/(debug|release)/scd-rs' >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
pkill -9 -x -u "$USER" gpg-agent 2>/dev/null || true
pkill -9 -x -u "$USER" scdaemon 2>/dev/null || true
pkill -9 -f -u "$USER" 'target/(debug|release)/scd-rs' 2>/dev/null || true
sleep 0.3

if pgrep -af -u "$USER" 'gpg-agent|scdaemon|scd-rs' >/dev/null; then
    echo "!!! gpg-agent / scdaemon survived kill; traces will likely fail:"
    pgrep -af -u "$USER" 'gpg-agent|scdaemon|scd-rs' | sed 's/^/    /'
fi

SIGN_FPR=$(gpg --card-status --with-colons 2>/dev/null | awk -F: '/^fpr:/ {print $2; exit}' || true)
if [ -z "$SIGN_FPR" ]; then
    echo "ERROR: no signing key found via gpg --card-status" >&2
    exit 1
fi
echo "Card signing key: $SIGN_FPR"
echo "--- scdaemon process after initial card-status:"
pgrep -af -u "$USER" 'scd-rs|scdaemon' | sed 's/^/    /' || echo "    (none)"

capture() {
    local name="$1"
    shift
    echo "+++ $name"
    # `gpgconf --kill scdaemon` only tells gpg-agent to stop using scdaemon;
    # the process itself sticks around with the current wire log open. We
    # force-kill it so it releases the file and the next invocation (via our
    # wrapper) creates a fresh one.
    pkill -9 -f -u "$USER" 'target/(debug|release)/scd-rs' 2>/dev/null || true
    sleep 0.2
    rm -f "$WIRE_LOG" "$WIRE_LOG.stderr"
    gpgconf --kill scdaemon >/dev/null 2>&1 || true
    if ! "$@"; then
        echo "  (workflow exited non-zero; continuing)"
    fi
    sleep 0.5
    if [ ! -f "$WIRE_LOG" ]; then
        echo "  !!! $WIRE_LOG missing. scd-rs stderr:"
        if [ -f "$WIRE_LOG.stderr" ]; then
            sed 's/^/      /' "$WIRE_LOG.stderr"
        else
            echo "      (no stderr file either — wrapper probably wasn't invoked)"
        fi
        echo "  Running scdaemon processes:"
        pgrep -af 'scd-rs|scdaemon' | sed 's/^/      /' || echo "      (none)"
        return 1
    fi
    cp "$WIRE_LOG" "$TRACE_DIR/scdrs-$name.log"
    echo "  -> $TRACE_DIR/scdrs-$name.log ($(wc -l <"$WIRE_LOG") lines)"
}

capture card-status gpg --card-status

capture clearsign bash -c "echo 'scd-rs trace test' | gpg --clearsign -u $SIGN_FPR -o /tmp/scd-rs-trace.sig"

TMP_PLAIN="$(mktemp --suffix=.txt)"
TMP_ENC="$(mktemp --suffix=.gpg)"
echo 'scd-rs decrypt test' >"$TMP_PLAIN"
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
echo "Done. Traces in $TRACE_DIR/scdrs-*.log"
echo "Next: normalize and diff against stock — see notes/03-trace-diff-vs-stock.md"
