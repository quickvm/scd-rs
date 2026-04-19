#!/usr/bin/env python3
"""Normalize Assuan wire traces into a common form for diffing.

Reads stdin (either stock scdaemon's `debug ipc` log or scd-rs's
`--trace-file` output) and writes normalized lines to stdout.

Transforms:
- Strip stock's `<date> <time> scdaemon[pid] DBG: chan_9 ` prefix.
- Drop free-form stock log lines that aren't `chan_9` directional traffic
  (e.g. `detected reader 'Nitrokey ...'`).
- Replace volatile fields with placeholders so the diff focuses on
  structural differences rather than per-run values.

Run on both sides before diffing:

    python3 scripts/normalize-trace.py < docs/assuan-traces/clearsign.scdaemon.log > a
    python3 scripts/normalize-trace.py < docs/assuan-traces/scdrs-clearsign.log > b
    diff -u a b
"""

from __future__ import annotations

import re
import sys

# `<date> <time> scdaemon[<pid>] DBG: chan_9 ` — the stock prefix we strip.
STOCK_PREFIX = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} scdaemon\[\d+\] DBG: chan_9 "
)

# `<date> <time> scdaemon[<pid>] ` — any other stock log noise we drop.
STOCK_NOISE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} scdaemon\[\d+\] ")

# `S SIG-COUNTER <n>` → `S SIG-COUNTER <N>`. Counter increments every sign.
SIG_COUNTER = re.compile(r"^(-> S SIG-COUNTER )\d+$")

# `OK <free-form comment>`. Stock puts stats in the trailing comment; we only
# really care about the OK itself, and scd-rs's comment differs by design.
OK_COMMENT = re.compile(r"^(-> OK)(\s+.*)?$")

# `ERR <code> <message>`. Codes are stable, free-form messages differ.
ERR_MESSAGE = re.compile(r"^(-> ERR \d+) .+$")

# `S PADDING <n>` — not all cards emit this; when present, only the value
# is stable so leave it alone, but listed here for completeness.

# `SETDATA [--append] <hex>` and similar commands whose payload varies per
# run (fresh digest / ciphertext each invocation).
SETDATA_PAYLOAD = re.compile(r"^(<- SETDATA(?: --append)?) [0-9A-Fa-f]{16,}$")

# Stock's debug-log rendering of a long D line:
#   `[ 44 20 ...bytes... (N byte(s) skipped) ]`
STOCK_BIG_D = re.compile(r"^-> \[ 44 20 .*\(\d+ byte\(s\) skipped\) \]$")

# An scd-rs `D <payload>` emission. Payloads longer than this or containing
# non-printable/non-space bytes are binary blobs we collapse into a count.
D_LINE_READABLE_LIMIT = 80
D_LINE = re.compile(r"^(-> |<- )D (.*)$", re.DOTALL)

# INQUIRE keywords that carry confidential material — the prompt text and
# the subsequent client response lines should be redacted.
CONFIDENTIAL_INQUIRE = re.compile(r"^-> INQUIRE (NEEDPIN|PASSPHRASE|PIN) ")

CONFIDENTIAL_PLACEHOLDER = "[[Confidential data not shown]]"
BINARY_PLACEHOLDER_FMT = "D <{n} byte payload>"


def is_printable_payload(s: str) -> bool:
    return all(0x20 <= ord(c) < 0x7F or c == "\t" for c in s)


def normalize_line(line: str, state: dict) -> str | None:
    """Return a normalized line, or None to drop the input entirely.

    `state` carries cross-line context (currently just whether the last
    emitted `INQUIRE` was confidential, so we can redact the client's
    D/END response lines that follow).
    """
    line = line.rstrip("\n")

    # Stage 1: strip the stock prefix if present. Keep everything after
    # `chan_9 ` (which will already begin with `<-` or `->`).
    stock = STOCK_PREFIX.match(line)
    if stock:
        line = line[stock.end() :]
    elif STOCK_NOISE.match(line):
        return None

    # Stock's debug-log `[ 44 20 ... skipped ]` rendering of a big D line.
    if STOCK_BIG_D.match(line):
        state["confidential_block"] = False
        return f"-> {BINARY_PLACEHOLDER_FMT.format(n='<N>')}"

    # Stock uses `[[Confidential data not shown]]` on its own for both
    # the INQUIRE prompt and the D/END responses.
    if "[[Confidential data not shown]]" in line:
        # Keep the direction marker, collapse to the placeholder so both
        # sides line up.
        marker = line[:3] if line[:3] in ("-> ", "<- ") else ""
        return f"{marker}{CONFIDENTIAL_PLACEHOLDER}"

    # At this point every line we keep should start with a direction marker.
    if not (line.startswith("<- ") or line.startswith("-> ")):
        return None

    # Stage 2: volatile-field placeholders.
    line = SIG_COUNTER.sub(r"\1<N>", line)
    line = OK_COMMENT.sub(r"\1", line)
    line = ERR_MESSAGE.sub(r"\1 <MSG>", line)
    line = SETDATA_PAYLOAD.sub(r"\1 <PAYLOAD>", line)

    # Stage 3: confidential INQUIRE + response redaction (stateful).
    if CONFIDENTIAL_INQUIRE.match(line):
        state["confidential_block"] = True
        return f"-> {CONFIDENTIAL_PLACEHOLDER}"
    if state.get("confidential_block"):
        if line.startswith("<- D ") or line == "<- END":
            if line == "<- END":
                state["confidential_block"] = False
            return f"<- {CONFIDENTIAL_PLACEHOLDER}"
        # Any other line ends the confidential window.
        state["confidential_block"] = False

    # Stage 4: collapse long or binary D-line payloads. We drop the exact
    # byte count because stock's and scd-rs's percent-escaping policies
    # differ, so the encoded lengths don't match even when the underlying
    # payload is the same shape.
    m = D_LINE.match(line)
    if m:
        prefix, payload = m.group(1), m.group(2)
        if len(payload) > D_LINE_READABLE_LIMIT or not is_printable_payload(payload):
            return f"{prefix}{BINARY_PLACEHOLDER_FMT.format(n='<N>')}"

    return line


def main() -> int:
    # Assuan traces legally contain non-UTF-8 bytes (raw `D` payloads, the
    # `S KDF \x81\x01\x00` DO wrapper, etc.). Read as latin-1 so every byte
    # maps to a codepoint without error, and write back the same way.
    in_stream = sys.stdin.buffer
    out_stream = sys.stdout.buffer
    state: dict = {}
    for raw in in_stream:
        line = raw.decode("latin-1")
        out = normalize_line(line, state)
        if out is not None:
            out_stream.write(out.encode("latin-1"))
            out_stream.write(b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
