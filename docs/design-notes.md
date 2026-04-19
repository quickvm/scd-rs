# Design notes

Running log of architectural choices as the rewrite progresses. Each entry
records the decision and the evidence it's based on so we can revisit later.

## Phase 1 — transport layer

### Ephemeral PC/SC handles work through `openpgp-card-sequoia`

Confirmed. The Sequoia wrapper's `Card<Open>` → `Card<Transaction>` chain
releases its underlying PC/SC handle cleanly when dropped. Recreating the
full chain per operation (`PcscBackend::card_backends` → `Card::<Open>::new`
or `open_by_ident` → `card.transaction`) is the correct discipline for our
daemon.

**Evidence:** `scd-rs-probe loop --count 100 --delay-ms 20` against a
Nitrokey 3 with concurrent `opensc-tool --list-readers` hitting the PC/SC
layer every 3 seconds: 100/100 iterations passed, 0 failures, 150.93s
elapsed. Same workload kills stock scdaemon on this box within a handful
of operations.

### Pin to `openpgp-card-sequoia` 0.2.2's dependency graph

We imported `openpgp-card-sequoia` and let it pull in its preferred
`openpgp-card 0.4.2`. Dropping our direct dependency on `openpgp-card 0.6.1`
avoids the duplicate-version breakage (two `KeyType` and `StatusBytes`
enums coexisting in the graph, neither assignable to the other).

**How to apply:** use `openpgp_card_sequoia::{state, types, Card}` for all
card-facing types; do not depend on `openpgp-card` directly unless we
later need something the wrapper does not expose. When `openpgp-card-sequoia`
releases a version targeting `openpgp-card 0.6.x`, we reconsider.

### Keygrip computation deferred to Phase 2

Sequoia 1.22's `Key<PublicParts>` does not expose a `keygrip()` method. The
GnuPG keygrip is SHA-1 of a canonical S-expression of the public key MPIs —
straightforward but not needed until we start emitting `S KEYPAIRINFO`
lines in the Assuan layer. `KeyInfo.keygrip` is left as `Option<String>` and
returns `None` for now.

**How to apply:** before Phase 3 can produce a real `S KEYPAIRINFO` line
matching stock scdaemon's output, we must implement keygrip derivation
for RSA, EdDSA, and ECDH/ECDSA public keys. Validate against the keygrips
observed in `docs/assuan-traces/`.

### AID format translation

`gpg-agent` uses the full 32-hex-char AID (`D276000124010304000FE9B8A8420000`)
everywhere in its Assuan traffic. `openpgp_card_sequoia::Card::open_by_ident`
and its internal `application_id.ident()` use the short `MANUF:SERIAL` form
(`000F:E9B8A842`). We keep the full form in our public API and translate
at the Sequoia boundary.

**How to apply:** every ident that crosses the Assuan surface is the full
form; every ident passed to Sequoia is the short form. `scd_rs_card`
owns the translation.

### pcscd-restart stress: probe recovers between restarts, USB eventually wedges

Ran `PCSCD_RESTART=1 tests/soak/stress.sh --count 300 --delay-ms 25`
(restart pcscd every 30s + `opensc-tool --list-readers` every 3s). Final
tally: **61/300 iterations succeeded, 239 failed, 3430s elapsed**.

Crucially, the failure mode was **not** stale handles. Every failed
iteration returned a clean error within ~20s, classified correctly:
retryable (`Transmit failed: CommError`, `SCARD_E_NO_SMARTCARD`) or
fatal (`Couldn't find card 000F:E9B8A842`). The probe never hung, never
cached state, never required a kill to recover. Whenever pcscd got a
stable window, iterations succeeded.

Over ~57 minutes of thrashing, the Nitrokey 3's CCID/USB state
eventually wedged: `lsusb` still showed the device, pcscd still
enumerated the reader, but `opensc-tool --atr` returned "Card not
present" and `pcsc_scan` returned "SCardEstablishContext: Access
denied". A full physical unplug of the Nitrokey cleared it.

This is a real-world hardware/stack limit, not a bug in our code. Stock
scdaemon would behave worse in the same scenario — it would silently
hold the stale handle and require `gpgconf --kill scdaemon`.

**What this tells us:**

- Per-operation handle discipline works. When the PC/SC layer is
  healthy, operations succeed. When it's unhealthy, operations fail
  visibly and the daemon stays ready to recover.
- The 61 successful iterations happened during the gaps between pcscd
  restarts — evidence that reconnect works once pcscd is back up.
- Retry-once logic in the daemon will turn the transient `CommError`
  class of failures into silent auto-recovery for clients. Scoped for
  Phase 2/3, along with error → Assuan error mapping.
- Realistic pcscd restart cadence is hours-to-days, not every 30s.
  The more representative long-running stress scenario is the one we
  already passed clean: sustained `opensc-tool --list-readers`
  concurrency (100/100 iterations), which exercises shared-access
  contention without wedging the USB stack.

### Remaining Phase 1 stress scenario: card removal mid-loop

Still needs a human pulling and reinserting the card during a running
probe. Covered in the script via prompt, not yet executed.

## Phase 3 — Assuan compatibility

### `gpg-agent` pads the PIN with trailing NULLs

gpg-agent allocates a 257-byte `gcry_malloc_secure` buffer for the PIN,
writes the user input, NULL-terminates, and then sends the whole buffer
on the Assuan wire. Our probe received 90 bytes for an 8-character PIN:
the 8 ASCII bytes followed by 82 trailing NULLs. Passing that padded
slice to `verify_pw1_sign` makes the card reject it as a 90-char PIN
and burn a retry.

Stock scdaemon handles this implicitly via C-string semantics — it
receives the bytes into a `char*`, and subsequent `strlen` / `strcpy`
calls truncate at the first NULL. We have to truncate explicitly.

**How to apply:** `pinentry::request_pin` treats the INQUIRE NEEDPIN
response as a C string — truncate at the first NULL byte before wrapping
in `SecretBox`. This matches libgcrypt's convention and is what the card
actually wants.

### RSA keygrip format

For RSA keys, libgcrypt feeds the modulus `n` through
`gcry_sexp_build("(n %m)", mpi)` using the `GCRYMPI_FMT_STD` MPI
serialization, which emits unsigned big-endian bytes with a leading
`0x00` prepended whenever the magnitude's high bit is set. The keygrip
is SHA-1 of that byte sequence, not of the stripped magnitude. We
verified byte-for-byte against the three keygrips captured in Phase 0.

Keygrip for EdDSA, ECDH, and ECDSA keys is deferred — not needed for
the user's RSA-4096 card.

### PIN cache design

One cache per Assuan session, TTL matching gpg-agent's
`default-cache-ttl` (600s). Mode-agnostic: OpenPGP cards verify PW1
mode 81 (signing) and mode 82 (user/decrypt) against the same PIN
bytes, so one cache entry serves both paths and a clearsign primes the
PIN for a subsequent decrypt.

`CommandHandler::reset_session` clears only the SETDATA buffer. Card
identity, keygrip map, `CardInfo`, and the PIN all survive `RESTART`
because `RESTART` is a per-flow boundary in gpg-agent's protocol, not a
session termination.

### Performance of the sign path

With the CardInfo cache + SERIALNO short-circuit, a repeat
`gpg --clearsign` breaks down as:

| Phase                               | Time    | Source                         |
|-------------------------------------|---------|--------------------------------|
| PC/SC `EstablishContext` + enumerate| 40 ms   | `PcscBackend::card_backends`   |
| `Card::new` (SELECT + read ARD)     | 500 ms  | `openpgp_card::Card::new`      |
| `verify_pw1_sign`                   | 600 ms  | verify APDU + round-trip       |
| `pso_compute_digital_signature`     | 1600 ms | Nitrokey 3 RSA-4096 silicon    |
| Assuan round-trips / overhead       | ~50 ms  | gpg-agent <-> scd-rs           |
| **Total**                           | **~2.8 s** |                            |

1.6s of the total is the Nitrokey's own RSA math — not improvable in
software. The remaining ~1.1s is the cost of our per-operation handle
discipline. A future **short-TTL card-handle pool** (hold the card
handle for N seconds after a successful op, reuse in that window) would
let rapid back-to-back signs drop to ~1.6s each. Tradeoff: reintroduces
a bounded stale-handle surface area for the TTL window. Worth
benchmarking and choosing a conservative TTL (e.g. 2–5s) before shipping.

### gpg-agent quirks that surfaced during cutover

These were all found by enabling `--log-file` and observing the live
command stream:

- `OPTION event-signal=<n>` — sent immediately after connect; we accept
  and ignore.
- `GETATTR $ENCRKEYID` / `GETATTR $SIGNKEYID` / `GETATTR $AUTHKEYID` —
  dollar-prefixed "private" attributes stock scdaemon emits as status
  lines during LEARN. `gpg-agent` later queries them via GETATTR for
  its own bookkeeping. We return NOT_SUPPORTED for these; gpg-agent
  tolerates the ERR and continues.
- `READKEY -- $<name>` — same family; gpg-agent pokes but doesn't fail
  when it's unsupported.
- gpg-agent sends `GETINFO version` and compares to its own version
  string. Returning `"2.4.9 (scd-rs 0.1.0)"` passes the "older than us"
  check while keeping the scd-rs tag visible in logs.

## Phase 4 — production hardening

### Trace diff vs stock scdaemon: zero load-bearing differences

Formal wire-level comparison across `card-status`, `clearsign`, and
`decrypt` workflows (`docs/assuan-traces/*.diff` + `.diff.notes.md`).
Every delta classified Intentional (version tag, reader name),
Advisory (`EXTCAP`, `DISP-SEX`, `KDF`, `UIF-*` — gpg-agent doesn't
read them), or Ordering (interleaved vs batched `KEY-FPR`/`KEY-TIME`
in LEARN — gpg-agent accumulates into state either way). Nothing
gpg-agent acts on is missing.

Generation is scripted: `scripts/capture-traces.sh` (stock),
`scripts/capture-scdrs-traces.sh` (scd-rs, via a new `--trace-file`
wire tap on `Connection`), and `scripts/normalize-trace.py` (strips
timestamps, redacts `[[Confidential data not shown]]` for NEEDPIN
prompts + responses, collapses volatile fields like `SIG-COUNTER` and
random ciphertexts). Reproducible on any hardware with a card.

The `--trace-file` tap redacts PIN bytes via a
`trace_confidential: bool` flag on `Connection` that wraps the whole
`inquire()` round when the keyword is NEEDPIN/PASSPHRASE/PIN. Covered
by `trace_redacts_confidential_inquire` test — without it the raw
trace would leak the user's card PIN.

### Moved off `openpgp-card-sequoia` onto `openpgp-card 0.6`

`openpgp-card-sequoia 0.2.2` pinned us to `openpgp-card 0.4.2`.
Dropping the wrapper and going directly to `openpgp-card 0.6.1`
removed ~1250 lines from `Cargo.lock` (sequoia-openpgp, nettle, and
their transitive deps fall out of the graph entirely). API adaptation
is mechanical — 0.6's `Card<Transaction>` state machine replaces the
role `openpgp-card-sequoia` previously played.

**No `read_card_info` perf improvement.** The plan (notes/02) targeted
~1 s by dropping the wrapper, on the theory that Sequoia was doing
the redundant ARD re-reads. Hardware measurement showed the re-reads
live in `openpgp-card` itself — `ocard::keys::public_key` has a
`// FIXME: caching` that re-fetches ARD on every per-slot pubkey
read, byte-identical in 0.4.2 and 0.6.1. Cold `read_card_info` stays
at ~3.6 s until that FIXME lands upstream. The dep cleanup is the
real win.

### Sliding PIN TTL with `SCD_RS_PIN_TTL`

`CachedPin::expires_at` now resets on each successful cache hit, so
an all-day coding session with `SCD_RS_PIN_TTL=8h` keeps the PIN
alive as long as card activity continues, expires 8 h after the last
op otherwise. TTL=0 disables the cache entirely (every sign/decrypt
re-prompts). Format is the shared `<n><unit>` parser in
`crate::duration_str` — `30s`/`10m`/`1h`/`2d`.

### Card-handle pool (`SCD_RS_CARD_POOL_TTL`)

Opt-in pool holding one warm `Card<Open>` across ops. Each op still
starts its own PC/SC transaction (pcsc-shared semantics preserved);
the `Card<Open>` / SCardConnect is the part that gets reused.

Two-phase win on pool hit:
1. Skip `Card::<Open>::new` (SELECT + ARD): ~500 ms saved.
2. Skip `verify_pw1_sign` when the card's `pw1_cds_valid_once` flag
   is false (Nitrokey default) and the pool has `pw1_sign_fresh`
   set: ~600 ms saved. Same logic for PW1 mode 82 which is always
   multi-op per spec.

Measured on Nitrokey 3: repeat sign 3.5 s → 2.0 s (41% faster). The
remaining ~2 s is the upstream ARD-re-read (~0.5 s) plus the card's
RSA-4096 silicon (~1.6 s). If the FIXME lands upstream, warm sign
should drop to ~1.5 s.

Safety net: if the skip-verify attempt fails with any non-retryable
card error, the freshness flag is cleared and the op retries with an
explicit verify on the same handle. Handles the edge case where
another PC/SC tenant momentarily claimed the card or the card reset
itself mid-TTL.

### Pre-existing Nitrokey firmware bug: fixed by vendor v1.8.3

During Phase 4 trace-diff work, `gpg --decrypt` failed against the
author's Nitrokey 3 (`v1.8.1` firmware) with card status word
`0x6A80` ("Incorrect parameters in command data field"). The same
ciphertext had decrypted cleanly in Phase 0. Diagnosis ruled out
scd-rs, stock scdaemon, and keyring/card desync — fingerprint +
keygrip matched on both sides, PSO:DECIPHER data field was correctly
formed (1-byte RSA padding indicator + 512-byte modulus-sized
ciphertext). The card itself was rejecting properly-formed
RSA-4096 ciphertexts.

Upgrading the Nitrokey to firmware v1.8.3 (`nitropy nk3 update`)
resolved the issue. Neither v1.8.2 nor v1.8.3 call out an RSA
PSO:DECIPHER fix in their changelogs, but the OpenPGP applet was
touched in both. Filed here rather than in the trace-diff notes
because it's a hardware/firmware fact, not a daemon fact.

### scdaemon error constants cleanup

Three of the original five error constants (`NOT_SUPPORTED`,
`INV_ARG`, `NO_CARD`) had values that didn't match their
libgpg-error names — they encoded `GPG_ERR_TOO_LARGE` (67),
`GPG_ERR_UNUSABLE_PUBKEY` (53), and `GPG_ERR_INV_OBJ` (65)
respectively. gpg-agent was tolerant of the mismatch so nothing
broke, but the semantic/wire-code split was a trap. Renumbered to
match names (60 / 45 / 112). `NO_CARD` becoming the canonical
`GPG_ERR_CARD_NOT_PRESENT` enables gpg-agent's "please insert the
card" prompt on missing-card paths.

Also added `INV_ID` (118) during the trace-diff work, which stock
scdaemon uses for "keygrip is on the card but the wrong usage for
this op" (asking the signing key to decrypt). Previously we returned
the misnamed `INV_ARG` for this case.

