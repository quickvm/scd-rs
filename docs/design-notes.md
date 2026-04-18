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
