# scd-rs

A Rust replacement for GnuPG's `scdaemon` targeting OpenPGP smartcards.
Drop-in compatible with `gpg-agent` via the Assuan protocol.

Built to fix a long-standing class of stale-handle bugs that stock
`scdaemon` hits under shared PC/SC access: when another PC/SC client
(browser auth, PIV tooling, `opensc-tool`, etc.) touches the card in
parallel, stock scdaemon ends up holding a dead handle and requires a
manual `gpgconf --kill scdaemon` to recover. `scd-rs` enforces
per-operation PC/SC handle discipline by default, so every card
interaction opens a fresh context and releases it on return.

Background on the upstream pain this addresses:

- [GnuPG and PC/SC conflicts, episode 3](https://blog.apdu.fr/posts/2024/12/gnupg-and-pcsc-conflicts-episode-3/).
  PC/SC maintainer Ludovic Rousseau walks through exactly how
  scdaemon's `SCARD_SHARE_EXCLUSIVE`-by-default posture breaks shared
  access and why `pcsc-shared` is only a partial fix.
- [GnuPG T7291](https://dev.gnupg.org/T7291): "scdaemon randomly
  hangs when trying to access a token."
- [GnuPG T2053](https://dev.gnupg.org/T2053): "scdaemon over pcsclite
  holds the card even with `--card-timeout 5`."

## Status

We got fed up with the state of smartcard bugs in `scdaemon`. Having to kick the
daemon at random every time it deadlocked pushed us here at QuickVM past the
limit of our sanity, so we decided to burn a bunch of our time and AI tokens to
rewrite `scdaemon` in Rust.

Yeah, yeah, we know. A vibe-coded project that sits in your cryptographic
critical path. We don't care. Upstream bug fixes on `scdaemon` aren't happening
and the brittleness of the whole toolchain hit a breaking point for us. It fixes
our pain, and we're open-sourcing it in the hope that it spares other Nitrokey 
(and maybe Yubikey, untested!) users from yet more RSI typing their PIN every 
time they want to sign a git commit.

That said, use this at _your_ own risk.

All three canonical workflows (`gpg --card-status`, `gpg --clearsign`,
`gpg --decrypt`) are validated against stock scdaemon via a formal Assuan-wire
trace diff (see `docs/assuan-traces/`) with zero load-bearing differences.

**Supported hardware:** Nitrokey 3 (primary test device) and YubiKey
4/5. Unknown vendor IDs render as raw hex; no speculative support for
other vendors.

**Key/algorithm support:** RSA-4096 is the primary tested path (the
author's card). ECC paths are wired but not hardware-validated.

## Quickstart

### 1. Install

```bash
cargo install --git https://github.com/quickvm/scd-rs scd-rs
```

Installs `scd-rs` and `scd-rs-probe` into `~/.cargo/bin`.

### 2. Point `gpg-agent` at it

Edit `~/.gnupg/gpg-agent.conf` and add one line:

```
# ~/.gnupg/gpg-agent.conf
scdaemon-program /home/<you>/.cargo/bin/scd-rs
```

(Or substitute wherever your cargo bin lives; `which scd-rs` if unsure.)

### 3. Configure via environment variables

`scdaemon-program` in `gpg-agent.conf` takes a path and nothing else,
so scd-rs reads its configuration from the environment. gpg-agent
inherits its environment from whatever launches it (your shell, the
systemd user session, etc.), so export the vars somewhere `gpg-agent`
will see them.

For an interactive shell setup, e.g. in `~/.bashrc` / `~/.zshrc`:

```bash
export SCD_RS_LOG=$HOME/.gnupg/scd-rs.log   # optional; else logs to stderr
export SCD_RS_PIN_TTL=8h                     # PIN cache TTL (default 10m)
export SCD_RS_CARD_POOL_TTL=5s               # handle-pool TTL (default 0=off)
```

For a systemd user session, drop equivalent lines into
`~/.config/environment.d/scd-rs.conf`:

```
SCD_RS_LOG=%h/.gnupg/scd-rs.log
SCD_RS_PIN_TTL=8h
SCD_RS_CARD_POOL_TTL=5s
```

### 4. Kick gpg-agent

```bash
gpgconf --kill scdaemon gpg-agent
```

Next `gpg` operation spawns `scd-rs` fresh and picks up the new config.

Confirm via your usual smoke test:

```bash
gpg --card-status
echo test | gpg --clearsign
```

## Configuration

All tuning is via environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `SCD_RS_LOG` | none | Path to append structured logs. Falls back to stderr. |
| `SCD_RS_PIN_TTL` | `10m` | In-process PIN cache TTL. Sliding window, each successful use resets the clock. `0` disables the cache and re-prompts pinentry every operation. Accepts `30s` / `10m` / `1h` / `2d`. |
| `SCD_RS_CARD_POOL_TTL` | `0` (off) | How long to hold a PC/SC handle warm across operations. When enabled, back-to-back signs skip the ~500 ms re-open and, when the card's `pw1_cds_valid_once` flag is false (Nitrokey default), the ~600 ms PW1 verify. Start with `5s`. |
| `SCD_RS_TRACE` via `--trace-file` | none | Tee every Assuan line to a file with `<- ` / `-> ` direction markers. Only meaningful when debugging scd-rs vs gpg-agent protocol questions. |

### How the two caches stack

`SCD_RS_PIN_TTL` and `SCD_RS_CARD_POOL_TTL` operate at different
layers. The PIN cache is a **human-facing** cache: it skips the
pinentry popup and the `INQUIRE NEEDPIN` round-trip by supplying PIN
bytes scd-rs already has in memory. The card-handle pool is a
**hardware-facing** cache: it skips the `Card::<Open>::new` APDUs
(SELECT + ARD, ~500 ms) and, when the card permits multi-op PW1, the
`VERIFY PW1` APDU (~600 ms).

What each combination removes from a sign/decrypt:

| `SCD_RS_PIN_TTL` | `SCD_RS_CARD_POOL_TTL` | pinentry popup | card SELECT + ARD | VERIFY PW1 APDU | PSO APDU |
|---|---|---|---|---|---|
| `0`   | `0`  | runs       | runs              | runs                      | runs |
| `10m` | `0`  | **skipped** | runs              | runs                      | runs |
| `0`   | `5s` | runs       | **skipped** (warm) | **skipped** (card permits) | runs |
| `10m` | `5s` | **skipped** | **skipped** (warm) | **skipped** (card permits) | runs |

The PSO operation itself (RSA on the card's crypto core) is always
paid, it's the only thing that actually signs or decrypts. Everything
else is overhead, and with both caches warm on back-to-back signs all
of it drops out.

### PIN cache

The PIN cache is per Assuan connection (i.e. per gpg-agent ↔ scd-rs
session, usually lifetime of gpg-agent). PIN bytes are wrapped in
`secrecy::SecretBox` while stored, and cleared on any `BadPin` response
from the card.

### Card-handle pool

Opt-in via `SCD_RS_CARD_POOL_TTL`. The pool holds at most one
`Card<Open>` (the PC/SC connection) across operations. Each operation
still starts its own PC/SC transaction, so other tenants on a shared
reader continue to interleave per `pcsc-shared` semantics.

Invalidation:
- TTL expiry or wrong ident → pool dropped, next op opens fresh.
- PC/SC / card-reset errors → pool dropped, op retried once on a fresh
  handle.
- `BadPin` or `InvalidID` → pool dropped, error propagated.
- `SERIALNO` resolving a different card → pool dropped.
- `RESTART` (gpg-agent flow boundary) → pool **preserved** by design.

The pool's `skip_verify` optimization only activates when the card
advertises multi-op PW1 signing (Nitrokey default). YubiKeys with
factory-default "PIN valid once" configuration still re-verify each
sign and just save the re-open overhead.

### Performance (Nitrokey 3, RSA-4096)

| Operation | No pool | `SCD_RS_CARD_POOL_TTL=5s` hit |
|---|---|---|
| `gpg --clearsign` (first / cold) | ~3.5 s | ~3.5 s (first establishes the pool) |
| Subsequent sign inside TTL | ~3.5 s | ~2.0 s |

The remaining 2.0 s is upstream-gated: ~0.5 s is `Card<Transaction>::new`
re-reading ARD (an upstream `// FIXME: caching` in
`openpgp-card::ocard::keys::public_key`), and ~1.6 s is the card silicon
doing the actual RSA-4096 modular exponentiation.

## Architecture

Three crates:

```
crates/
├── scd-rs-card       OpenPGP card layer (openpgp-card 0.6, PC/SC via card-backend-pcsc)
├── scd-rs-assuan     Assuan protocol server (hand-rolled; no maintained Rust Assuan crate)
└── scd-rs            Daemon + probe binaries
    ├── bin/scd-rs         the daemon gpg-agent talks to
    └── bin/scd-rs-probe   hardware validation harness (enumerate / info / loop)
```

`scd-rs-card` is the only code that holds card handles. Every other
layer calls into it via a `&mut Option<PooledCard>` plumbed through
`Session`. `scd-rs-assuan` is framing + dispatch; it knows nothing about
card state. The `scd-rs` crate binds the two.

### Handle discipline

`scd-rs-card::with_pooled_card` is the single entry point. It takes an
optional pool and either reuses a warm handle or opens fresh, runs the
closure, and either re-pools the handle or drops it based on outcome.
There is exactly one place in the crate that calls `Card::<Open>::new`
(the fresh-path helper), by design.

### Session state

`scd_rs::state::Session` carries all per-connection state:

- `current_ident`: last resolved card AID
- `cached_info`: `CardInfo` snapshot (populated lazily, survives RESTART)
- `known_keys`: keygrip to usage map derived from `cached_info`
- `setdata`: buffered payload from `SETDATA` / `SETDATA --append`
- `cached_pin`: sliding-window PIN cache
- `card_pool`: optional `PooledCard` when pooling is enabled

`RESTART` clears only `setdata`. Card identity, keygrip map, `CardInfo`,
PIN, and pool all survive, matching gpg-agent's expectation that
`RESTART` is a per-flow boundary, not a session termination.

## Development

### Build & test

```bash
cargo test --workspace              # unit + integration tests, no hardware
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release
```

### Running a local build against gpg-agent

If you're iterating on scd-rs itself and want gpg-agent to invoke your
working-tree `target/release/scd-rs` with sensible env-var defaults
set, point `scdaemon-program` at the development wrapper from a clone
of the repo:

```
# ~/.gnupg/gpg-agent.conf (development only)
scdaemon-program /path/to/scd-rs/scripts/scd-rs-debug.sh
```

The wrapper resolves the binary relative to its own location and
defaults `SCD_RS_LOG=/tmp/scd-rs.log`, `SCD_RS_PIN_TTL=10m`, and
`SCD_RS_CARD_POOL_TTL=5s`. Override by exporting before kicking
gpg-agent. Not intended for end-user installs.

### Hardware-in-the-loop probe

```bash
# Enumerate readers
./target/release/scd-rs-probe serial

# Full CardInfo dump
./target/release/scd-rs-probe info --ident <AID>

# Loop (alternates enumerate + read_card_info); respects SCD_RS_CARD_POOL_TTL
./target/release/scd-rs-probe loop --count 50 --ident <AID>
```

### Soak test

`tests/soak/stress.sh` exercises the probe against real hardware under
concurrent `opensc-tool` load (the scenario that kills stock scdaemon).
Needs a card inserted and PC/SC daemon running.

### Assuan trace diff vs stock scdaemon

Trace captures are **local-only** (the entire `docs/assuan-traces/`
directory is gitignored). They carry identifying card metadata (AID,
cardholder name, public-key fingerprints, random ciphertext/signature
bytes) so they're kept per-developer. Regenerate them on demand:

```bash
# Requires an OpenPGP card inserted with usable signing + encryption
# subkeys. Will prompt via pinentry.

# 1. Capture stock scdaemon's wire traffic (temporarily neutralizes any
# `scdaemon-program` override in gpg-agent.conf, kicks the daemons,
# runs `gpg --card-status`, `gpg --clearsign`, `gpg --decrypt`, and
# writes {card-status,clearsign,decrypt}.{scdaemon,gpg-agent}.log
# under docs/assuan-traces/).
./scripts/capture-traces.sh

# 2. Same three workflows against scd-rs via `--trace-file`. Produces
# scdrs-{card-status,clearsign,decrypt}.log in the same directory.
./scripts/capture-scdrs-traces.sh
```

Both scripts restore the original gpg-agent.conf on exit and are
idempotent against rerun.

The normalizer strips timestamps, the stock `chan_9` channel prefix,
and the `<date> scdaemon[pid] DBG:` log headers; redacts
`INQUIRE NEEDPIN` prompts and their client D/END response lines as
`[[Confidential data not shown]]`; and collapses volatile fields
(signature counters, OK comment strings, ERR messages, large SETDATA
payloads, and binary D lines) to placeholders so two runs diff
cleanly.

Diff the two sides:

```bash
for w in card-status clearsign decrypt; do
    python3 scripts/normalize-trace.py <docs/assuan-traces/$w.scdaemon.log \
        >/tmp/$w.stock.norm
    python3 scripts/normalize-trace.py <docs/assuan-traces/scdrs-$w.log \
        >/tmp/$w.scdrs.norm
    diff -au /tmp/$w.stock.norm /tmp/$w.scdrs.norm \
        >docs/assuan-traces/$w.diff || true
done
```

Review each `.diff` and classify deltas into Load-bearing (stock
emits, gpg-agent depends on), Advisory (stock emits, gpg-agent
tolerates missing), or Intentional (scd-rs emits something distinct
and known). The design goal is zero Load-bearing deltas; the current
workspace ships with that achieved against Nitrokey 3.

### Building inside a container (mirrors CI)

```bash
podman build -t scd-rs-agent:test -f Containerfile.test .
podman run --rm -v "$PWD:/src:z" -w /src scd-rs-agent:test cargo test --workspace
```

CI runs these same commands; see `.buildkite/pipeline.yml`.

## License

MIT. See [LICENSE](LICENSE).

## Related

- [`openpgp-card`](https://codeberg.org/openpgp-card/openpgp-card):
  the underlying card-access library. scd-rs uses 0.6.
- GnuPG's [`scdaemon`](https://www.gnupg.org/documentation/manuals/gnupg/Smart-Card-Daemon.html):
  the C implementation this replaces for a narrow set of workflows.
