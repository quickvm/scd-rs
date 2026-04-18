# scdaemon Rust Rewrite Plan

## Goal

Build a Rust replacement for `scdaemon` that is API-compatible enough for `gpg-agent` to use as a drop-in smartcard backend, while avoiding the long-lived PC/SC handle and shared-access design flaws that cause stale-card failures.

Use Sequoia's existing Rust OpenPGP card stack as the foundation instead of reimplementing OpenPGP card behavior from scratch.

The working target is:

- reliable OpenPGP card operations on Nitrokey 3 and YubiKey
- no persistent stale reader/card session state
- safe coexistence with other PC/SC clients
- enough Assuan compatibility for normal GnuPG signing, decryption, auth, and card-status flows

## Non-Goals For V1

- full feature parity with every historical `scdaemon` feature
- legacy serial/USB reader support outside PC/SC
- admin workflows beyond what is needed for common user operations
- an internal CCID stack
- S/MIME, PIV, PKCS#15, or vendor-specific applets

V1 should be intentionally narrow: OpenPGP card over PC/SC only.

## Problem Statement

The existing failure mode appears to come from the combination of:

- long-lived `scdaemon` process state
- cached reader/card handles
- weak recovery when another PC/SC client perturbs card state
- assumptions that exclusive access or persistent card identity remain valid across operations

The rewrite should treat PC/SC state as ephemeral, not durable.

## Foundation Choice

This project should be built on top of the existing Sequoia/OpenPGP card ecosystem:

- `openpgp-card`
- `openpgp-card-sequoia`
- `card-backend-pcsc`
- potentially `sequoia-keystore-openpgp-card`

That changes the implementation strategy:

- do not write a new OpenPGP card engine unless Sequoia is missing a required primitive
- do not write APDU parsing or OpenPGP application logic from scratch unless forced to
- focus custom work on daemonization, compatibility, retry semantics, pinentry integration, and GnuPG Assuan protocol behavior

The problem is no longer “how do we talk to OpenPGP cards in Rust?”

The problem is:

- how to wrap proven Rust card libraries in a `scdaemon`-compatible daemon
- how to ensure reconnect/transaction semantics remain safe under shared PC/SC use
- how to satisfy `gpg-agent` expectations well enough that the replacement is operationally viable

## Design Principles

1. Never trust a previously opened card handle.
2. Treat each card operation as a fresh transaction boundary.
3. Make recovery the normal path, not an exception path.
4. Keep per-card cached metadata soft and invalidatable.
5. Prefer statelessness over performance unless measurement proves otherwise.
6. Keep the compatibility layer thin and isolate card logic from Assuan protocol handling.

## High-Level Architecture

The project should be split into these crates:

### `scd-rs-assuan`

Implements the subset of the Assuan protocol needed to talk to `gpg-agent`.

Responsibilities:

- socket server
- command parsing
- status/error responses
- connection/session lifecycle
- compatibility shims for scdaemon command surface

### `scd-rs-core`

Card/application orchestration layer.

Responsibilities:

- command routing from Assuan to card operations
- card discovery
- reader selection
- operation policy
- PIN flow integration
- retry/reconnect policy

### `scd-rs-pcsc`

Thin integration layer around Sequoia's PC/SC-backed card access.

Responsibilities:

- wrap Sequoia/openpgp-card backend creation
- enforce reconnect/transaction policy at operation boundaries
- isolate backend-specific retry logic
- own the critical invariants that avoid stale handles

This should stay as small as possible. If Sequoia already exposes the right semantics, use them directly.

### `scd-rs-openpgp-card`

Adapter layer over Sequoia/OpenPGP card crates.

Responsibilities:

- map daemon operations onto Sequoia card APIs
- normalize card metadata into the daemon's internal model
- adapt Sequoia errors into daemon/Assuan errors
- keep Sequoia-specific usage contained

This layer should not duplicate protocol logic that Sequoia already owns.

### `scd-rs-pinentry`

Bridge to `pinentry` or an equivalent prompt helper.

Responsibilities:

- request user PIN securely
- cache policy hooks
- cancellation propagation

### `scd-rs-compat`

Compatibility and packaging layer.

Responsibilities:

- socket naming
- environment/config parsing
- `scdaemon-program` deployment path
- logging and metrics

## Core Transport Rules

These are the rules that matter most for avoiding the current bug class.

### 1. No long-lived `hCard`

Do not keep a connected card handle across unrelated operations. A handle may live only for the duration of a single logical card operation, even if the underlying library makes longer-lived objects convenient.

Examples:

- `SERIALNO`
- `LEARN`
- `PKSIGN`
- `PKDECRYPT`
- `GETATTR`

Each operation should:

1. establish or refresh PC/SC context
2. enumerate/select reader
3. connect to card
4. begin transaction
5. perform APDU sequence
6. end transaction
7. disconnect

### 2. Use `SCardBeginTransaction` / `SCardEndTransaction`

Every APDU sequence that assumes a stable card state must be wrapped in a PC/SC transaction, either directly by the backend or by verifying that Sequoia's path already gives us equivalent guarantees.

### 3. Revalidate reader/card identity every operation

Before executing an operation, confirm:

- reader still exists
- card still present
- ATR matches expected card if previous metadata exists
- selected application is still OpenPGP

If any check fails, discard cached state and reconnect from scratch.

### 4. Cache metadata, not transport handles

Allowed cache:

- last seen ATR
- card serial / AID
- card capabilities
- key fingerprints / touch policy metadata

Forbidden cache:

- raw PC/SC card handles
- open transaction assumptions
- selected-file/application state that cannot be cheaply re-established

### 5. Build for reconnect-first behavior

On these errors, automatically reconnect and retry once if the command is idempotent or safely restartable:

- `SCARD_E_NO_SMARTCARD`
- `SCARD_W_RESET_CARD`
- `SCARD_W_REMOVED_CARD`
- protocol reset / sharing violations
- card/application-not-selected conditions caused by reset

Operations with side effects should not blindly retry unless proven safe.

## Assuan Compatibility Strategy

Do not start by cloning all of `scdaemon`. Implement the minimal subset needed for GnuPG signing flows first.

Suggested command tiers:

### Tier 1

- `SERIALNO`
- `GETINFO`
- `GETATTR`
- `LEARN`
- `CHECKPIN`
- `PKSIGN`
- `PKDECRYPT`
- `PKAUTH`

### Tier 2

- card insertion/removal notifications
- key generation hooks
- admin commands used by `gpg --card-edit`

### Tier 3

- obscure legacy compatibility commands

Before coding, capture the real command set used by `gpg-agent` in your workflow with Assuan tracing.

Also capture the exact Sequoia flows needed to perform the same operations natively. That will tell us what the compatibility adapter must translate, and whether any required capability is missing in Sequoia's public APIs.

## Suggested Implementation Plan

### Phase 0: Research and Trace Capture

- capture real `gpg-agent <-> scdaemon` traffic for:
  - `gpg --card-status`
  - `echo test | gpg --clearsign`
  - git commit signing
  - decrypt
  - ssh auth if needed later
- document required Assuan commands and response shapes
- identify which scdaemon status lines `gpg-agent` depends on versus ignores

Deliverable:

- `docs/assuan-traces/`
- `docs/required-commands.md`

### Phase 1: Sequoia Transport Validation

- build a standalone Rust probe on top of:
  - `card-backend-pcsc`
  - `openpgp-card-sequoia`
- implement repeated card enumeration, status fetch, and sign flows
- enforce per-operation reopen/reconnect from our wrapper layer
- stress-test with concurrent external PC/SC clients
- prove no stale-handle behavior under:
  - reinsertion
  - reader reset
  - `pcscd` restart
  - concurrent `opensc-tool` / browser / other clients

Deliverable:

- `crates/scd-rs-pcsc`
- `cargo run -p sequoia-pcsc-probe`

Exit criteria:

- repeated sign/status probes survive conditions that currently poison `scdaemon`
- Sequoia backend behavior is confirmed suitable for daemon use

### Phase 2: Sequoia Adapter Layer

- implement a stable internal API over Sequoia card crates
- map:
  - card status
  - serial lookup
  - sign
  - decrypt
  - auth
  - PIN verify
- normalize recovery and retry behavior around Sequoia APIs
- fill small gaps with targeted extensions only if public APIs are insufficient

Deliverable:

- `crates/scd-rs-openpgp-card`
- test vectors against real Nitrokey 3

Exit criteria:

- native Rust CLI can perform sign and status reliably for your Nitrokey using Sequoia-backed card operations

### Phase 3: Assuan Daemon MVP

- implement Unix socket server
- implement Tier 1 commands
- make `gpg-agent.conf` `scdaemon-program` point to the Rust daemon
- run real `gpg --card-status` and `gpg --clearsign`

Deliverable:

- `crates/scd-rs-assuan`
- `crates/scd-rs-compat`

Exit criteria:

- real GnuPG operations work without stock `scdaemon`

### Phase 4: Hardening

- structured logs with card/session IDs
- integration tests across reconnect scenarios
- timeout tuning
- better error mapping from PC/SC to Assuan/GPG expectations
- pinentry integration polish

Exit criteria:

- daemon remains healthy across a full workday with concurrent desktop apps

### Phase 5: Broader Compatibility

- `gpg --card-edit` support
- optional SSH-related support if needed
- distro packaging
- migration docs

## Error Handling Model

Use typed errors with explicit layers:

- transport errors
- card protocol errors
- user interaction errors
- compatibility mapping errors

Never collapse everything into generic “Not supported”.

Every outward-facing error should preserve:

- originating layer
- original PC/SC code if present
- retryability
- whether reconnect was attempted

## Concurrency Model

Use a single-reader operation lock per physical card/reader pair.

Recommendations:

- internal async is fine, but card APDU execution should be serialized per reader
- support multiple clients, but only one active transaction per reader
- do not permit overlapping APDU flows on the same card handle

If multiple clients ask for the same reader concurrently:

- either queue operations
- or fail quickly with a retryable busy error

Be explicit. Hidden interleaving will recreate the same class of bugs.

## Observability

This project should be heavily instrumented from day one.

Add:

- structured logs
- transaction IDs
- reader name
- ATR
- PC/SC return codes
- reconnect count
- command latency

Optional:

- OpenTelemetry spans around Assuan command handling and APDU sequences

## Testing Strategy

### Unit Tests

- APDU parsing
- OpenPGP data object parsing
- Assuan command parsing
- error mapping

### Integration Tests

- mock Assuan client against daemon
- mock PC/SC transport
- card present / removed / reset scenarios

### Hardware-in-the-Loop Tests

Test at minimum on:

- Nitrokey 3
- YubiKey 5 OpenPGP

Scenarios:

- repeated `gpg --card-status`
- repeated signing
- card reinsertion during idle
- card reinsertion during active desktop app use
- `pcscd` restart
- another PC/SC client touching the card between operations

### Regression Harness

Build a soak test that runs for hours:

- repeated status
- repeated sign
- periodic external client interference
- forced reconnects

Success metric:

- no daemon restart needed

## Security Considerations

- zeroize PIN material in memory where practical
- avoid writing sensitive card state to disk
- strictly separate logging from sensitive APDU payloads
- support least-privilege runtime defaults
- keep IPC surface narrow

## Packaging and Adoption

### Initial Deployment

Deploy as an alternate daemon via:

```conf
scdaemon-program /path/to/scd-rs
```

This keeps rollback trivial.

### Packaging Targets

- Fedora COPR or RPM
- standalone tarball
- optional Nix package

### Migration Story

- stock `scdaemon` remains fallback
- one config toggle to switch back
- no key migration required

## Recommended Tech Stack

- Sequoia OpenPGP card crates as the default foundation
- `pcsc` crate or direct `pcsc-sys` only when Sequoia abstraction is insufficient
- `tokio` only if async meaningfully helps the server layer
- `thiserror` / `anyhow` split between library and binary boundaries
- `tracing` + `tracing-subscriber`
- `zeroize`
- `clap` for debug tools

Avoid premature framework complexity. The core of this project is correctness at the PC/SC transaction boundary and compatibility with `gpg-agent`, not rewriting card semantics that already exist in Sequoia.

## Immediate Next Steps

1. Create workspace skeleton with the crates above.
2. Capture Assuan traces from stock `scdaemon`.
3. Implement a Sequoia-backed probe that never reuses card handles across operations from our wrapper layer.
4. Prove the probe survives the exact failure modes that currently break your Nitrokey workflow.
5. Only then start the Assuan compatibility layer.

## Decision Summary

The rewrite should not be “scdaemon in Rust” and it definitely should not be “OpenPGP card logic rewritten from scratch in Rust”. It should be a narrower, transaction-safe OpenPGP card daemon that reuses Sequoia's existing Rust card stack and adds a compatibility shell around it. The fastest path to success is to solve your real problem first: reliable card operations under shared PC/SC conditions. Full feature parity can come later.
