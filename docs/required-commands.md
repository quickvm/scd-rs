# Required Assuan command surface

Derived from real traces of stock `scdaemon` 2.4.9 ↔ `gpg-agent` during
`gpg --card-status`, `gpg --clearsign`, and `gpg --decrypt` on a Nitrokey 3
(OpenPGP card application v3.4, RSA 4096 signing/encryption/authentication
subkeys). Source logs live in `docs/assuan-traces/`.

`gpg-agent` log output is empty because its `log-file` directive does not
capture `debug ipc` the way `scdaemon`'s does, but `scdaemon`'s log shows both
directions (`<-` from agent, `->` to agent) so it's sufficient.

## Observed Tier 1 commands

| Command                          | Used by                 | Handled by `scd-rs` MVP |
|----------------------------------|-------------------------|-------------------------|
| `GETINFO version`                | card-status             | yes (static reply)      |
| `SERIALNO`                       | card-status, decrypt    | yes                     |
| `SERIALNO --all`                 | clearsign, decrypt      | yes                     |
| `LEARN --force`                  | card-status             | yes (see status lines below) |
| `KEYINFO --list`                 | card-status, clearsign  | yes                     |
| `KEYINFO --list=encr`            | decrypt                 | yes                     |
| `KEYINFO <keygrip>`              | clearsign, decrypt      | yes                     |
| `GETATTR KEY-ATTR`               | card-status             | yes                     |
| `SETDATA <hex>`                  | clearsign, decrypt      | yes                     |
| `SETDATA --append <hex>`         | decrypt                 | yes (chunk continuation) |
| `PKSIGN --hash=<algo> <keygrip>` | clearsign               | yes                     |
| `PKDECRYPT <keygrip>`            | decrypt                 | yes                     |
| `RESTART`                        | all flows (session end) | yes (session reset, no disconnect) |

## Status lines `LEARN --force` must emit

Not all are load-bearing. The ones `gpg-agent` demonstrably uses downstream
(and therefore we must emit) are in **bold**.

- **`S READER <human-readable-reader-name>`**
- **`S SERIALNO <AID-hex>`**
- **`S APPTYPE openpgp`**
- **`S APPVERSION <bcd-version>`** (e.g. `304` for v3.4)
- `S EXTCAP <flags>` — advisory capability summary (`gc=…+ki=…+…`)
- `S MANUFACTURER <id> <name>`
- `S DISP-NAME <cardholder-name-escaped>`
- `S DISP-LANG <lang>`
- `S DISP-SEX <digit>`
- `S PUBKEY-URL <url>`
- **`S KEY-FPR <n> <fpr>`** — n ∈ {1,2,3} for sig/enc/auth
- `S KEY-TIME <n> <unix-ts>`
- **`S CHV-STATUS <flags>`** — PIN state (`+1+127+127+127+3+3+3`)
- `S SIG-COUNTER <n>`
- `S KDF <escaped-blob>`
- `S UIF-1 <blob>` / `S UIF-2 <blob>` / `S UIF-3 <blob>`
- **`S KEYPAIRINFO <keygrip> OPENPGP.<n> <usage> <create-ts> <algo>`** — one per key; `gpg-agent` keygrip-indexes future operations from this

The bold ones are the minimum we must emit for downstream commands to work.
The rest are safe to emit (we have the data) and cheap, so we should
reproduce them unless they cost real effort.

## `KEYINFO` response format

```
S KEYINFO <keygrip> T <AID> OPENPGP.<n> <usage>
OK
```

`T` = type (token/card-resident key). Usage codes: `sc` (sign+cert),
`e` (encrypt), `sa` (sign+auth). `--list` emits one line per key; `--list=encr`
filters to encryption-capable keys.

## `SETDATA` chunking

`gpg-agent` splits payloads larger than ~1000 chars across one `SETDATA` and
one or more `SETDATA --append` calls. The daemon must concatenate into a
per-session buffer and clear it after the next `PKSIGN` or `PKDECRYPT`.

## `PKSIGN` response

```
[ <signature-bytes-as-SCdaemon-D-format> ]
OK
```

Internally scdaemon's log uses `[ 44 20 6f 07 … (516 byte(s) skipped) ]` to
abbreviate; the wire format is `D ` plus hex-encoded bytes across multiple
lines as usual.

## `PKDECRYPT` response

Emits a `PADDING` status line before the data:

```
S PADDING 0
D <plaintext-hex>
OK
```

`PADDING 0` means the plaintext is already unpadded (card stripped PKCS#1
padding). `gpg-agent` relies on this hint.

## Error responses

```
ERR <code> <msg> <SCD>
```

Observed codes from our traces:

- `100663313 No secret key <SCD>` — wrong keygrip for PKDECRYPT
- `100663414 Invalid ID <SCD>` — non-decrypt keygrip used for PKDECRYPT

The anonymous-recipient retry loop in `gpg --decrypt` drives several of these
during the traces — `gpg-agent` tolerates them cleanly and continues trying
other keys, so our daemon must return them rather than raising a fatal state.

## Session lifecycle

`RESTART` at end of each logical workflow. The daemon must:

1. Clear the per-flow `SETDATA` buffer.
2. Keep the Unix socket connection open.
3. Reply `OK`.
4. Accept further commands on the same connection.

Card identity, cached `CardInfo`, keygrip map, the PIN cache, and the
optional pooled card handle all **survive** `RESTART`; gpg-agent treats
`RESTART` as a flow boundary, not a session end, so re-reading all of
that state would add several seconds of round-trips to every sign.

No PC/SC disconnect is required on `RESTART`; card access is per-
operation inside `scd-rs-card::with_pooled_card`, independent of the
Assuan session.

## Commands observed but NOT required

None in our traces outside the Tier 1 list. `LEARN` without `--force`,
`READKEY`, `READCERT`, `CHECKPIN`, admin commands (`PASSWD`, `GENKEY`, etc.)
didn't appear in these flows. They're deferred to the fast-follow scope.

## Nitrokey 3 specifics observed

- OpenPGP application v3.4
- RSA 4096 for all three subkeys
- KDF: disabled (`UIF setting ..: Sign=off Decrypt=off Auth=off`)
- Signature counter present (`SIG-COUNTER 1764`)
- Reader string: `Nitrokey Nitrokey 3 [CCID/ICCD Interface] 00 00`
- AID: `D276000124010304000FE9B8A8420000` (standard OpenPGP prefix + vendor + serial)
