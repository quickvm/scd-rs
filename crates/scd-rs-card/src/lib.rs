//! `OpenPGP` card access for `scd-rs`.
//!
//! Enforces per-operation PC/SC handle discipline: every externally visible
//! operation opens a fresh `PcscBackend` → `Card` → `Transaction` chain and
//! drops it before returning. Nothing in this crate is permitted to retain a
//! card handle across calls.
//!
//! Uses the `openpgp-card` 0.6 `Card<Transaction>` state machine. That layer
//! caches a single `ApplicationRelatedData` read for the lifetime of the
//! transaction, so fingerprints / PW status / algorithm attributes /
//! key-generation times all come out of one APDU. Per-slot public-key reads
//! still cost two APDUs each (the upstream `ocard::keys::public_key` has a
//! standing `FIXME: caching` that re-fetches ARD before parsing the pubkey
//! response, same story in 0.4 and 0.6).

use std::fmt;
use std::time::{Duration, Instant};

use card_backend::CardBackend;
use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::algorithm::AlgorithmAttributes;
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime, KeySet};
use openpgp_card::ocard::{KeyType, StatusBytes};
use openpgp_card::state::{Open, Transaction};
use openpgp_card::{Card, Error as OcError};
use secrecy::SecretBox;
use thiserror::Error;
use tracing::{debug, instrument};

mod keygrip;

pub use keygrip::{format_hex, rsa_keygrip};

/// Card application identifier in uppercase hex form, e.g.
/// `D276000124010304000FE9B8A8420000`. This matches the format `gpg-agent`
/// uses for `SERIALNO` responses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardIdent(pub String);

impl fmt::Display for CardIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CardIdent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Which of the three `OpenPGP` card subkeys a `KeyInfo` refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsage {
    /// `OPENPGP.1` — signing + certification.
    Signing,
    /// `OPENPGP.2` — decryption.
    Decryption,
    /// `OPENPGP.3` — authentication.
    Authentication,
}

impl KeyUsage {
    #[must_use]
    pub const fn openpgp_slot(self) -> u8 {
        match self {
            Self::Signing => 1,
            Self::Decryption => 2,
            Self::Authentication => 3,
        }
    }

    /// Usage flags as written in scdaemon `KEYPAIRINFO` status lines.
    #[must_use]
    pub const fn scd_usage(self) -> &'static str {
        match self {
            Self::Signing => "sc",
            Self::Decryption => "e",
            Self::Authentication => "sa",
        }
    }

    const fn key_type(self) -> KeyType {
        match self {
            Self::Signing => KeyType::Signing,
            Self::Decryption => KeyType::Decryption,
            Self::Authentication => KeyType::Authentication,
        }
    }

    fn pick_from_key_set<T>(self, set: &KeySet<T>) -> Option<&T> {
        match self {
            Self::Signing => set.signature(),
            Self::Decryption => set.decryption(),
            Self::Authentication => set.authentication(),
        }
    }
}

/// Metadata for one of the three `OpenPGP` subkeys on the card.
///
/// `keygrip` is not populated in Phase 1 — see `docs/design-notes.md`.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub usage: KeyUsage,
    pub keygrip: Option<String>,
    /// 40-char uppercase hex fingerprint, or `None` if the slot is empty.
    pub fingerprint: Option<String>,
    /// Unix timestamp of key creation, or `None` if the slot is empty.
    pub created: Option<u32>,
    /// Algorithm as the card reports it (e.g. `"rsa4096"`, `"ed25519"`).
    pub algorithm: Option<String>,
}

/// PIN / CHV state derived from the card's PW status bytes.
#[derive(Debug, Clone, Copy)]
pub struct ChvStatus {
    /// Signing PIN valid for more than one signature?
    pub signing_pin_multi_op: bool,
    pub pw1_max_len: u8,
    pub rc_max_len: u8,
    pub pw3_max_len: u8,
    pub pw1_retries: u8,
    pub rc_retries: u8,
    pub pw3_retries: u8,
}

/// Full card snapshot — everything needed to answer `LEARN --force`.
#[derive(Debug, Clone)]
pub struct CardInfo {
    pub ident: CardIdent,
    pub app: u8,
    pub app_version_bcd: u16,
    pub manufacturer_id: u16,
    pub manufacturer_name: String,
    pub serial_number: u32,
    pub cardholder_name: Option<String>,
    pub cardholder_lang: Option<String>,
    pub pubkey_url: Option<String>,
    pub chv_status: ChvStatus,
    pub sig_counter: u32,
    pub keys: [KeyInfo; 3],
}

#[derive(Debug, Error)]
pub enum CardError {
    #[error("no OpenPGP card found")]
    NotFound,
    #[error("card identifier mismatch: expected {expected}, found {found}")]
    IdentMismatch { expected: String, found: String },
    #[error("PC/SC error: {message}")]
    Pcsc { message: String, retryable: bool },
    #[error("card status error: {status}")]
    CardStatus { status: String, retryable: bool },
    #[error("bad PIN; {retries_left} attempt(s) remaining")]
    BadPin { retries_left: u8 },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl CardError {
    /// True if the operation is safe to retry after reopening a fresh handle.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Pcsc { retryable, .. } | Self::CardStatus { retryable, .. } => *retryable,
            _ => false,
        }
    }

    fn from_status_bytes(sb: StatusBytes) -> Self {
        match sb {
            StatusBytes::PasswordNotChecked(n) => Self::BadPin { retries_left: n },
            StatusBytes::SecurityStatusNotSatisfied
            | StatusBytes::ConditionOfUseNotSatisfied
            | StatusBytes::AuthenticationMethodBlocked => Self::CardStatus {
                status: format!("{sb}"),
                retryable: false,
            },
            StatusBytes::MemoryFailure | StatusBytes::TerminationState => Self::CardStatus {
                status: format!("{sb}"),
                retryable: true,
            },
            other => Self::CardStatus {
                status: format!("{other}"),
                retryable: false,
            },
        }
    }
}

impl From<OcError> for CardError {
    fn from(err: OcError) -> Self {
        match err {
            OcError::Smartcard(sc) => Self::Pcsc {
                message: sc.to_string(),
                retryable: true,
            },
            OcError::CardStatus(sb) => Self::from_status_bytes(sb),
            OcError::NotFound(msg) => Self::Internal(format!("not found: {msg}")),
            OcError::ParseError(msg) => Self::Internal(format!("parse: {msg}")),
            OcError::UnsupportedAlgo(msg) | OcError::UnsupportedFeature(msg) => {
                Self::Unsupported(msg)
            }
            other => Self::Internal(other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CardError>;

/// PIN verification mode for a pooled card operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// PW1 mode 81 — signing (PSO:CDS).
    Signing,
    /// PW1 mode 82 — decryption / authentication.
    User,
}

/// A card handle kept open across operations so back-to-back signs/decrypts
/// skip the ~500 ms `Card::<Open>::new` (SELECT + ARD) overhead.
///
/// Holds `Card<Open>` — the PC/SC connection — but NOT `Card<Transaction>`.
/// Each operation starts a fresh PC/SC transaction so other clients on a
/// shared reader can interleave (the `pcsc-shared` guarantee still holds).
/// What gets reused is the card session the connection owns, which means
/// OpenPGP-applet selection state (and, when `pw1_cds_valid_once` is false,
/// PW1 verification state) persists across ops as long as this handle does.
pub struct PooledCard {
    card: Card<Open>,
    ident: String,
    last_used: Instant,
    /// PW1 mode 81 currently verified on this handle? Set after a successful
    /// Signing op; cleared whenever the card state may have changed.
    pw1_sign_fresh: bool,
    /// PW1 mode 82 currently verified on this handle?
    pw1_user_fresh: bool,
    /// `pw_status_bytes().pw1_cds_valid_once()` from the first transaction.
    /// `true` means every `PSO:CDS` needs its own PW1/81 verify (`YubiKey`
    /// default); `false` means one verify covers many signs (`Nitrokey`
    /// default). PW1 mode 82 is always multi-op per the `OpenPGP` card
    /// spec — no equivalent flag.
    signing_pin_valid_once: bool,
}

// `card: Card<Open>` is deliberately omitted — it carries a backend
// trait-object that isn't Debug.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for PooledCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledCard")
            .field("ident", &self.ident)
            .field("last_used", &self.last_used)
            .field("pw1_sign_fresh", &self.pw1_sign_fresh)
            .field("pw1_user_fresh", &self.pw1_user_fresh)
            .field("signing_pin_valid_once", &self.signing_pin_valid_once)
            .finish()
    }
}

impl PooledCard {
    #[must_use]
    pub fn is_fresh(&self, ttl: Duration) -> bool {
        self.last_used.elapsed() < ttl
    }

    #[must_use]
    pub fn ident(&self) -> &str {
        &self.ident
    }
}

/// Run a card operation, reusing a pooled handle when one is available,
/// fresh and matching the requested `ident`. Otherwise opens a fresh
/// PC/SC handle; on success and when `ttl > 0`, stores it in `pool`.
///
/// When `pin` is Some, performs the corresponding PW1 verify *unless*
/// the pooled handle already has that mode freshly verified and the
/// card's PW1 mode permits multi-op use — then the verify is skipped.
/// If the skipped-verify op fails, we retry once on the same handle
/// with an explicit verify (handles the case where the card state drifted
/// under us). Persistent failure bubbles up as usual.
///
/// Failures on a pool hit invalidate the pool entry. Retryable errors
/// (PC/SC communication, card reset, etc.) trigger one retry via the
/// fresh-open path.
pub fn with_pooled_card<R, F>(
    pool: &mut Option<PooledCard>,
    ttl: Duration,
    ident: &str,
    pin: Option<(PinMode, &[u8])>,
    mut f: F,
) -> Result<R>
where
    F: FnMut(&mut Card<Transaction<'_>>) -> Result<R>,
{
    // Reuse path
    if ttl > Duration::ZERO
        && matches!(
            pool.as_ref(),
            Some(pc) if pc.ident == ident && pc.is_fresh(ttl)
        )
    {
        let mut pc = pool.take().expect("matched above");
        let can_skip_verify = match pin {
            Some((PinMode::Signing, _)) => pc.pw1_sign_fresh && !pc.signing_pin_valid_once,
            // PW1 mode 82 is multi-op by spec — no valid-once bit.
            Some((PinMode::User, _)) => pc.pw1_user_fresh,
            None => true,
        };
        let first = if can_skip_verify {
            run_on_handle(&mut pc.card, None, &mut f)
        } else {
            run_on_handle(&mut pc.card, pin, &mut f)
        };
        let result = match first {
            Ok(v) => Ok(v),
            Err(err) if can_skip_verify && !err.is_retryable() => {
                // Card probably lost its verified state (PC/SC-shared tenant
                // came in, card was briefly reset, etc.). Clear the freshness
                // flag and retry with a real verify on the same handle.
                tracing::info!(error = %err, "skip-verify op failed; retrying with explicit verify");
                if let Some((mode, _)) = pin {
                    match mode {
                        PinMode::Signing => pc.pw1_sign_fresh = false,
                        PinMode::User => pc.pw1_user_fresh = false,
                    }
                }
                run_on_handle(&mut pc.card, pin, &mut f)
            }
            Err(err) => Err(err),
        };
        match result {
            Ok(value) => {
                pc.last_used = Instant::now();
                if let Some((mode, _)) = pin {
                    match mode {
                        PinMode::Signing => pc.pw1_sign_fresh = true,
                        PinMode::User => pc.pw1_user_fresh = true,
                    }
                }
                *pool = Some(pc);
                debug!(skipped_verify = can_skip_verify && pin.is_some(), "pool hit");
                return Ok(value);
            }
            Err(err) if err.is_retryable() => {
                tracing::info!(error = %err, "pool hit failed retryably; retrying fresh");
                // drop pc; fall through to fresh path
            }
            Err(err) => {
                // Non-retryable (BadPin, InvalidID, ...). Drop the pool entry
                // because card state may be tainted (e.g. PW1 counter changed).
                return Err(err);
            }
        }
    } else if pool.is_some() {
        // Stale entry (wrong ident or expired): drop it.
        *pool = None;
    }

    // Fresh path
    let mut card = open_card_by_ident(ident)?;
    let (value, signing_pin_valid_once) = run_on_handle_and_meta(&mut card, pin, &mut f)?;
    if ttl > Duration::ZERO {
        let (sign_fresh, user_fresh) = match pin {
            Some((PinMode::Signing, _)) => (true, false),
            Some((PinMode::User, _)) => (false, true),
            None => (false, false),
        };
        *pool = Some(PooledCard {
            card,
            ident: ident.to_string(),
            last_used: Instant::now(),
            pw1_sign_fresh: sign_fresh,
            pw1_user_fresh: user_fresh,
            signing_pin_valid_once,
        });
    }
    Ok(value)
}

/// Start a transaction on the given `Card<Open>`, optionally verify a PIN,
/// run the closure. Transaction is dropped before return.
fn run_on_handle<R, F>(
    card: &mut Card<Open>,
    pin: Option<(PinMode, &[u8])>,
    f: &mut F,
) -> Result<R>
where
    F: FnMut(&mut Card<Transaction<'_>>) -> Result<R>,
{
    let mut txn = card.transaction()?;
    if let Some((mode, pin_bytes)) = pin {
        let pin_box = SecretBox::new(Box::from(pin_bytes));
        match mode {
            PinMode::Signing => txn.card().verify_pw1_sign(pin_box)?,
            PinMode::User => txn.card().verify_pw1_user(pin_box)?,
        }
    }
    f(&mut txn)
}

/// Same as [`run_on_handle`] but also reads and returns the card's
/// `pw1_cds_valid_once` flag. Used on the fresh-open path so the pool
/// entry knows whether skip-verify is legal for subsequent signing ops.
/// Defaults to `true` (conservative: always re-verify) if the read fails.
fn run_on_handle_and_meta<R, F>(
    card: &mut Card<Open>,
    pin: Option<(PinMode, &[u8])>,
    f: &mut F,
) -> Result<(R, bool)>
where
    F: FnMut(&mut Card<Transaction<'_>>) -> Result<R>,
{
    let mut txn = card.transaction()?;
    if let Some((mode, pin_bytes)) = pin {
        let pin_box = SecretBox::new(Box::from(pin_bytes));
        match mode {
            PinMode::Signing => txn.card().verify_pw1_sign(pin_box)?,
            PinMode::User => txn.card().verify_pw1_user(pin_box)?,
        }
    }
    let value = f(&mut txn)?;
    let valid_once = txn
        .pw_status_bytes()
        .map(|p| p.pw1_cds_valid_once())
        .unwrap_or(true);
    Ok((value, valid_once))
}

/// Open a `Card<Open>` matching `ident`. Iterates PC/SC backends; returns
/// `NotFound` if none match. Error conversion handles `IdentMismatch` and
/// PC/SC-level failures.
fn open_card_by_ident(ident: &str) -> Result<Card<Open>> {
    let short = short_ident_from_full(ident)?;
    let t_ctx = Instant::now();
    let backends = PcscBackend::card_backends(None).map_err(|e| CardError::Pcsc {
        message: e.to_string(),
        retryable: true,
    })?;
    let mut enum_ms: u64 = t_ctx.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    for backend in backends {
        let backend: Box<dyn CardBackend + Send + Sync> = backend.map_err(|e| CardError::Pcsc {
            message: e.to_string(),
            retryable: true,
        })?;
        let t_open = Instant::now();
        let mut card = Card::<Open>::new(backend)?;
        let open_ms = t_open.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let aid = {
            let txn = card.transaction()?;
            txn.application_identifier()?
        };
        if aid.ident().eq_ignore_ascii_case(&short) {
            tracing::debug!(ctx_ms = enum_ms, open_ms, "card opened fresh");
            return Ok(card);
        }
        enum_ms = enum_ms.saturating_add(open_ms);
    }
    Err(CardError::NotFound)
}

/// Build the scdaemon-style full AID (32 hex chars) from the card's
/// `ApplicationIdentifier` fields. The `OpenPGP` card application's registered
/// AID prefix is `D276000124` plus an application byte, a 16-bit BCD version,
/// the manufacturer ID, the card serial, and a 16-bit RFU trailer.
fn full_aid(app: u8, version_bcd: u16, manufacturer: u16, serial: u32) -> String {
    format!("D276000124{app:02X}{version_bcd:04X}{manufacturer:04X}{serial:08X}0000")
}

/// Parse an scdaemon-style full AID into the short `MANUF:SERIAL` ident
/// that the `openpgp-card` transaction layer uses internally.
fn short_ident_from_full(full: &str) -> Result<String> {
    let upper = full.to_ascii_uppercase();
    if upper.len() != 32 || !upper.starts_with("D276000124") {
        return Err(CardError::Internal(format!(
            "unexpected AID format: {full}"
        )));
    }
    // AID layout: D276000124 | app(2) | version(4) | manuf(4) | serial(8) | rfu(4)
    let manuf = &upper[16..20];
    let serial = &upper[20..28];
    Ok(format!("{manuf}:{serial}"))
}

/// Enumerate every `OpenPGP` card currently visible via PC/SC.
///
/// Returns full scdaemon-style AID strings suitable to pass back to
/// `read_card_info`, `sign_digest_info`, or `decrypt`.
#[instrument(level = "debug")]
pub fn enumerate_cards() -> Result<Vec<CardIdent>> {
    let backends = PcscBackend::card_backends(None).map_err(|e| CardError::Pcsc {
        message: e.to_string(),
        retryable: true,
    })?;

    let mut idents = Vec::new();
    for backend in backends {
        let backend: Box<dyn CardBackend + Send + Sync> = backend.map_err(|e| CardError::Pcsc {
            message: e.to_string(),
            retryable: true,
        })?;
        let mut card = Card::<Open>::new(backend)?;
        let txn = card.transaction()?;
        let app_id = txn.application_identifier()?;
        idents.push(CardIdent(full_aid(
            app_id.application(),
            app_id.version(),
            app_id.manufacturer(),
            app_id.serial(),
        )));
    }
    Ok(idents)
}

/// Fetch the full card snapshot `gpg-agent` needs for `LEARN --force`.
///
/// All the ARD-derived metadata (fingerprints, PW status, algorithm
/// attributes, key-generation times) comes out of a single ARD read that
/// `Card<Transaction>` caches on entry. Cardholder DO, URL, and the
/// signature counter are one APDU each. Per-slot public-key reads still
/// cost two APDUs each because `public_key_material` internally re-reads
/// ARD (the upstream `// FIXME: caching`).
#[instrument(level = "debug", skip(pool), fields(ident, pool_ttl_s = pool_ttl.as_secs()))]
pub fn read_card_info(
    pool: &mut Option<PooledCard>,
    pool_ttl: Duration,
    ident: &str,
) -> Result<CardInfo> {
    let t_start = Instant::now();
    let result = with_pooled_card(pool, pool_ttl, ident, None, |txn| {
        let app_id = txn.application_identifier()?;
        let pws = txn.pw_status_bytes()?;
        let fingerprints = txn.fingerprints().ok();
        let gen_times = txn.key_generation_times().ok();
        let aa_sig = txn.algorithm_attributes(KeyType::Signing).ok();
        let aa_dec = txn.algorithm_attributes(KeyType::Decryption).ok();
        let aa_aut = txn.algorithm_attributes(KeyType::Authentication).ok();

        let chv_status = ChvStatus {
            signing_pin_multi_op: !pws.pw1_cds_valid_once(),
            pw1_max_len: pws.pw1_max_len(),
            rc_max_len: pws.rc_max_len(),
            pw3_max_len: pws.pw3_max_len(),
            pw1_retries: pws.err_count_pw1(),
            rc_retries: pws.err_count_rc(),
            pw3_retries: pws.err_count_pw3(),
        };

        let cardholder = txn.cardholder_related_data().ok();
        let cardholder_name = cardholder
            .as_ref()
            .and_then(|c| c.name())
            .map(|n| n.iter().map(|&b| b as char).collect());
        let cardholder_lang = cardholder
            .as_ref()
            .and_then(|c| c.lang())
            .map(|langs| langs.iter().map(ToString::to_string).collect());

        let pubkey_url = txn.url().ok().filter(|s| !s.is_empty());
        let sig_counter = txn.digital_signature_count().unwrap_or(0);

        let keys = [
            build_key_info(
                txn,
                KeyUsage::Signing,
                fingerprints.as_ref(),
                gen_times.as_ref(),
                aa_sig.as_ref(),
            ),
            build_key_info(
                txn,
                KeyUsage::Decryption,
                fingerprints.as_ref(),
                gen_times.as_ref(),
                aa_dec.as_ref(),
            ),
            build_key_info(
                txn,
                KeyUsage::Authentication,
                fingerprints.as_ref(),
                gen_times.as_ref(),
                aa_aut.as_ref(),
            ),
        ];

        Ok(CardInfo {
            ident: CardIdent(full_aid(
                app_id.application(),
                app_id.version(),
                app_id.manufacturer(),
                app_id.serial(),
            )),
            app: app_id.application(),
            app_version_bcd: app_id.version(),
            manufacturer_id: app_id.manufacturer(),
            manufacturer_name: manufacturer_name(app_id.manufacturer()),
            serial_number: app_id.serial(),
            cardholder_name,
            cardholder_lang,
            pubkey_url,
            chv_status,
            sig_counter,
            keys,
        })
    });
    let elapsed_ms: u64 = t_start.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    debug!(elapsed_ms, ok = result.is_ok(), "read_card_info complete");
    result
}

fn build_key_info(
    txn: &mut Card<Transaction<'_>>,
    usage: KeyUsage,
    fingerprints: Option<&KeySet<Fingerprint>>,
    gen_times: Option<&KeySet<KeyGenerationTime>>,
    algorithm: Option<&AlgorithmAttributes>,
) -> KeyInfo {
    let fingerprint = fingerprints
        .and_then(|s| usage.pick_from_key_set(s))
        .map(format_fingerprint);

    let created = gen_times
        .and_then(|s| usage.pick_from_key_set(s))
        .map(KeyGenerationTime::get);

    let algorithm = algorithm.map(ToString::to_string);

    let keygrip = match txn.public_key_material(usage.key_type()).ok() {
        Some(PublicKeyMaterial::R(rsa)) => {
            Some(keygrip::format_hex(&keygrip::rsa_keygrip(rsa.n())))
        }
        _ => None,
    };

    KeyInfo {
        usage,
        keygrip,
        fingerprint,
        created,
        algorithm,
    }
}

fn format_fingerprint(fp: &Fingerprint) -> String {
    fp.as_bytes()
        .iter()
        .fold(String::with_capacity(40), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02X}");
            acc
        })
}

fn manufacturer_name(id: u16) -> String {
    match id {
        0x0006 => "Yubico".into(),
        0x000F => "Nitrokey".into(),
        other => format!("0x{other:04X}"),
    }
}

/// Compute an RSA signature via `PSO: COMPUTE DIGITAL SIGNATURE`.
///
/// `digest_info` is the pre-built PKCS#1 `DigestInfo` structure (what
/// `gpg-agent` places in `SETDATA`). The card wraps it in PKCS#1 padding
/// internally and returns the raw signature bytes.
///
/// Uses `openpgp-card`'s low-level `ocard::Transaction` (reached via
/// `Card<Transaction>::card()`) rather than any high-level wrapper — the
/// wrappers rebuild a `DigestInfo` from a raw hash, and we already have
/// the exact bytes `gpg-agent` wants signed.
#[instrument(
    level = "debug",
    skip(pool, pin, digest_info),
    fields(ident, pool_ttl_s = pool_ttl.as_secs(), pin_len = pin.len(), di_len = digest_info.len())
)]
pub fn sign_digest_info(
    pool: &mut Option<PooledCard>,
    pool_ttl: Duration,
    ident: &str,
    pin: &[u8],
    digest_info: &[u8],
) -> Result<Vec<u8>> {
    let t_overall = Instant::now();
    let result = with_pooled_card(
        pool,
        pool_ttl,
        ident,
        Some((PinMode::Signing, pin)),
        |txn| {
            let t_cds = Instant::now();
            let sig = txn
                .card()
                .pso_compute_digital_signature(digest_info.to_vec())
                .map_err(|e| {
                    tracing::error!(error = %e, "pso_compute_digital_signature failed");
                    e
                })?;
            tracing::debug!(
                cds_ms = t_cds.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                sig_len = sig.len(),
                "signature returned"
            );
            Ok(sig)
        },
    );
    tracing::info!(
        total_ms = t_overall.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
        ok = result.is_ok(),
        "sign_digest_info finished"
    );
    result
}

/// Decrypt a ciphertext via `PSO: DECIPHER`.
///
/// `ciphertext` is the payload `gpg-agent` placed in `SETDATA` (for RSA:
/// the raw padded block, optionally preceded by a 1-byte algo hint that
/// scdaemon forwards verbatim). The card returns the unpadded plaintext.
#[instrument(
    level = "debug",
    skip(pool, pin, ciphertext),
    fields(ident, pool_ttl_s = pool_ttl.as_secs(), pin_len = pin.len(), ct_len = ciphertext.len())
)]
pub fn decrypt(
    pool: &mut Option<PooledCard>,
    pool_ttl: Duration,
    ident: &str,
    pin: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    with_pooled_card(pool, pool_ttl, ident, Some((PinMode::User, pin)), |txn| {
        debug!("PIN verified; sending PSO:DECIPHER");
        let plain = txn.card().pso_decipher(ciphertext.to_vec()).map_err(|e| {
            tracing::error!(error = %e, "pso_decipher failed");
            e
        })?;
        debug!(plain_len = plain.len(), "plaintext returned");
        Ok(plain)
    })
}
