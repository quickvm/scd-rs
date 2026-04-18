//! Sequoia-backed `OpenPGP` card access for `scd-rs`.
//!
//! Enforces per-operation PC/SC handle discipline: every externally visible
//! operation opens a fresh `PcscBackend` → `Card<Open>` → `Card<Transaction>`
//! chain and drops it before returning. Nothing in this crate is permitted to
//! retain a card handle across calls.

use std::fmt;

use card_backend::CardBackend;
use card_backend_pcsc::PcscBackend;
use openpgp_card::Card as OcCard;
use openpgp_card_sequoia::state::{Open, Transaction};
use openpgp_card_sequoia::types::{Error as OcError, KeyType, StatusBytes};
use openpgp_card_sequoia::Card;
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

/// Build the scdaemon-style full AID (32 hex chars) from the card's
/// `ApplicationIdentifier` fields. The `OpenPGP` card application's registered
/// AID prefix is `D276000124` plus an application byte, a 16-bit BCD version,
/// the manufacturer ID, the card serial, and a 16-bit RFU trailer.
fn full_aid(app: u8, version_bcd: u16, manufacturer: u16, serial: u32) -> String {
    format!("D276000124{app:02X}{version_bcd:04X}{manufacturer:04X}{serial:08X}0000")
}

/// Parse an scdaemon-style full AID into the short ident
/// (`MANUF:SERIAL`) that `openpgp_card_sequoia::Card::open_by_ident` expects.
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

/// Open a transaction against the requested card, run `f`, then drop the
/// backend / card / transaction stack before returning.
///
/// `ident` accepts the full AID hex (`D276...`) that `gpg-agent` sends; it is
/// translated to the short `MANUF:SERIAL` form internally. Pass `None` to pick
/// the first card PC/SC returns.
#[instrument(level = "debug", skip(f), fields(ident = ident.unwrap_or("<any>")))]
pub fn with_card<R, F>(ident: Option<&str>, f: F) -> Result<R>
where
    F: FnOnce(&mut Card<Transaction<'_>>) -> Result<R>,
{
    let backends = PcscBackend::card_backends(None).map_err(|e| CardError::Pcsc {
        message: e.to_string(),
        retryable: true,
    })?;

    let mut card: Card<Open> = if let Some(full) = ident {
        let short = short_ident_from_full(full)?;
        Card::<Open>::open_by_ident(backends, &short)?
    } else {
        let mut it = backends;
        let backend = it
            .next()
            .ok_or(CardError::NotFound)?
            .map_err(|e| CardError::Pcsc {
                message: e.to_string(),
                retryable: true,
            })?;
        Card::<Open>::new(backend)?
    };

    let mut txn = card.transaction()?;
    debug!("transaction open");
    let result = f(&mut txn);
    drop(txn);
    drop(card);
    debug!(success = result.is_ok(), "transaction closed");
    result
}

/// Enumerate every `OpenPGP` card currently visible via PC/SC.
///
/// Returns full scdaemon-style AID strings suitable to pass back to
/// `with_card`.
#[instrument(level = "debug")]
pub fn enumerate_cards() -> Result<Vec<CardIdent>> {
    let backends = PcscBackend::card_backends(None).map_err(|e| CardError::Pcsc {
        message: e.to_string(),
        retryable: true,
    })?;

    let mut idents = Vec::new();
    for backend in backends {
        let backend = backend.map_err(|e| CardError::Pcsc {
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
#[instrument(level = "debug", fields(ident))]
pub fn read_card_info(ident: &str) -> Result<CardInfo> {
    with_card(Some(ident), |txn| {
        let app_id = txn.application_identifier()?;
        let pws = txn.pw_status_bytes()?;

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
            key_info(txn, KeyUsage::Signing)?,
            key_info(txn, KeyUsage::Decryption)?,
            key_info(txn, KeyUsage::Authentication)?,
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
    })
}

fn key_info(txn: &mut Card<Transaction<'_>>, usage: KeyUsage) -> Result<KeyInfo> {
    let key_type = usage.key_type();
    let fingerprint = txn.fingerprint(key_type)?.map(|fp| format!("{fp:X}"));
    let created = txn.key_generation_times().ok().and_then(|kgt| {
        match usage {
            KeyUsage::Signing => kgt.signature(),
            KeyUsage::Decryption => kgt.decryption(),
            KeyUsage::Authentication => kgt.authentication(),
        }
        .map(u32::from)
    });

    let algorithm = txn
        .algorithm_attributes(key_type)
        .ok()
        .map(|a| a.to_string());

    let keygrip = txn
        .public_key(key_type)
        .ok()
        .flatten()
        .and_then(|pk| compute_keygrip(&pk));

    Ok(KeyInfo {
        usage,
        keygrip,
        fingerprint,
        created,
        algorithm,
    })
}

fn compute_keygrip(pk: &openpgp_card_sequoia::PublicKey) -> Option<String> {
    use sequoia_openpgp::crypto::mpi::PublicKey;
    match pk.mpis() {
        PublicKey::RSA { n, .. } => {
            let grip = keygrip::rsa_keygrip(n.value());
            Some(keygrip::format_hex(&grip))
        }
        _ => None,
    }
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
/// Uses `openpgp-card` directly rather than the Sequoia wrapper because
/// the wrapper's `Signer` insists on rebuilding a `DigestInfo` from a raw
/// hash — we already have the exact bytes `gpg-agent` wants the card to
/// sign.
#[instrument(level = "debug", skip(pin, digest_info), fields(ident, pin_len = pin.len(), di_len = digest_info.len()))]
pub fn sign_digest_info(ident: &str, pin: &[u8], digest_info: &[u8]) -> Result<Vec<u8>> {
    let t_overall = std::time::Instant::now();
    let result = with_low_level_card(ident, |txn| {
        let t_verify = std::time::Instant::now();
        txn.verify_pw1_sign(pin).map_err(|e| {
            tracing::error!(error = %e, "verify_pw1_sign failed");
            e
        })?;
        tracing::debug!(
            verify_ms = t_verify.elapsed().as_millis() as u64,
            "PIN verified; sending PSO:CDS"
        );
        let t_cds = std::time::Instant::now();
        let sig = txn.pso_compute_digital_signature(digest_info.to_vec()).map_err(|e| {
            tracing::error!(error = %e, "pso_compute_digital_signature failed");
            e
        })?;
        tracing::debug!(
            cds_ms = t_cds.elapsed().as_millis() as u64,
            sig_len = sig.len(),
            "signature returned"
        );
        Ok(sig)
    });
    tracing::info!(total_ms = t_overall.elapsed().as_millis() as u64, "sign_digest_info finished");
    result
}

/// Decrypt a ciphertext via `PSO: DECIPHER`.
///
/// `ciphertext` is the payload `gpg-agent` placed in `SETDATA` (for RSA:
/// the raw padded block, optionally preceded by a 1-byte algo hint that
/// scdaemon forwards verbatim). The card returns the unpadded plaintext.
#[instrument(level = "debug", skip(pin, ciphertext), fields(ident, pin_len = pin.len(), ct_len = ciphertext.len()))]
pub fn decrypt(ident: &str, pin: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    with_low_level_card(ident, |txn| {
        txn.verify_pw1_user(pin).map_err(|e| {
            tracing::error!(error = %e, "verify_pw1_user failed");
            e
        })?;
        debug!("PIN verified; sending PSO:DECIPHER");
        let plain = txn.pso_decipher(ciphertext.to_vec()).map_err(|e| {
            tracing::error!(error = %e, "pso_decipher failed");
            e
        })?;
        debug!(plain_len = plain.len(), "plaintext returned");
        Ok(plain)
    })
}

fn with_low_level_card<R, F>(ident: &str, f: F) -> Result<R>
where
    F: FnOnce(&mut openpgp_card::Transaction<'_>) -> Result<R>,
{
    let short = short_ident_from_full(ident)?;
    let t_ctx = std::time::Instant::now();
    let backends = PcscBackend::card_backends(None).map_err(|e| CardError::Pcsc {
        message: e.to_string(),
        retryable: true,
    })?;
    let mut enum_ms: u64 = t_ctx.elapsed().as_millis() as u64;
    for backend in backends {
        let backend: Box<dyn CardBackend + Send + Sync> = backend.map_err(|e| CardError::Pcsc {
            message: e.to_string(),
            retryable: true,
        })?;
        let t_open = std::time::Instant::now();
        let mut card = OcCard::new(backend)?;
        let open_ms = t_open.elapsed().as_millis() as u64;
        let mut txn = card.transaction()?;
        let app_id = txn.application_identifier()?;
        if app_id.ident().eq_ignore_ascii_case(&short) {
            tracing::debug!(
                ctx_ms = enum_ms,
                open_ms,
                "card matched, running low-level op"
            );
            let out = f(&mut txn);
            drop(txn);
            drop(card);
            return out;
        }
        enum_ms = enum_ms.saturating_add(open_ms);
    }
    Err(CardError::NotFound)
}
