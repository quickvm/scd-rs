//! Per-connection daemon session state.
//!
//! Lives for the lifetime of one Assuan client connection. Does not retain
//! any PC/SC handles — card access is always fresh via `scd_rs_card`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use scd_rs_card::{CardIdent, CardInfo, KeyUsage};
use secrecy::{ExposeSecret, SecretBox};

/// Snapshot of the keys learned from a `LEARN --force` / `read_card_info`.
#[derive(Debug, Clone, Default)]
pub struct KnownKeys {
    /// Maps 40-char uppercase keygrip → slot usage.
    by_grip: HashMap<String, KeyUsage>,
    /// The ident of the card this snapshot came from.
    ident: Option<CardIdent>,
}

impl KnownKeys {
    #[must_use]
    pub fn from_card_info(info: &CardInfo) -> Self {
        let mut by_grip = HashMap::new();
        for key in &info.keys {
            if let Some(grip) = &key.keygrip {
                by_grip.insert(grip.clone(), key.usage);
            }
        }
        Self {
            by_grip,
            ident: Some(info.ident.clone()),
        }
    }

    #[must_use]
    pub fn usage(&self, keygrip: &str) -> Option<KeyUsage> {
        self.by_grip.get(keygrip).copied()
    }

    pub fn grips(&self) -> impl Iterator<Item = (&String, &KeyUsage)> {
        self.by_grip.iter()
    }

    #[must_use]
    pub fn ident(&self) -> Option<&CardIdent> {
        self.ident.as_ref()
    }
}

/// Which PW1 mode a cached PIN was validated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// PW1 mode 81 (signing).
    Signing,
    /// PW1 mode 82 (decryption / authentication).
    User,
}

/// A PIN cached in-memory for the lifetime of the session or until the TTL
/// expires. Mirrors what stock `scdaemon` keeps via gpg-agent's pin cache so
/// users don't re-enter the PIN on every sign within a gpg-agent session.
pub struct CachedPin {
    bytes: SecretBox<Vec<u8>>,
    mode: PinMode,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedPin")
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl CachedPin {
    #[must_use]
    pub fn new(bytes: Vec<u8>, mode: PinMode, ttl: Duration) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
            mode,
            expires_at: Instant::now() + ttl,
        }
    }

    #[must_use]
    pub fn is_valid(&self, mode: PinMode) -> bool {
        self.mode == mode && Instant::now() < self.expires_at
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }
}

/// Default TTL for the in-process PIN cache, chosen to match gpg-agent's
/// `default-cache-ttl` of 600 seconds.
pub const DEFAULT_PIN_TTL: Duration = Duration::from_secs(600);

/// One Assuan session's worth of state.
#[derive(Debug, Default)]
pub struct Session {
    /// The card this session is currently bound to (from last SERIALNO /
    /// LEARN), in scdaemon-style full AID form.
    pub current_ident: Option<String>,
    /// Data buffered by `SETDATA` / `SETDATA --append`, consumed by the
    /// next `PKSIGN` or `PKDECRYPT`.
    pub setdata: Vec<u8>,
    /// Keys discovered by the last `LEARN` / `KEYINFO --list`.
    pub known_keys: KnownKeys,
    /// In-memory PIN cache. Cleared on RESTART and on bad-PIN errors.
    pub cached_pin: Option<CachedPin>,
    /// Cached `CardInfo` from the last card read. Used to serve prompt
    /// building, cardholder display, and signature-counter lookups without
    /// re-reading the card (each `read_card_info` costs ~3 seconds of
    /// round-trips). Refreshed explicitly on SERIALNO and LEARN --force.
    pub cached_info: Option<CardInfo>,
}

impl Session {
    /// Return the cached PIN bytes if it's still valid for `mode`.
    #[must_use]
    pub fn pin_for(&self, mode: PinMode) -> Option<&[u8]> {
        self.cached_pin
            .as_ref()
            .filter(|p| p.is_valid(mode))
            .map(CachedPin::bytes)
    }

    /// Store a PIN in the cache with the default TTL.
    pub fn cache_pin(&mut self, bytes: Vec<u8>, mode: PinMode) {
        self.cached_pin = Some(CachedPin::new(bytes, mode, DEFAULT_PIN_TTL));
    }

    pub fn clear_pin(&mut self) {
        self.cached_pin = None;
    }
}

impl Session {
    pub fn set_data(&mut self, hex: &str) -> Result<(), hex::FromHexError> {
        self.setdata = hex::decode(hex)?;
        Ok(())
    }

    pub fn append_data(&mut self, hex: &str) -> Result<(), hex::FromHexError> {
        let mut more = hex::decode(hex)?;
        self.setdata.append(&mut more);
        Ok(())
    }

    pub fn take_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.setdata)
    }
}
