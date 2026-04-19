//! Per-connection daemon session state.
//!
//! Lives for the lifetime of one Assuan client connection. Does not retain
//! any PC/SC handles; card access is always fresh via `scd_rs_card`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use scd_rs_card::{CardIdent, CardInfo, KeyUsage, PooledCard};
use secrecy::{ExposeSecret, SecretBox};

use crate::pin_ttl;

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

/// Which PW1 mode a card operation needs; the daemon uses this only to
/// dispatch the right verify APDU (`verify_pw1_sign` vs `verify_pw1_user`).
/// On standard `OpenPGP` cards both modes accept the same PIN bytes, so our
/// in-memory cache is mode-agnostic and can serve signing and user ops with
/// the same entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// PW1 mode 81 (signing).
    Signing,
    /// PW1 mode 82 (decryption / authentication).
    User,
}

/// A PIN cached in-memory for the lifetime of the session or until the TTL
/// expires. TTL is a sliding window; each successful cache hit pushes
/// `expires_at` forward by another full TTL, so an all-day session keeps
/// the PIN valid as long as card operations keep happening.
///
/// TTL of zero disables the cache: `expires_at = now` on entry, so the
/// very next `is_valid()` check returns false.
pub struct CachedPin {
    bytes: SecretBox<Vec<u8>>,
    expires_at: Instant,
}

impl std::fmt::Debug for CachedPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedPin")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl CachedPin {
    #[must_use]
    pub fn new(bytes: Vec<u8>, ttl: Duration) -> Self {
        Self {
            bytes: SecretBox::new(Box::new(bytes)),
            expires_at: Instant::now() + ttl,
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// Push the expiry window forward. Called after a cached PIN
    /// successfully unlocks a card operation.
    pub fn touch(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }
}

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
    /// Optional warm card handle kept across operations when
    /// `SCD_RS_CARD_POOL_TTL` is set. `None` = pooling disabled (every
    /// card op opens a fresh PC/SC handle).
    pub card_pool: Option<PooledCard>,
}

impl Session {
    /// Return the cached PIN bytes if the cache is populated and unexpired.
    #[must_use]
    pub fn cached_pin_bytes(&self) -> Option<&[u8]> {
        self.cached_pin
            .as_ref()
            .filter(|p| p.is_valid())
            .map(CachedPin::bytes)
    }

    /// Store a PIN in the cache with the configured TTL.
    pub fn cache_pin(&mut self, bytes: Vec<u8>) {
        self.cached_pin = Some(CachedPin::new(bytes, pin_ttl::configured()));
    }

    /// Reset the PIN cache expiry window. Called after a cached PIN has
    /// successfully unlocked a card operation so that activity keeps the
    /// cache alive (sliding window). No-op if the cache is empty.
    pub fn touch_pin(&mut self) {
        if let Some(pin) = self.cached_pin.as_mut() {
            pin.touch(pin_ttl::configured());
        }
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
