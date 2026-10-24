//! Per-connection daemon session state.
//!
//! Lives for the lifetime of one Assuan client connection. Does not retain
//! any PC/SC handles; card access is always fresh via `scd_rs_card`.

use std::time::{Duration, Instant};

use scd_rs_card::PooledCard;
use secrecy::{ExposeSecret, SecretBox};

use crate::cards::KnownCards;
use crate::pin_ttl;

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
    /// The card this session is bound to, in scdaemon-style full AID form.
    /// Set by SERIALNO, and by a KEYINFO / PKSIGN / PKDECRYPT keygrip that
    /// lives on another card; see [`Session::bind_card`].
    pub current_ident: Option<String>,
    /// Data buffered by `SETDATA` / `SETDATA --append`, consumed by the
    /// next `PKSIGN` or `PKDECRYPT`.
    pub setdata: Vec<u8>,
    /// Cards seen this session, with a `CardInfo` snapshot of each one read
    /// so far. Serves prompts, KEYINFO and keygrip routing without
    /// re-reading a card (each `read_card_info` costs ~3 seconds of
    /// round-trips). LEARN --force re-reads the bound card.
    pub cards: KnownCards,
    /// In-memory PIN cache for the bound card. Cleared on bad-PIN errors
    /// and when the session moves to another card.
    pub cached_pin: Option<CachedPin>,
    /// Optional warm handle to the bound card, kept across operations when
    /// `SCD_RS_CARD_POOL_TTL` is set. `None` = pooling disabled (every
    /// card op opens a fresh PC/SC handle).
    pub card_pool: Option<PooledCard>,
}

impl Session {
    /// Bind the session to the card `ident`. Moving to a different card
    /// drops the cached PIN and the pooled handle: both belong to the old
    /// card, and sending its PIN to the new card would burn one of the new
    /// card's PIN retries.
    pub fn bind_card(&mut self, ident: &str) {
        if self.current_ident.as_deref() == Some(ident) {
            return;
        }
        if let Some(old) = &self.current_ident {
            tracing::info!(from = %old, to = ident, "switching cards; dropping PIN cache and pool");
        }
        self.cached_pin = None;
        self.card_pool = None;
        self.current_ident = Some(ident.to_string());
    }

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

#[cfg(test)]
mod tests {
    use scd_rs_card::test_support::pooled_card;

    use super::*;
    use crate::cards::fixtures::{NITROKEY, YUBIKEY};

    /// A session bound to `ident` with a cached PIN and a pooled handle.
    fn bound_session(ident: &str) -> Session {
        Session {
            current_ident: Some(ident.to_string()),
            cached_pin: Some(CachedPin::new(b"123456".to_vec(), Duration::from_secs(600))),
            card_pool: Some(pooled_card(ident)),
            ..Session::default()
        }
    }

    #[test]
    fn switching_cards_drops_pin_and_pool() {
        let mut session = bound_session(YUBIKEY);
        session.setdata = b"digest".to_vec();

        session.bind_card(NITROKEY);

        assert_eq!(session.current_ident.as_deref(), Some(NITROKEY));
        assert!(session.cached_pin.is_none());
        assert!(session.card_pool.is_none());
        assert_eq!(session.setdata, b"digest", "SETDATA belongs to the next op");
    }

    #[test]
    fn rebinding_the_same_card_keeps_pin_and_pool() {
        let mut session = bound_session(NITROKEY);

        session.bind_card(NITROKEY);

        assert_eq!(session.cached_pin_bytes(), Some(&b"123456"[..]));
        assert_eq!(
            session.card_pool.as_ref().map(PooledCard::ident),
            Some(NITROKEY)
        );
    }

    #[test]
    fn first_bind_sets_the_card() {
        let mut session = Session::default();
        session.bind_card(YUBIKEY);
        assert_eq!(session.current_ident.as_deref(), Some(YUBIKEY));
    }
}
