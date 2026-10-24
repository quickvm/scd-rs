//! Choosing between `OpenPGP` cards when more than one is plugged in.
//!
//! Everything here works on snapshots the session already holds, so the
//! choice of card (by AID, by keygrip, or by default) is testable without
//! hardware. The PC/SC calls that fill these snapshots live in `commands`.

use scd_rs_card::{CardIdent, CardInfo, KeyUsage};

/// The card a `SERIALNO` request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wanted<'a> {
    /// Bare `SERIALNO` or `SERIALNO --all`: the first card PC/SC lists.
    First,
    /// `SERIALNO --demand=<AID>`.
    Aid(&'a str),
}

/// Pick the card `wanted` names out of `present` (PC/SC reader order).
#[must_use]
pub fn choose<'a>(present: &'a [CardIdent], wanted: Wanted<'_>) -> Option<&'a CardIdent> {
    match wanted {
        Wanted::First => present.first(),
        Wanted::Aid(aid) => present.iter().find(|card| same_card(card.as_ref(), aid)),
    }
}

/// True when two AIDs name the same card.
///
/// Like stock scdaemon's `is_same_serialno`, `OpenPGP` AIDs compare without
/// their two version bytes: stock reports a `YubiKey` as
/// `D27600012401` `0000` `0006…` while the card itself (and scd-rs) say
/// `D27600012401` `0304` `0006…`, and either form can come back in a
/// `--demand`.
#[must_use]
pub fn same_card(a: &str, b: &str) -> bool {
    if is_openpgp_aid(a) && is_openpgp_aid(b) {
        a[16..].eq_ignore_ascii_case(&b[16..])
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

/// `D27600012401` (the `OpenPGP` application RID plus PIX app byte),
/// version, manufacturer, serial, RFU: 16 bytes as 32 hex digits.
fn is_openpgp_aid(aid: &str) -> bool {
    aid.len() == 32 && aid.is_ascii() && aid[..12].eq_ignore_ascii_case("D27600012401")
}

/// What a session knows about the cards plugged in: which ones the last
/// enumeration found, and a `CardInfo` snapshot for each card read so far.
///
/// Snapshots last for the session, because reading a card costs seconds
/// (SELECT + ARD, then two APDUs per public key). Keygrip lookups after
/// the first one are answered from memory.
#[derive(Debug, Default)]
pub struct KnownCards {
    present: Vec<CardIdent>,
    infos: Vec<CardInfo>,
}

impl KnownCards {
    /// AIDs from the last enumeration, in PC/SC reader order. Empty until
    /// the session first enumerates.
    #[must_use]
    pub fn present(&self) -> &[CardIdent] {
        &self.present
    }

    /// Record a fresh enumeration, dropping snapshots of cards that are gone.
    pub fn set_present(&mut self, present: Vec<CardIdent>) {
        self.infos.retain(|info| present.contains(&info.ident));
        self.present = present;
    }

    /// Present cards that have no snapshot yet.
    #[must_use]
    pub fn unread(&self) -> Vec<CardIdent> {
        self.present
            .iter()
            .filter(|ident| self.get(ident.as_ref()).is_none())
            .cloned()
            .collect()
    }

    #[must_use]
    pub fn get(&self, ident: &str) -> Option<&CardInfo> {
        self.infos.iter().find(|info| info.ident.as_ref() == ident)
    }

    /// Store a snapshot, replacing any older one of the same card.
    pub fn insert(&mut self, info: CardInfo) {
        if let Some(old) = self.infos.iter_mut().find(|old| old.ident == info.ident) {
            *old = info;
        } else {
            self.infos.push(info);
        }
    }

    /// The card holding the key with this uppercase-hex keygrip, and the
    /// key's slot usage.
    #[must_use]
    pub fn find_keygrip(&self, keygrip: &str) -> Option<(&CardIdent, KeyUsage)> {
        self.infos.iter().find_map(|info| {
            info.keys
                .iter()
                .find(|key| key.keygrip.as_deref() == Some(keygrip))
                .map(|key| (&info.ident, key.usage))
        })
    }

    /// Snapshots of present cards in `KEYINFO --list` order: the bound card
    /// first (stock scdaemon lists its current card first), then the rest
    /// in reader order.
    #[must_use]
    pub fn listing(&self, bound: Option<&str>) -> Vec<&CardInfo> {
        let (bound_card, others): (Vec<&CardIdent>, Vec<&CardIdent>) = self
            .present
            .iter()
            .partition(|ident| Some(ident.as_ref()) == bound);
        bound_card
            .into_iter()
            .chain(others)
            .filter_map(|ident| self.get(ident.as_ref()))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Two cards shaped like the maintainer's: a `YubiKey` that PC/SC lists
    //! first, and a Nitrokey 3 that holds the signing key in use. AIDs and
    //! keygrips are made up, so a test that reached PC/SC by mistake would
    //! find no matching card.

    use scd_rs_card::{CardIdent, CardInfo, ChvStatus, KeyInfo, KeyUsage};

    pub const YUBIKEY: &str = "D2760001240103040006000000010000";
    pub const NITROKEY: &str = "D276000124010304000F000000020000";
    pub const YUBIKEY_SIGN: &str = "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1";
    pub const YUBIKEY_ENCR: &str = "A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2A2";
    pub const YUBIKEY_AUTH: &str = "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3";
    pub const NITROKEY_SIGN: &str = "B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1";
    pub const NITROKEY_ENCR: &str = "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2";
    pub const NITROKEY_AUTH: &str = "B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3B3";

    pub fn ident(aid: &str) -> CardIdent {
        CardIdent(aid.to_string())
    }

    /// Both cards, `YubiKey` first, the order the bug report saw.
    pub fn both() -> Vec<CardIdent> {
        vec![ident(YUBIKEY), ident(NITROKEY)]
    }

    pub fn yubikey() -> CardInfo {
        card_info(YUBIKEY, [YUBIKEY_SIGN, YUBIKEY_ENCR, YUBIKEY_AUTH])
    }

    pub fn nitrokey() -> CardInfo {
        card_info(NITROKEY, [NITROKEY_SIGN, NITROKEY_ENCR, NITROKEY_AUTH])
    }

    fn card_info(aid: &str, grips: [&str; 3]) -> CardInfo {
        let key = |usage, grip: &str| KeyInfo {
            usage,
            keygrip: Some(grip.to_string()),
            fingerprint: None,
            created: None,
            algorithm: None,
        };
        CardInfo {
            ident: ident(aid),
            app: 1,
            app_version_bcd: 0x0304,
            manufacturer_id: 0,
            manufacturer_name: "test".into(),
            serial_number: 0,
            cardholder_name: None,
            cardholder_lang: None,
            pubkey_url: None,
            chv_status: ChvStatus {
                signing_pin_multi_op: true,
                pw1_max_len: 127,
                rc_max_len: 127,
                pw3_max_len: 127,
                pw1_retries: 3,
                rc_retries: 0,
                pw3_retries: 3,
            },
            sig_counter: 0,
            keys: [
                key(KeyUsage::Signing, grips[0]),
                key(KeyUsage::Decryption, grips[1]),
                key(KeyUsage::Authentication, grips[2]),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn known(present: Vec<CardIdent>, infos: Vec<CardInfo>) -> KnownCards {
        let mut cards = KnownCards::default();
        cards.set_present(present);
        for info in infos {
            cards.insert(info);
        }
        cards
    }

    #[test]
    fn first_is_the_first_card_pcsc_lists() {
        assert_eq!(choose(&both(), Wanted::First), Some(&ident(YUBIKEY)));
    }

    #[test]
    fn demand_picks_the_named_card_wherever_it_is_listed() {
        assert_eq!(
            choose(&both(), Wanted::Aid(NITROKEY)),
            Some(&ident(NITROKEY))
        );
        assert_eq!(choose(&both(), Wanted::Aid(YUBIKEY)), Some(&ident(YUBIKEY)));
    }

    #[test]
    fn demand_for_an_absent_card_picks_nothing() {
        let only_yubikey = vec![ident(YUBIKEY)];
        assert_eq!(choose(&only_yubikey, Wanted::Aid(NITROKEY)), None);
        assert_eq!(choose(&[], Wanted::Aid(NITROKEY)), None);
        assert_eq!(choose(&[], Wanted::First), None);
    }

    #[test]
    fn demand_ignores_openpgp_version_bytes_like_stock() {
        // Stock scdaemon reports a YubiKey with version 0000.
        let stock_form = "D2760001240100000006000000010000";
        assert_eq!(
            choose(&both(), Wanted::Aid(stock_form)),
            Some(&ident(YUBIKEY))
        );
        assert!(same_card(&YUBIKEY.to_ascii_lowercase(), YUBIKEY));
    }

    #[test]
    fn same_card_still_compares_serials() {
        assert!(!same_card(YUBIKEY, NITROKEY));
        // Same serial, different manufacturer.
        assert!(!same_card(
            "D276000124010304000F000000010000",
            "D2760001240103040006000000010000"
        ));
        // Not OpenPGP AIDs: compared whole.
        assert!(same_card("D2760000850101", "d2760000850101"));
        assert!(!same_card("D2760000850101", "D2760000850102"));
    }

    #[test]
    fn same_card_rejects_non_ascii_without_panicking() {
        // 32 bytes, with a two-byte char straddling the byte-16 split.
        let odd = format!("D27600012401000é{}", "0".repeat(15));
        assert_eq!(odd.len(), 32);
        assert!(!same_card(&odd, YUBIKEY));
        assert!(!same_card(YUBIKEY, &odd));
    }

    #[test]
    fn finds_a_keygrip_on_the_second_card() {
        let cards = known(both(), vec![yubikey(), nitrokey()]);
        assert_eq!(
            cards.find_keygrip(NITROKEY_SIGN),
            Some((&ident(NITROKEY), KeyUsage::Signing))
        );
        assert_eq!(
            cards.find_keygrip(NITROKEY_ENCR),
            Some((&ident(NITROKEY), KeyUsage::Decryption))
        );
        assert_eq!(
            cards.find_keygrip(YUBIKEY_AUTH),
            Some((&ident(YUBIKEY), KeyUsage::Authentication))
        );
        assert_eq!(cards.find_keygrip(&"0".repeat(40)), None);
    }

    #[test]
    fn unread_lists_present_cards_without_a_snapshot() {
        let cards = known(both(), vec![yubikey()]);
        assert_eq!(cards.unread(), vec![ident(NITROKEY)]);
        let complete = known(both(), vec![yubikey(), nitrokey()]);
        assert_eq!(complete.unread(), Vec::<CardIdent>::new());
    }

    #[test]
    fn enumeration_drops_snapshots_of_removed_cards() {
        let mut cards = known(both(), vec![yubikey(), nitrokey()]);
        cards.set_present(vec![ident(NITROKEY)]);
        assert!(cards.get(YUBIKEY).is_none());
        assert_eq!(cards.find_keygrip(YUBIKEY_SIGN), None);
        assert_eq!(
            cards.get(NITROKEY).map(|info| &info.ident),
            Some(&ident(NITROKEY))
        );
    }

    #[test]
    fn insert_replaces_an_older_snapshot() {
        let mut cards = known(both(), vec![nitrokey()]);
        let mut newer = nitrokey();
        newer.sig_counter = 42;
        cards.insert(newer);
        assert_eq!(cards.get(NITROKEY).map(|info| info.sig_counter), Some(42));
        assert_eq!(cards.listing(None).len(), 1);
    }

    #[test]
    fn listing_puts_the_bound_card_first_then_reader_order() {
        let cards = known(both(), vec![nitrokey(), yubikey()]);
        let order = |bound| -> Vec<&str> {
            cards
                .listing(bound)
                .iter()
                .map(|info| info.ident.as_ref())
                .collect()
        };
        assert_eq!(order(None), vec![YUBIKEY, NITROKEY]);
        assert_eq!(order(Some(YUBIKEY)), vec![YUBIKEY, NITROKEY]);
        assert_eq!(order(Some(NITROKEY)), vec![NITROKEY, YUBIKEY]);
    }

    #[test]
    fn listing_skips_cards_without_a_snapshot() {
        let cards = known(both(), vec![nitrokey()]);
        let listed: Vec<&str> = cards
            .listing(None)
            .iter()
            .map(|i| i.ident.as_ref())
            .collect();
        assert_eq!(listed, vec![NITROKEY]);
    }
}
