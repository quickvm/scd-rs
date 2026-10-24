//! Card stand-ins for tests in crates that hold a [`PooledCard`].
//!
//! Compiled only with the `test-support` feature. The fake card answers the
//! two APDUs `Card::<Open>::new` sends (SELECT and the ARD read) and rejects
//! everything else, so a pooled handle built here can never reach a real
//! card or verify a PIN.

use std::time::Instant;

use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};
use openpgp_card::state::Open;
use openpgp_card::Card;

use crate::PooledCard;

/// Application Related Data from a `YubiKey` 5, taken from the parser tests
/// of `openpgp-card` 0.6.1 (`src/ocard/tlv.rs`, `test_tlv_yubi5`).
const ARD_HEX: &str = concat!(
    "6e8201374f10d27600012401030400061601918000005f520800730000e00590007f740381012073820110c00a",
    "7d000bfe080000ff0000c106010800001100c206010800001100c306010800001100da06010800001100c407ff",
    "7f7f7f030003c55000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000c650",
    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000000000cd100000000000000000",
    "0000000000000000de0801000200030081027f660802020bfe02020bfed6020020d7020020d8020020d9020020",
);

const STATUS_OK: [u8; 2] = [0x90, 0x00];
const STATUS_INS_NOT_SUPPORTED: [u8; 2] = [0x6D, 0x00];

struct FakeBackend;

struct FakeTransaction;

impl CardBackend for FakeBackend {
    fn limit_card_caps(&self, card_caps: CardCaps) -> CardCaps {
        card_caps
    }

    fn transaction(
        &mut self,
        _reselect_application: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        Ok(Box::new(FakeTransaction))
    }
}

impl CardTransaction for FakeTransaction {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        match cmd {
            [0x00, 0xA4, 0x04, 0x00, ..] => Ok(STATUS_OK.to_vec()),
            [0x00, 0xCA, 0x00, 0x6E, ..] => {
                let mut reply = decode_hex(ARD_HEX);
                reply.extend_from_slice(&STATUS_OK);
                Ok(reply)
            }
            _ => Ok(STATUS_INS_NOT_SUPPORTED.to_vec()),
        }
    }

    fn feature_pinpad_verify(&self) -> bool {
        false
    }

    fn feature_pinpad_modify(&self) -> bool {
        false
    }

    fn pinpad_verify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("fake card has no pinpad".into()))
    }

    fn pinpad_modify(
        &mut self,
        _pin: PinType,
        _card_caps: &Option<CardCaps>,
    ) -> Result<Vec<u8>, SmartcardError> {
        Err(SmartcardError::Error("fake card has no pinpad".into()))
    }

    fn was_reset(&self) -> bool {
        false
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

/// A pooled handle labelled `ident`, with both PW1 modes marked verified,
/// backed by the fake card above.
#[must_use]
pub fn pooled_card(ident: &str) -> PooledCard {
    let backend: Box<dyn CardBackend + Send + Sync> = Box::new(FakeBackend);
    let card = Card::<Open>::new(backend).expect("fake card ARD parses");
    PooledCard {
        card,
        ident: ident.to_string(),
        last_used: Instant::now(),
        pw1_sign_fresh: true,
        pw1_user_fresh: true,
        signing_pin_valid_once: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pooled_card_opens_on_fake_backend() {
        let pool = pooled_card("D276000124010304000FE9B8A8420000");
        assert_eq!(pool.ident(), "D276000124010304000FE9B8A8420000");
    }
}
