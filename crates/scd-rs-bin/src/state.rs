//! Per-connection daemon session state.
//!
//! Lives for the lifetime of one Assuan client connection. Does not retain
//! any PC/SC handles — card access is always fresh via `scd_rs_card`.

use std::collections::HashMap;

use scd_rs_card::{CardIdent, CardInfo, KeyUsage};

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
