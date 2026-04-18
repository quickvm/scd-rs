//! Sequoia-backed `OpenPGP` card access for `scd-rs`.
//!
//! Enforces per-operation PC/SC handle discipline: every externally visible
//! operation opens a fresh `PcscBackend` → `Card<Open>` → `Card<Transaction>`
//! chain and drops it before returning. Nothing in this crate is permitted to
//! retain a card handle across calls.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CardError {
    #[error("no OpenPGP card found")]
    NotFound,
    #[error("card identifier mismatch: expected {expected}, found {found}")]
    IdentMismatch { expected: String, found: String },
    #[error("PC/SC error: {0}")]
    Pcsc(String),
    #[error("OpenPGP card error: {0}")]
    Card(String),
    #[error("bad PIN")]
    BadPin,
}
