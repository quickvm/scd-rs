//! `scd-rs` daemon support library.
//!
//! The binary crates in `src/bin/` stay thin; protocol and card glue lives in
//! these modules so they can be unit-tested.

pub mod commands;
pub mod pinentry;
pub mod state;
