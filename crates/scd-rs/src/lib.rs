//! `scd-rs` daemon support library.
//!
//! The binary crates in `src/bin/` stay thin; protocol and card glue lives in
//! these modules so they can be unit-tested.

pub mod commands;
pub mod duration_str;
pub mod pin_ttl;
pub mod pinentry;
pub mod pool_ttl;
pub mod state;

pub use commands::ScdHandler;
pub use state::Session;
