//! Minimal Assuan protocol server targeted at `gpg-agent <-> scdaemon` flows.
//!
//! Hand-rolled because the Rust ecosystem has no maintained Assuan server
//! crate. Covers the Tier 1 command surface needed for sign/decrypt/status
//! workflows.

pub mod framing;
pub mod protocol;
pub mod server;
pub mod session;

pub use server::{AssuanServer, CommandHandler, Connection, HandlerError, ServerError};
