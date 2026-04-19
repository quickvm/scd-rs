//! Resolves the card-handle pool TTL from `SCD_RS_CARD_POOL_TTL`.
//!
//! Syntax mirrors [`crate::pin_ttl`]; `<n><unit>`, unit = `s`/`m`/`h`/`d`.
//! A bare `0` (the default) disables pooling, meaning every card operation
//! opens a fresh PC/SC handle (the original Phase-1 discipline). Enable
//! with e.g. `SCD_RS_CARD_POOL_TTL=5` for a 5 s window.

use std::sync::OnceLock;
use std::time::Duration;

use crate::duration_str;

/// Pooling is off by default. Enabling it reintroduces the class of
/// stale-handle bugs that stock scdaemon has; the TTL bound keeps that
/// surface area small but non-zero.
pub const DEFAULT_POOL_TTL: Duration = Duration::from_secs(0);

const ENV_VAR: &str = "SCD_RS_CARD_POOL_TTL";

static RESOLVED: OnceLock<Duration> = OnceLock::new();

/// Return the configured card-handle pool TTL. Result is memoized for the
/// lifetime of the process.
#[must_use]
pub fn configured() -> Duration {
    *RESOLVED.get_or_init(|| match std::env::var(ENV_VAR) {
        Err(_) => DEFAULT_POOL_TTL,
        Ok(raw) => match duration_str::parse(&raw) {
            Ok(dur) => {
                if dur.is_zero() {
                    tracing::info!(raw = %raw, "card-handle pool disabled via {ENV_VAR}=0");
                } else {
                    tracing::info!(
                        seconds = dur.as_secs(),
                        raw = %raw,
                        "card-handle pool enabled via {ENV_VAR}"
                    );
                }
                dur
            }
            Err(msg) => {
                tracing::warn!(
                    raw = %raw,
                    error = %msg,
                    "invalid {ENV_VAR}; pool stays disabled"
                );
                DEFAULT_POOL_TTL
            }
        },
    })
}
