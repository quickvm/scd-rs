//! Resolves the PIN cache TTL from the `SCD_RS_PIN_TTL` environment variable.
//!
//! Accepts simple suffixed durations — `30s`, `10m`, `1h`, `2d`. A bare `0`
//! is treated as `0s` and disables the cache (every sign/decrypt re-prompts).
//! Unrecognized values log a warning and fall through to the default.

use std::sync::OnceLock;
use std::time::Duration;

use crate::duration_str;

/// Default TTL when `SCD_RS_PIN_TTL` is unset. Matches the 10 min window
/// gpg-agent itself uses for its `default-cache-ttl`.
pub const DEFAULT_PIN_TTL: Duration = Duration::from_secs(600);

const ENV_VAR: &str = "SCD_RS_PIN_TTL";

static RESOLVED: OnceLock<Duration> = OnceLock::new();

/// Return the configured PIN cache TTL. Result is memoized for the lifetime
/// of the process; env changes after first call are ignored.
#[must_use]
pub fn configured() -> Duration {
    *RESOLVED.get_or_init(|| match std::env::var(ENV_VAR) {
        Err(_) => DEFAULT_PIN_TTL,
        Ok(raw) => match duration_str::parse(&raw) {
            Ok(dur) => {
                tracing::info!(
                    seconds = dur.as_secs(),
                    raw = %raw,
                    "PIN cache TTL from {ENV_VAR}"
                );
                dur
            }
            Err(msg) => {
                tracing::warn!(
                    raw = %raw,
                    error = %msg,
                    default_seconds = DEFAULT_PIN_TTL.as_secs(),
                    "invalid {ENV_VAR}; using default"
                );
                DEFAULT_PIN_TTL
            }
        },
    })
}
