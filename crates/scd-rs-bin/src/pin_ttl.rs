//! Resolves the PIN cache TTL from the `SCD_RS_PIN_TTL` environment variable.
//!
//! Accepts simple suffixed durations — `30s`, `10m`, `1h`, `2d`. A bare `0`
//! is treated as `0s` and disables the cache (every sign/decrypt re-prompts).
//! Unrecognized values log a warning and fall through to the default.

use std::sync::OnceLock;
use std::time::Duration;

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
        Ok(raw) => match parse(&raw) {
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

/// Parse a human-friendly duration. Accepts `<number><unit>` where unit is
/// one of `s`/`m`/`h`/`d`. A bare number is treated as seconds.
pub fn parse(s: &str) -> Result<Duration, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty value".into());
    }
    let (num_str, unit) = match trimmed.as_bytes().last().copied() {
        Some(b) if b.is_ascii_digit() => (trimmed, b's'),
        Some(b) => (&trimmed[..trimmed.len() - 1], b),
        None => unreachable!("non-empty string has a last byte"),
    };
    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("bad number `{num_str}`: {e}"))?;
    let multiplier: u64 = match unit {
        b's' => 1,
        b'm' => 60,
        b'h' => 3600,
        b'd' => 86_400,
        other => {
            return Err(format!(
                "unknown unit `{}` (use s/m/h/d)",
                char::from(other)
            ));
        }
    };
    let seconds = num
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration overflow: {num}{}", char::from(unit)))?;
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_number_as_seconds() {
        assert_eq!(parse("0").unwrap(), Duration::from_secs(0));
        assert_eq!(parse("42").unwrap(), Duration::from_secs(42));
    }

    #[test]
    fn parses_suffixed_units() {
        assert_eq!(parse("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse("2d").unwrap(), Duration::from_secs(172_800));
    }

    #[test]
    fn rejects_empty() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(parse("5y").is_err());
        assert!(parse("10ms").is_err()); // two-char unit not supported
    }

    #[test]
    fn rejects_non_numeric() {
        assert!(parse("abc").is_err());
        assert!(parse("m").is_err());
    }

    #[test]
    fn rejects_overflow() {
        assert!(parse("999999999999999999999d").is_err());
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(parse("  10m  ").unwrap(), Duration::from_secs(600));
    }
}
