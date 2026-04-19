//! Shared parser for `<number><unit>` durations (`30s`, `10m`, `1h`, `2d`).
//!
//! A bare number is treated as seconds. `0` disables whatever the caller
//! uses the duration for.

use std::time::Duration;

/// Parse a human-friendly duration. Accepts `<number><unit>` where unit is
/// one of `s`/`m`/`h`/`d`. A bare number is seconds.
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
