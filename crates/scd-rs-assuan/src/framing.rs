//! Assuan line I/O: byte-level escaping and DATA-line chunking.
//!
//! Assuan transports bytes over a newline-delimited protocol where a handful
//! of control bytes (`%`, `\r`, `\n`) must be percent-encoded as uppercase
//! `%XX`. Everything else passes through verbatim, so signatures,
//! ciphertexts, and other binary payloads ride through intact. Every line
//! (including the leading `D `, `S `, etc. and the trailing `\n`) must be
//! ≤ `MAX_LINE_LEN` bytes; `encode_data_lines` chunks to satisfy that.

use thiserror::Error;

/// Assuan line-length ceiling, inclusive of the trailing `\n`.
pub const MAX_LINE_LEN: usize = 1000;

/// Escape one byte into `out`, emitting either the raw byte or `%XX`.
fn push_escaped(out: &mut Vec<u8>, b: u8) {
    match b {
        b'%' | b'\n' | b'\r' => {
            out.push(b'%');
            let hi = HEX[(b >> 4) as usize];
            let lo = HEX[(b & 0x0F) as usize];
            out.push(hi);
            out.push(lo);
        }
        _ => out.push(b),
    }
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Length an Assuan-escaped encoding of `b` will consume (1 or 3).
const fn escaped_len(b: u8) -> usize {
    match b {
        b'%' | b'\n' | b'\r' => 3,
        _ => 1,
    }
}

/// Encode `bytes` into a single escaped buffer (no chunking, no `D ` prefix).
#[must_use]
pub fn encode_data(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        push_escaped(&mut out, b);
    }
    out
}

/// Encode `bytes` into one or more `D <payload>` lines, each ≤ `MAX_LINE_LEN`
/// bytes when emitted with a trailing newline. The returned `Vec<u8>`s do
/// **not** include the trailing newline — the caller adds it.
#[must_use]
pub fn encode_data_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    // Budget leaves room for the `D ` prefix (2) and `\n` terminator (1).
    const BUDGET: usize = MAX_LINE_LEN - 3;
    let mut lines = Vec::new();
    let mut cur = Vec::with_capacity(BUDGET + 2);
    cur.extend_from_slice(b"D ");

    for &b in bytes {
        if cur.len() - 2 + escaped_len(b) > BUDGET {
            lines.push(cur);
            cur = Vec::with_capacity(BUDGET + 2);
            cur.extend_from_slice(b"D ");
        }
        push_escaped(&mut cur, b);
    }

    if cur.len() > 2 {
        lines.push(cur);
    }
    lines
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("truncated `%XX` escape")]
    TruncatedEscape,
    #[error("invalid hex digit `{0}` in escape")]
    InvalidHex(u8),
}

/// Decode an Assuan-escaped payload back into raw bytes.
pub fn decode_data(input: &[u8]) -> Result<Vec<u8>, FrameError> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'%' {
            if i + 2 >= input.len() {
                return Err(FrameError::TruncatedEscape);
            }
            let hi = hex_digit(input[i + 1])?;
            let lo = hex_digit(input[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, FrameError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        other => Err(FrameError::InvalidHex(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_simple_ascii() {
        let input = b"hello world";
        let encoded = encode_data(input);
        assert_eq!(encoded, input);
        assert_eq!(decode_data(&encoded).unwrap(), input);
    }

    #[test]
    fn escapes_percent_cr_lf() {
        let input = b"a%b\nc\rd";
        let encoded = encode_data(input);
        assert_eq!(encoded, b"a%25b%0Ac%0Dd");
        assert_eq!(decode_data(&encoded).unwrap(), input);
    }

    #[test]
    fn encodes_binary_bytes_verbatim() {
        let input: Vec<u8> = (0u8..=255).collect();
        let encoded = encode_data(&input);
        let decoded = decode_data(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn decode_accepts_lowercase_hex() {
        assert_eq!(decode_data(b"%0a%0d%25").unwrap(), b"\n\r%");
    }

    #[test]
    fn decode_rejects_truncated_escape() {
        assert_eq!(
            decode_data(b"abc%1"),
            Err(FrameError::TruncatedEscape)
        );
    }

    #[test]
    fn decode_rejects_invalid_hex() {
        assert!(matches!(
            decode_data(b"%ZZ"),
            Err(FrameError::InvalidHex(_))
        ));
    }

    #[test]
    fn encode_data_lines_respects_max_line_len() {
        // All raw bytes that do NOT need escaping.
        let input = vec![b'x'; 5_000];
        let lines = encode_data_lines(&input);
        assert!(!lines.is_empty());
        for line in &lines {
            assert!(line.starts_with(b"D "));
            // Each emitted line plus trailing newline must be ≤ MAX_LINE_LEN.
            assert!(line.len() < MAX_LINE_LEN);
        }
    }

    #[test]
    fn encode_data_lines_handles_escapes_at_boundary() {
        // Worst case: all bytes trigger escaping, so every input byte costs 3.
        let input = vec![b'%'; 1_000];
        let lines = encode_data_lines(&input);
        for line in &lines {
            assert!(line.len() < MAX_LINE_LEN);
        }
        // Concatenate payloads and decode — must roundtrip.
        let mut joined = Vec::new();
        for line in &lines {
            joined.extend_from_slice(&line[2..]);
        }
        assert_eq!(decode_data(&joined).unwrap(), input);
    }

    #[test]
    fn encode_data_lines_empty_input_emits_no_lines() {
        assert!(encode_data_lines(&[]).is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10_000))]

        #[test]
        fn roundtrip_encode_decode(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let encoded = encode_data(&bytes);
            let decoded = decode_data(&encoded).unwrap();
            prop_assert_eq!(decoded, bytes);
        }

        #[test]
        fn roundtrip_encode_data_lines(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let lines = encode_data_lines(&bytes);
            // Verify the line-length invariant holds for every emitted line.
            for line in &lines {
                prop_assert!(line.len() < MAX_LINE_LEN);
                prop_assert!(line.starts_with(b"D "));
            }
            // Concatenate payloads (strip `D ` prefix) and decode.
            let mut joined = Vec::new();
            for line in &lines {
                joined.extend_from_slice(&line[2..]);
            }
            let decoded = decode_data(&joined).unwrap();
            prop_assert_eq!(decoded, bytes);
        }
    }
}
