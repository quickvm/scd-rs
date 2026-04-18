//! Assuan line parsing.
//!
//! The daemon reads client lines and emits server lines. Parsing is
//! centralised here; emission is done directly via `Connection` helpers
//! because each kind of outgoing line follows a different shape and
//! byte-stream rule.

use thiserror::Error;

use crate::framing::{decode_data, FrameError, MAX_LINE_LEN};

/// A single line received from the Assuan peer (typically `gpg-agent`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientLine {
    /// Command: a verb plus trimmed argument string.
    Command { verb: String, args: String },
    /// `D` line carrying already-decoded raw bytes.
    Data(Vec<u8>),
    /// `END` line terminating an `INQUIRE` response payload.
    End,
    /// `CAN` — client cancels the in-flight operation.
    Cancel,
    /// `BYE` — client closes the session.
    Bye,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("empty line")]
    EmptyLine,
    #[error("line longer than {MAX_LINE_LEN} bytes ({0} bytes)")]
    LineTooLong(usize),
    #[error("non-ASCII byte 0x{0:02X} in command verb")]
    NonAsciiVerb(u8),
    #[error("bad DATA encoding: {0}")]
    BadData(#[from] FrameError),
}

/// Parse one newline-terminated (or not) line into a `ClientLine`.
///
/// The caller should have already stripped the trailing newline, but we
/// tolerate it being present.
pub fn parse_client_line(line: &[u8]) -> Result<ClientLine, ProtocolError> {
    let line = strip_trailing_newline(line);

    if line.is_empty() {
        return Err(ProtocolError::EmptyLine);
    }
    if line.len() > MAX_LINE_LEN {
        return Err(ProtocolError::LineTooLong(line.len()));
    }

    // Fast paths for single-keyword lines.
    match line {
        b"END" | b"end" => return Ok(ClientLine::End),
        b"CAN" | b"can" => return Ok(ClientLine::Cancel),
        b"BYE" | b"bye" => return Ok(ClientLine::Bye),
        _ => {}
    }

    // `D ` prefix is the Assuan data line.
    if let Some(payload) = line.strip_prefix(b"D ") {
        return Ok(ClientLine::Data(decode_data(payload)?));
    }
    if line == b"D" {
        return Ok(ClientLine::Data(Vec::new()));
    }

    // Otherwise it's a command: VERB[ ARGS...]
    let (verb_bytes, args_bytes) = match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], line[i + 1..].trim_ascii()),
        None => (line, &[][..]),
    };

    for &b in verb_bytes {
        if !b.is_ascii() {
            return Err(ProtocolError::NonAsciiVerb(b));
        }
    }

    let verb = String::from_utf8_lossy(verb_bytes).to_ascii_uppercase();
    let args = String::from_utf8_lossy(args_bytes).into_owned();
    Ok(ClientLine::Command { verb, args })
}

fn strip_trailing_newline(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && matches!(line[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_command_with_no_args() {
        assert_eq!(
            parse_client_line(b"RESET\n").unwrap(),
            ClientLine::Command {
                verb: "RESET".into(),
                args: String::new()
            }
        );
    }

    #[test]
    fn parses_command_with_args() {
        assert_eq!(
            parse_client_line(b"SETDATA 48656C6C6F\n").unwrap(),
            ClientLine::Command {
                verb: "SETDATA".into(),
                args: "48656C6C6F".into()
            }
        );
    }

    #[test]
    fn uppercases_verb() {
        let cmd = parse_client_line(b"setdata foo").unwrap();
        match cmd {
            ClientLine::Command { verb, .. } => assert_eq!(verb, "SETDATA"),
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn parses_data_line() {
        assert_eq!(
            parse_client_line(b"D hello%25world\n").unwrap(),
            ClientLine::Data(b"hello%world".to_vec())
        );
    }

    #[test]
    fn parses_empty_data_line() {
        assert_eq!(parse_client_line(b"D\n").unwrap(), ClientLine::Data(Vec::new()));
    }

    #[test]
    fn parses_end_cancel_bye() {
        assert_eq!(parse_client_line(b"END\n").unwrap(), ClientLine::End);
        assert_eq!(parse_client_line(b"CAN\n").unwrap(), ClientLine::Cancel);
        assert_eq!(parse_client_line(b"BYE").unwrap(), ClientLine::Bye);
    }

    #[test]
    fn rejects_empty_line() {
        assert_eq!(parse_client_line(b"\n"), Err(ProtocolError::EmptyLine));
        assert_eq!(parse_client_line(b""), Err(ProtocolError::EmptyLine));
    }

    #[test]
    fn rejects_overlong_line() {
        let long = vec![b'x'; MAX_LINE_LEN + 1];
        assert!(matches!(
            parse_client_line(&long),
            Err(ProtocolError::LineTooLong(_))
        ));
    }

    #[test]
    fn trims_args_whitespace() {
        let cmd = parse_client_line(b"FOO    bar baz   ").unwrap();
        match cmd {
            ClientLine::Command { args, .. } => assert_eq!(args, "bar baz"),
            _ => panic!("expected command"),
        }
    }
}
