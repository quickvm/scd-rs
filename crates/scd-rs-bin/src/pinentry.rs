//! Pinentry bridge: turns an `INQUIRE NEEDPIN` into raw PIN bytes.
//!
//! `gpg-agent` owns the pinentry UX; we just ask for the PIN with a
//! scdaemon-style prompt and collect the bytes it returns.

use scd_rs_assuan::{Connection, ServerError};
use secrecy::SecretBox;
use zeroize::Zeroize;

/// Ask the client (gpg-agent) to prompt the user for the card PIN.
///
/// Returns the PIN as raw bytes wrapped in `SecretBox`, which zeroises the
/// buffer when dropped.
pub async fn request_pin(
    conn: &mut Connection,
    prompt: &str,
) -> Result<SecretBox<Vec<u8>>, ServerError> {
    let mut bytes = conn.inquire("NEEDPIN", prompt).await?;
    // Wrap before anything can panic / return early past this point.
    let pin = SecretBox::new(Box::new(bytes.clone()));
    bytes.zeroize();
    Ok(pin)
}

/// Build the structured prompt scdaemon uses for `INQUIRE NEEDPIN`. Values
/// flow into pinentry's labelled-field display.
#[must_use]
pub fn build_prompt(serial: &str, holder: Option<&str>, counter: Option<u32>) -> String {
    let mut out = String::from("||Please unlock the card%0A%0A");
    out.push_str("Serial: ");
    out.push_str(serial);
    if let Some(h) = holder {
        out.push_str("%0AHolder: ");
        out.push_str(h);
    }
    if let Some(c) = counter {
        out.push_str("%0ACounter: ");
        out.push_str(&c.to_string());
    }
    out
}
