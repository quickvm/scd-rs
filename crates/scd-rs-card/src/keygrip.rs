//! `GnuPG` keygrip computation.
//!
//! A keygrip is the 20-byte SHA-1 digest of a canonical representation of a
//! public key, used by `gpg-agent` to index keys independent of their
//! fingerprint. For RSA the input is the modulus `n` as libgcrypt feeds it
//! to the hash when building keys through `gcry_sexp_build("(n %m)", ...)`,
//! i.e. unsigned big-endian bytes with a leading `0x00` prepended whenever
//! the high bit of the magnitude is set (the `GCRYMPI_FMT_STD` convention).

use sha1::{Digest, Sha1};

/// Compute the keygrip for an RSA public key given its modulus `n` as
/// unsigned big-endian bytes (no leading zero padding).
///
/// libgcrypt's `gcry_sexp_build("(n %m)", mpi)` emits the MPI in
/// `GCRYMPI_FMT_STD`; the signed two's-complement form that prepends a
/// leading `0x00` byte whenever the high bit of the magnitude is set, so
/// the value is unambiguously unsigned. The keygrip SHA-1 is computed over
/// that serialization, not over the stripped magnitude alone.
#[must_use]
pub fn rsa_keygrip(n: &[u8]) -> [u8; 20] {
    let stripped = strip_leading_zeros(n);
    let mut hasher = Sha1::new();
    if stripped.first().copied().unwrap_or(0) & 0x80 != 0 {
        hasher.update([0x00]);
    }
    hasher.update(stripped);
    hasher.finalize().into()
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// Format 20 bytes as uppercase hex, matching scdaemon output.
#[must_use]
pub fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0F));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0x00, 0x00, 0xAB, 0xCD]), &[0xAB, 0xCD]);
        assert_eq!(strip_leading_zeros(&[0xAB, 0xCD]), &[0xAB, 0xCD]);
        assert_eq!(strip_leading_zeros(&[0x00]), &[] as &[u8]);
    }

    #[test]
    fn format_hex_uppercase() {
        assert_eq!(format_hex(&[0xAB, 0xCD, 0x01]), "ABCD01");
        assert_eq!(format_hex(&[0x00, 0xFF]), "00FF");
    }

    #[test]
    fn rsa_keygrip_no_leading_zero_prepended_when_high_bit_clear() {
        // High bit of 0x01 is clear → no leading zero prepended.
        // SHA-1(01020304) = 12DADA1FFF4D4787ADE3333147202C3B443E376F
        let grip = rsa_keygrip(&[0x01u8, 0x02, 0x03, 0x04]);
        assert_eq!(format_hex(&grip), "12DADA1FFF4D4787ADE3333147202C3B443E376F");
    }

    #[test]
    fn rsa_keygrip_leading_zero_prepended_when_high_bit_set() {
        // High bit of 0xFF is set → libgcrypt would prepend 0x00 for sign.
        // SHA-1(00FF) = AA3E5DCDD77B153F2E59BD0D8794FDE33CB4E486
        let grip = rsa_keygrip(&[0xFFu8]);
        assert_eq!(format_hex(&grip), "AA3E5DCDD77B153F2E59BD0D8794FDE33CB4E486");
    }
}
