//! Tier 1 Assuan command handlers.
//!
//! Each command corresponds to one verb observed in the Phase 0 scdaemon
//! trace (see `docs/required-commands.md` and `docs/assuan-traces/`).

use scd_rs_assuan::{CommandHandler, Connection, HandlerError};
use scd_rs_card::{
    decrypt, enumerate_cards, read_card_info, sign_digest_info, CardInfo, KeyInfo, KeyUsage,
};
use secrecy::ExposeSecret;

use crate::pinentry::{build_prompt, request_pin};
use crate::state::{KnownKeys, PinMode, Session};

/// Assuan error codes mirrored from gpg-agent / scdaemon.
///
/// The full space is defined in libgpg-error. We only surface the handful
/// the protocol actually uses.
mod err {
    pub const GENERAL: u32 = 100_663_297; // GPG_ERR_GENERAL with source=SCD
    pub const NOT_SUPPORTED: u32 = 100_663_363;
    pub const INV_ARG: u32 = 100_663_349;
    pub const NO_CARD: u32 = 100_663_361;
    pub const NO_SECRET_KEY: u32 = 100_663_313;
}

/// The root command dispatcher.
pub struct ScdHandler;

impl CommandHandler for ScdHandler {
    type Session = Session;

    /// gpg-agent issues RESTART between logical flows (card-status → sign →
    /// decrypt, etc.) and expects per-flow state to clear. Clear SETDATA and
    /// the keygrip cache, but preserve the PIN cache so subsequent sign/
    /// decrypt operations don't re-prompt the user within the TTL window.
    fn reset_session(&self, session: &mut Session) {
        // RESTART ends a logical flow (card-status → sign → decrypt), so only
        // the per-flow buffer needs clearing. Card identity, enumerated keys,
        // cached metadata, and the PIN are all still valid for the next flow
        // and are expensive to rebuild, so we keep them.
        session.setdata.clear();
    }

    async fn handle(
        &self,
        session: &mut Session,
        conn: &mut Connection,
        verb: &str,
        args: &str,
    ) -> Result<(), HandlerError> {
        tracing::info!(verb, args, "command");
        match verb {
            "GETINFO" => getinfo(conn, args).await,
            "OPTION" => {
                // gpg-agent sends `OPTION event-signal=NN` and similar
                // per-connection settings. We accept and ignore; any
                // option we actually need will surface via trace logs.
                tracing::debug!(option = args, "OPTION (ignored)");
                Ok(())
            }
            "SERIALNO" => serialno(session, conn, args).await,
            "LEARN" => learn(session, conn, args).await,
            "KEYINFO" => keyinfo(session, conn, args).await,
            "GETATTR" => getattr(session, conn, args).await,
            "SETDATA" => setdata(session, args),
            "PKSIGN" => pksign(session, conn, args).await,
            "PKDECRYPT" => pkdecrypt(session, conn, args).await,
            _ => Err(HandlerError::new(
                err::NOT_SUPPORTED,
                format!("unknown command: {verb}"),
            )),
        }
    }
}

async fn getinfo(conn: &mut Connection, args: &str) -> Result<(), HandlerError> {
    match args {
        "version" => {
            // Prefix with a GnuPG-looking version so gpg-agent's "outdated
            // scdaemon" check passes, then tag our own.
            conn.write_data(
                format!(
                    "{} (scd-rs {})",
                    GPG_VERSION_COMPAT,
                    env!("CARGO_PKG_VERSION"),
                )
                .as_bytes(),
            )
            .await
            .map_err(|e| handler_io(&e))?;
            Ok(())
        }
        "socket_name" | "status" | "reader_list" | "deny_admin" | "app_list"
        | "card_list" | "connections" => Err(HandlerError::new(
            err::NOT_SUPPORTED,
            format!("GETINFO {args} not supported"),
        )),
        other => Err(HandlerError::new(
            err::NOT_SUPPORTED,
            format!("GETINFO {other} not supported"),
        )),
    }
}

/// `GnuPG` version we pretend to be for the purposes of the `GETINFO version`
/// check. Bump this alongside the fedora-stable scdaemon release so we keep
/// passing the "outdated server" guard.
const GPG_VERSION_COMPAT: &str = "2.4.9";

async fn serialno(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    // gpg-agent issues SERIALNO and SERIALNO --all repeatedly during every
    // sign/decrypt flow to re-confirm the card is still present. Re-opening
    // the PC/SC context each time costs ~1 second on the Nitrokey. If we
    // already bound a card in this session, emit the cached ident and skip
    // the enumeration; if the card has actually been pulled, the next real
    // card operation will return a PC/SC error and we'll reconcile.
    //
    // `SERIALNO --reset` (not yet used by our gpg-agent) should force a real
    // enumeration.
    let force_reset = args.split_whitespace().any(|t| t == "--reset");
    if !force_reset {
        if let Some(ident) = &session.current_ident {
            conn.write_status("SERIALNO", ident)
                .await
                .map_err(|e| handler_io(&e))?;
            tracing::info!("SERIALNO served from session");
            return Ok(());
        }
    }
    let idents = enumerate_cards().map_err(card_err)?;
    let chosen = idents.into_iter().next().ok_or_else(|| {
        HandlerError::new(err::NO_CARD, "no OpenPGP card present")
    })?;
    conn.write_status("SERIALNO", chosen.as_ref())
        .await
        .map_err(|e| handler_io(&e))?;
    if session.current_ident.as_deref() != Some(chosen.as_ref()) {
        session.cached_info = None;
        session.known_keys = KnownKeys::default();
    }
    session.current_ident = Some(chosen.0);
    Ok(())
}

async fn learn(
    session: &mut Session,
    conn: &mut Connection,
    _args: &str,
) -> Result<(), HandlerError> {
    // LEARN --force semantically refreshes card state; always re-read.
    let info = refresh_card_info(session)?;
    emit_learn_status(conn, &info).await?;
    Ok(())
}

/// Return the session's cached `CardInfo`, populating it on first access.
/// Subsequent callers within the same session reuse the cached snapshot,
/// which cuts several seconds off sign and decrypt flows.
fn ensure_card_info(session: &mut Session) -> Result<&CardInfo, HandlerError> {
    if session.cached_info.is_none() {
        tracing::info!("CardInfo cache miss — refreshing from card");
        let _ = refresh_card_info(session)?;
    } else {
        tracing::info!("CardInfo cache hit");
    }
    Ok(session.cached_info.as_ref().expect("just populated"))
}

/// Force a fresh read from the card, updating both the info cache and the
/// keygrip map.
fn refresh_card_info(session: &mut Session) -> Result<CardInfo, HandlerError> {
    let ident = require_ident(session)?;
    let info = read_card_info(&ident).map_err(card_err)?;
    session.known_keys = KnownKeys::from_card_info(&info);
    session.cached_info = Some(info.clone());
    Ok(info)
}

async fn emit_learn_status(conn: &mut Connection, info: &CardInfo) -> Result<(), HandlerError> {
    // Matches the order and shape of the Phase 0 LEARN --force trace.
    status(conn, "READER", &format!("{} card reader", info.manufacturer_name)).await?;
    status(conn, "SERIALNO", info.ident.as_ref()).await?;
    status(conn, "APPTYPE", "openpgp").await?;
    status(conn, "APPVERSION", &format!("{:X}", info.app_version_bcd)).await?;
    status(
        conn,
        "MANUFACTURER",
        &format!("{} {}", info.manufacturer_id, info.manufacturer_name),
    )
    .await?;
    if let Some(name) = &info.cardholder_name {
        status(conn, "DISP-NAME", name).await?;
    }
    if let Some(lang) = &info.cardholder_lang {
        status(conn, "DISP-LANG", lang).await?;
    }
    if let Some(url) = &info.pubkey_url {
        status(conn, "PUBKEY-URL", url).await?;
    }
    for (idx, key) in info.keys.iter().enumerate() {
        if let Some(fp) = &key.fingerprint {
            status(conn, "KEY-FPR", &format!("{} {fp}", idx + 1)).await?;
        }
        if let Some(ts) = key.created {
            status(conn, "KEY-TIME", &format!("{} {ts}", idx + 1)).await?;
        }
    }
    status(
        conn,
        "CHV-STATUS",
        &format!(
            // First digit mirrors stock scdaemon: 1 = PW1 valid for multiple
            // PSO:CDS operations, 0 = single-use ("Signature PIN: forced").
            "+{}+{}+{}+{}+{}+{}+{}",
            u8::from(info.chv_status.signing_pin_multi_op),
            info.chv_status.pw1_max_len,
            info.chv_status.rc_max_len,
            info.chv_status.pw3_max_len,
            info.chv_status.pw1_retries,
            info.chv_status.rc_retries,
            info.chv_status.pw3_retries,
        ),
    )
    .await?;
    status(conn, "SIG-COUNTER", &info.sig_counter.to_string()).await?;
    for key in &info.keys {
        status(conn, "KEYPAIRINFO", &keypairinfo_payload(key)).await?;
    }
    Ok(())
}

async fn status(conn: &mut Connection, keyword: &str, data: &str) -> Result<(), HandlerError> {
    conn.write_status(keyword, data).await.map_err(|e| handler_io(&e))
}

fn keypairinfo_payload(key: &KeyInfo) -> String {
    let grip = key.keygrip.as_deref().unwrap_or("X");
    let slot = key.usage.openpgp_slot();
    let usage = key.usage.scd_usage();
    let created = key.created.unwrap_or(0);
    let algo = key.algorithm.as_deref().map_or_else(
        || "unknown".into(),
        algo_to_scd_token,
    );
    format!("{grip} OPENPGP.{slot} {usage} {created} {algo}")
}

/// Convert Sequoia's `AlgorithmAttributes::Display` format (e.g.
/// `"RSA 4096 [e 32]"`) into scdaemon's compact form (`"rsa4096"`).
fn algo_to_scd_token(algo: &str) -> String {
    let lower = algo.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("rsa ") {
        let bits = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>();
        return format!("rsa{bits}");
    }
    if lower.contains("ed25519") {
        return "ed25519".into();
    }
    if lower.contains("cv25519") {
        return "cv25519".into();
    }
    // Fallback: first word, lowercased, spaces stripped.
    lower.split_whitespace().next().unwrap_or("unknown").into()
}

async fn keyinfo(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    // Three forms: `--list`, `--list=<filter>`, or `<keygrip>`.
    if let Some(filter) = args.strip_prefix("--list") {
        let filter = filter.strip_prefix('=').unwrap_or("").trim();
        keyinfo_list(session, conn, filter).await
    } else if !args.is_empty() {
        keyinfo_single(session, conn, args.trim()).await
    } else {
        Err(HandlerError::new(err::INV_ARG, "KEYINFO requires arg"))
    }
}

async fn keyinfo_list(
    session: &mut Session,
    conn: &mut Connection,
    filter: &str,
) -> Result<(), HandlerError> {
    let info = ensure_card_info(session)?.clone();
    for key in &info.keys {
        let matches = match filter {
            "" => true,
            "encr" => key.usage == KeyUsage::Decryption,
            "sign" => key.usage == KeyUsage::Signing,
            "auth" => key.usage == KeyUsage::Authentication,
            other => {
                return Err(HandlerError::new(
                    err::INV_ARG,
                    format!("unknown KEYINFO filter {other}"),
                ));
            }
        };
        if !matches {
            continue;
        }
        let Some(grip) = &key.keygrip else {
            continue;
        };
        conn.write_status(
            "KEYINFO",
            &format!(
                "{grip} T {} OPENPGP.{} {}",
                info.ident,
                key.usage.openpgp_slot(),
                key.usage.scd_usage()
            ),
        )
        .await
        .map_err(|e| handler_io(&e))?;
    }
    Ok(())
}

async fn keyinfo_single(
    session: &mut Session,
    conn: &mut Connection,
    keygrip: &str,
) -> Result<(), HandlerError> {
    let keygrip_upper = keygrip.to_ascii_uppercase();
    let usage = if let Some(u) = session.known_keys.usage(&keygrip_upper) {
        u
    } else {
        let info = ensure_card_info(session)?;
        let Some(found) = info
            .keys
            .iter()
            .find(|k| k.keygrip.as_deref() == Some(keygrip_upper.as_str()))
            .map(|k| k.usage)
        else {
            return Err(HandlerError::new(
                err::NO_SECRET_KEY,
                format!("unknown keygrip {keygrip}"),
            ));
        };
        found
    };
    let ident = session
        .known_keys
        .ident()
        .map(ToString::to_string)
        .or_else(|| session.current_ident.clone())
        .unwrap_or_default();
    conn.write_status(
        "KEYINFO",
        &format!(
            "{keygrip_upper} T {ident} OPENPGP.{} {}",
            usage.openpgp_slot(),
            usage.scd_usage()
        ),
    )
    .await
    .map_err(|e| handler_io(&e))?;
    Ok(())
}

async fn getattr(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    let info = ensure_card_info(session)?.clone();
    match args {
        "KEY-ATTR" => {
            for (idx, key) in info.keys.iter().enumerate() {
                let algo = key.algorithm.as_deref().map_or_else(
                    || "unknown".into(),
                    algo_to_scd_token,
                );
                // For RSA the scdaemon format is `<slot> 1 rsa<bits> <e_bits> 1`.
                status(conn, "KEY-ATTR", &format!("{} 1 {algo} 32 1", idx + 1)).await?;
            }
        }
        "KEY-FPR" => {
            for (idx, key) in info.keys.iter().enumerate() {
                if let Some(fp) = &key.fingerprint {
                    status(conn, "KEY-FPR", &format!("{} {fp}", idx + 1)).await?;
                }
            }
        }
        "KEY-TIME" => {
            for (idx, key) in info.keys.iter().enumerate() {
                if let Some(ts) = key.created {
                    status(conn, "KEY-TIME", &format!("{} {ts}", idx + 1)).await?;
                }
            }
        }
        "SERIALNO" => {
            status(conn, "SERIALNO", info.ident.as_ref()).await?;
        }
        "APPTYPE" => {
            status(conn, "APPTYPE", "openpgp").await?;
        }
        "CHV-STATUS" => {
            let c = &info.chv_status;
            status(
                conn,
                "CHV-STATUS",
                &format!(
                    "+{}+{}+{}+{}+{}+{}+{}",
                    u8::from(c.signing_pin_multi_op),
                    c.pw1_max_len,
                    c.rc_max_len,
                    c.pw3_max_len,
                    c.pw1_retries,
                    c.rc_retries,
                    c.pw3_retries,
                ),
            )
            .await?;
        }
        "SIG-COUNTER" => {
            status(conn, "SIG-COUNTER", &info.sig_counter.to_string()).await?;
        }
        "DISP-NAME" => {
            if let Some(name) = &info.cardholder_name {
                status(conn, "DISP-NAME", name).await?;
            }
        }
        "DISP-LANG" => {
            if let Some(lang) = &info.cardholder_lang {
                status(conn, "DISP-LANG", lang).await?;
            }
        }
        "PUBKEY-URL" => {
            if let Some(url) = &info.pubkey_url {
                status(conn, "PUBKEY-URL", url).await?;
            }
        }
        "KEYPAIRINFO" => {
            for key in &info.keys {
                status(conn, "KEYPAIRINFO", &keypairinfo_payload(key)).await?;
            }
        }
        "MANUFACTURER" => {
            status(
                conn,
                "MANUFACTURER",
                &format!("{} {}", info.manufacturer_id, info.manufacturer_name),
            )
            .await?;
        }
        other => {
            return Err(HandlerError::new(
                err::NOT_SUPPORTED,
                format!("GETATTR {other} not supported"),
            ))
        }
    }
    Ok(())
}

fn setdata(session: &mut Session, args: &str) -> Result<(), HandlerError> {
    let (append, hex_body) = match args.strip_prefix("--append") {
        Some(rest) => (true, rest.trim()),
        None => (false, args.trim()),
    };
    let parse = |s: &str| hex::decode(s).map_err(|e| HandlerError::new(err::INV_ARG, e.to_string()));
    if append {
        session.setdata.append(&mut parse(hex_body)?);
    } else {
        session.setdata = parse(hex_body)?;
    }
    Ok(())
}

async fn pksign(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    // gpg-agent sends `--hash=<algo> <keygrip>`; we only use the keygrip for
    // routing (the hash is encoded in the DigestInfo we already have).
    let keygrip = args
        .split_whitespace()
        .last()
        .ok_or_else(|| HandlerError::new(err::INV_ARG, "PKSIGN requires keygrip"))?;
    let usage = resolve_key(session, keygrip)?;
    if usage != KeyUsage::Signing && usage != KeyUsage::Authentication {
        return Err(HandlerError::new(
            err::INV_ARG,
            format!("keygrip {keygrip} is not a signing key"),
        ));
    }
    let digest_info = session.take_data();
    if digest_info.is_empty() {
        return Err(HandlerError::new(err::INV_ARG, "no SETDATA buffered"));
    }
    let ident = require_ident(session)?;
    let (prompt, _) = prompt_for_card(session, /* include_counter = */ true)?;
    let signature = sign_with_cached_pin(session, conn, &ident, &digest_info, &prompt).await?;
    conn.write_data(&signature)
        .await
        .map_err(|e| handler_io(&e))?;
    Ok(())
}

/// Try to sign using the cached PIN; on bad-PIN, invalidate cache and
/// re-prompt once. Keeps pinentry off the user's face for every single sign.
async fn sign_with_cached_pin(
    session: &mut Session,
    conn: &mut Connection,
    ident: &str,
    digest_info: &[u8],
    prompt: &str,
) -> Result<Vec<u8>, HandlerError> {
    if let Some(cached) = session.pin_for(PinMode::Signing) {
        match sign_digest_info(ident, cached, digest_info) {
            Ok(sig) => {
                tracing::debug!("PKSIGN served from PIN cache");
                return Ok(sig);
            }
            Err(scd_rs_card::CardError::BadPin { .. }) => {
                tracing::info!("cached PIN rejected; prompting for fresh PIN");
                session.clear_pin();
                // Fall through to the fresh-prompt path below.
            }
            Err(other) => return Err(card_err(other)),
        }
    }

    let pin = request_pin(conn, prompt)
        .await
        .map_err(|e| handler_io(&e))?;

    if std::env::var_os("SCD_RS_DRY_SIGN").is_some_and(|v| !v.is_empty()) {
        tracing::warn!(
            pin_len_after_trim = pin.expose_secret().len(),
            "DRY_SIGN: skipping card verify",
        );
        return Err(HandlerError::new(
            err::GENERAL,
            "SCD_RS_DRY_SIGN set: skipping card verify",
        ));
    }

    let pin_bytes = pin.expose_secret().clone();
    let signature = sign_digest_info(ident, &pin_bytes, digest_info).map_err(card_err)?;
    session.cache_pin(pin_bytes, PinMode::Signing);
    Ok(signature)
}

async fn pkdecrypt(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    let keygrip = args.trim();
    let usage = resolve_key(session, keygrip)?;
    if usage != KeyUsage::Decryption {
        return Err(HandlerError::new(
            err::INV_ARG,
            format!("keygrip {keygrip} is not a decryption key"),
        ));
    }
    let ciphertext = session.take_data();
    if ciphertext.is_empty() {
        return Err(HandlerError::new(err::INV_ARG, "no SETDATA buffered"));
    }
    let ident = require_ident(session)?;
    let (prompt, _) = prompt_for_card(session, /* include_counter = */ false)?;
    let plaintext = decrypt_with_cached_pin(session, conn, &ident, &ciphertext, &prompt).await?;
    // gpg-agent expects the PADDING status line before the plaintext.
    status(conn, "PADDING", "0").await?;
    conn.write_data(&plaintext)
        .await
        .map_err(|e| handler_io(&e))?;
    Ok(())
}

async fn decrypt_with_cached_pin(
    session: &mut Session,
    conn: &mut Connection,
    ident: &str,
    ciphertext: &[u8],
    prompt: &str,
) -> Result<Vec<u8>, HandlerError> {
    if let Some(cached) = session.pin_for(PinMode::User) {
        match decrypt(ident, cached, ciphertext) {
            Ok(plain) => {
                tracing::debug!("PKDECRYPT served from PIN cache");
                return Ok(plain);
            }
            Err(scd_rs_card::CardError::BadPin { .. }) => {
                tracing::info!("cached PIN rejected; prompting for fresh PIN");
                session.clear_pin();
            }
            Err(other) => return Err(card_err(other)),
        }
    }

    let pin = request_pin(conn, prompt)
        .await
        .map_err(|e| handler_io(&e))?;
    let pin_bytes = pin.expose_secret().clone();
    let plaintext = decrypt(ident, &pin_bytes, ciphertext).map_err(card_err)?;
    session.cache_pin(pin_bytes, PinMode::User);
    Ok(plaintext)
}

fn resolve_key(session: &mut Session, keygrip: &str) -> Result<KeyUsage, HandlerError> {
    let grip = keygrip.to_ascii_uppercase();
    if let Some(usage) = session.known_keys.usage(&grip) {
        return Ok(usage);
    }
    // Fall back to the cached info; refresh only if the cache is empty.
    let info = ensure_card_info(session)?;
    info.keys
        .iter()
        .find(|k| k.keygrip.as_deref() == Some(grip.as_str()))
        .map(|k| k.usage)
        .ok_or_else(|| {
            HandlerError::new(err::NO_SECRET_KEY, format!("unknown keygrip {keygrip}"))
        })
}

/// Build the pinentry prompt string from cached card info. Returns the
/// prompt plus the card ident we pulled it from, for callers that want to
/// assert they match the session's current ident.
fn prompt_for_card(
    session: &mut Session,
    include_counter: bool,
) -> Result<(String, String), HandlerError> {
    let info = ensure_card_info(session)?;
    let prompt = build_prompt(
        info.ident.as_ref(),
        info.cardholder_name.as_deref(),
        if include_counter {
            Some(info.sig_counter)
        } else {
            None
        },
    );
    Ok((prompt, info.ident.to_string()))
}

fn require_ident(session: &Session) -> Result<String, HandlerError> {
    session
        .current_ident
        .clone()
        .ok_or_else(|| HandlerError::new(err::NO_CARD, "SERIALNO first"))
}

fn card_err(err: scd_rs_card::CardError) -> HandlerError {
    match err {
        scd_rs_card::CardError::NotFound => {
            HandlerError::new(err::NO_CARD, "no OpenPGP card present")
        }
        scd_rs_card::CardError::BadPin { retries_left } => HandlerError::new(
            err::GENERAL,
            format!("bad PIN; {retries_left} attempts remaining"),
        ),
        other => HandlerError::new(err::GENERAL, other.to_string()),
    }
}

fn handler_io(err: &scd_rs_assuan::ServerError) -> HandlerError {
    HandlerError::new(err::GENERAL, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_algorithm_converts_to_scd_token() {
        assert_eq!(algo_to_scd_token("RSA 4096 [e 32]"), "rsa4096");
        assert_eq!(algo_to_scd_token("RSA 2048 [e 17]"), "rsa2048");
    }

    #[test]
    fn eddsa_cv25519_algorithm_tokens() {
        assert_eq!(algo_to_scd_token("EdDSA ed25519"), "ed25519");
        assert_eq!(algo_to_scd_token("ECDH cv25519"), "cv25519");
    }

    #[test]
    fn setdata_buffers_and_appends() {
        let mut session = Session::default();
        setdata(&mut session, "48656c6c6f").unwrap();
        assert_eq!(session.setdata, b"Hello");
        setdata(&mut session, "--append 20576f726c64").unwrap();
        assert_eq!(session.setdata, b"Hello World");
    }

    #[test]
    fn setdata_rejects_bad_hex() {
        let mut session = Session::default();
        assert!(setdata(&mut session, "not-hex").is_err());
    }
}
