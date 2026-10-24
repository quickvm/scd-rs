//! Tier 1 Assuan command handlers.
//!
//! Each command corresponds to one verb observed in the Phase 0 scdaemon
//! trace (see `docs/required-commands.md` and `docs/assuan-traces/`).

use std::time::Duration;

use scd_rs_assuan::{CommandHandler, Connection, HandlerError};
use scd_rs_card::{
    decrypt, enumerate_cards, read_card_info, sign_digest_info, CardIdent, CardInfo, KeyInfo,
    KeyUsage,
};
use secrecy::ExposeSecret;

use crate::cards::{choose, same_card, KnownCards, Wanted};
use crate::pinentry::{build_prompt, request_pin};
use crate::pool_ttl;
use crate::state::Session;

/// Assuan error codes mirrored from gpg-agent / scdaemon. Values are
/// `(GPG_ERR_SOURCE_SCD << 24) | <gpg-error code>`; the canonical
/// libgpg-error numbering you can cross-check with `gpg-error --list`.
mod err {
    /// `GPG_ERR_GENERAL` (1). Catch-all for "something went wrong and we
    /// don't have a better classification".
    pub const GENERAL: u32 = 100_663_297;
    /// `GPG_ERR_NO_SECKEY` (17). The requested keygrip isn't on the card
    /// at all; distinct from `INV_ID`, which covers "on the card, wrong
    /// usage".
    pub const NO_SECRET_KEY: u32 = 100_663_313;
    /// `GPG_ERR_NOT_FOUND` (27). `KEYINFO <keygrip>` names a key on none
    /// of the cards; stock answers this rather than `NO_SECRET_KEY`.
    pub const NOT_FOUND: u32 = 100_663_323;
    /// `GPG_ERR_INV_ARG` (45). Malformed command arguments (missing
    /// keygrip, bad hex, etc.).
    pub const INV_ARG: u32 = 100_663_341;
    /// `GPG_ERR_NOT_SUPPORTED` (60). Verb or option the daemon doesn't
    /// handle. gpg-agent tolerates this and moves on.
    pub const NOT_SUPPORTED: u32 = 100_663_356;
    /// `GPG_ERR_CARD_NOT_PRESENT` (112). No `OpenPGP` card visible on any
    /// connected reader, or SERIALNO hasn't been run yet in this session.
    pub const NO_CARD: u32 = 100_663_408;
    /// `GPG_ERR_INV_ID` (118). PKSIGN/PKDECRYPT keygrip names a key that's
    /// on the card but has the wrong usage for the requested operation
    /// (e.g. asking the signing key to decrypt).
    pub const INV_ID: u32 = 100_663_414;
    /// `GPG_ERR_ENODEV` (32848). `SERIALNO --demand=<AID>` names a card
    /// that is not plugged in, matching stock's "No such device".
    pub const NO_DEVICE: u32 = 100_696_144;
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
            "GETINFO" => getinfo(session, conn, args).await,
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

async fn getinfo(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
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
        "card_list" => card_list(session, conn).await,
        "socket_name" | "status" | "reader_list" | "deny_admin" | "app_list" | "connections" => {
            Err(HandlerError::new(
                err::NOT_SUPPORTED,
                format!("GETINFO {args} not supported"),
            ))
        }
        other => Err(HandlerError::new(
            err::NOT_SUPPORTED,
            format!("GETINFO {other} not supported"),
        )),
    }
}

/// `GETINFO card_list`: one `S SERIALNO` per card in PC/SC reader order,
/// the order stock sorts its list in. Stock lists only cards an earlier
/// SERIALNO scanned; scd-rs enumerates, so the list is never stale.
async fn card_list(session: &mut Session, conn: &mut Connection) -> Result<(), HandlerError> {
    let present = enumerate_cards().map_err(card_err)?;
    if present.is_empty() {
        return Err(HandlerError::new(err::NO_CARD, "no OpenPGP card present"));
    }
    for ident in &present {
        status(conn, "SERIALNO", ident.as_ref()).await?;
    }
    session.cards.set_present(present);
    Ok(())
}

/// `GnuPG` version we pretend to be for the purposes of the `GETINFO version`
/// check. Bump this alongside the fedora-stable scdaemon release so we keep
/// passing the "outdated server" guard.
const GPG_VERSION_COMPAT: &str = "2.4.9";

/// What a `SERIALNO` line asks for.
#[derive(Debug, PartialEq, Eq)]
struct SerialnoRequest<'a> {
    wanted: Wanted<'a>,
    /// `--reset`: enumerate even when the session already has a card.
    reset: bool,
}

impl<'a> SerialnoRequest<'a> {
    /// Parse `SERIALNO [--demand=<AID>] [--all] [--reset] [<apptype>]`.
    /// `--all` and an apptype change nothing: scd-rs serves only the
    /// `OpenPGP` application, and stock answers `--all` with one card too.
    fn parse(args: &'a str) -> Result<Self, HandlerError> {
        let mut request = Self {
            wanted: Wanted::First,
            reset: false,
        };
        for token in args.split_whitespace() {
            if token == "--reset" {
                request.reset = true;
            } else if let Some(aid) = token
                .strip_prefix("--demand=")
                .filter(|aid| !aid.is_empty())
            {
                request.wanted = Wanted::Aid(aid);
            } else if token.starts_with("--demand") {
                return Err(HandlerError::new(
                    err::INV_ARG,
                    "missing value for --demand",
                ));
            }
        }
        Ok(request)
    }

    /// The bound card, when it answers this request without enumerating.
    fn served_by<'s>(&self, bound: Option<&'s str>) -> Option<&'s str> {
        let bound = bound.filter(|_| !self.reset)?;
        match self.wanted {
            Wanted::First => Some(bound),
            Wanted::Aid(aid) => same_card(aid, bound).then_some(bound),
        }
    }
}

async fn serialno(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    // gpg-agent issues SERIALNO and SERIALNO --all repeatedly during every
    // sign/decrypt flow to re-confirm the card is still present. Re-opening
    // every card each time costs ~1 second for the Nitrokey alone. A session
    // that has bound a card answers from memory, so a card pulled since is
    // only noticed when a card operation fails. `--reset`, and a `--demand`
    // for a card other than the bound one, enumerate.
    let request = SerialnoRequest::parse(args)?;
    if let Some(ident) = request.served_by(session.current_ident.as_deref()) {
        let ident = ident.to_string();
        status(conn, "SERIALNO", &ident).await?;
        tracing::info!("SERIALNO served from session");
        return Ok(());
    }
    let present = enumerate_cards().map_err(card_err)?;
    let ident = bind_from(session, present, request.wanted)?;
    status(conn, "SERIALNO", &ident).await
}

/// Record the cards an enumeration found and bind the one `wanted` names.
/// No card at all is `NO_CARD`. A demanded card that is not among them is
/// `NO_DEVICE`, as stock answers, and leaves the session's card alone.
fn bind_from(
    session: &mut Session,
    present: Vec<CardIdent>,
    wanted: Wanted<'_>,
) -> Result<String, HandlerError> {
    let chosen = choose(&present, wanted).map(|ident| ident.0.clone());
    session.cards.set_present(present);
    let ident = chosen.ok_or_else(|| match wanted {
        Wanted::First => HandlerError::new(err::NO_CARD, "no OpenPGP card present"),
        Wanted::Aid(aid) => HandlerError::new(err::NO_DEVICE, format!("card {aid} not present")),
    })?;
    session.bind_card(&ident);
    Ok(ident)
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

/// Return the bound card's `CardInfo` snapshot, reading the card on first
/// access. Subsequent callers within the same session reuse the snapshot,
/// which cuts several seconds off sign and decrypt flows.
///
/// Binds the first card PC/SC lists if the session has none yet; stock
/// scdaemon caches card state across sessions and so can serve metadata
/// queries before an explicit `SERIALNO`. scd-rs starts each session
/// empty, so we fold in the enumeration step here rather than make
/// gpg-agent retry after a `NO_CARD` error.
fn ensure_card_info(session: &mut Session) -> Result<&CardInfo, HandlerError> {
    if session.current_ident.is_none() {
        let present = enumerate_cards().map_err(card_err)?;
        bind_from(session, present, Wanted::First)?;
    }
    let ident = require_ident(session)?;
    if session.cards.get(&ident).is_none() {
        tracing::info!("CardInfo cache miss; refreshing from card");
        read_snapshot(session, &ident)?;
    } else {
        tracing::info!("CardInfo cache hit");
    }
    Ok(session.cards.get(&ident).expect("just populated"))
}

/// Force a fresh read of the bound card, updating its snapshot.
fn refresh_card_info(session: &mut Session) -> Result<CardInfo, HandlerError> {
    let ident = require_ident(session)?;
    read_snapshot(session, &ident)
}

/// Read `ident`'s `CardInfo` into the session's snapshots. Only the bound
/// card goes through the session's pooled handle, which holds one card;
/// any other card is read on a handle that is dropped straight after.
fn read_snapshot(session: &mut Session, ident: &str) -> Result<CardInfo, HandlerError> {
    let info = if session.current_ident.as_deref() == Some(ident) {
        read_card_info(&mut session.card_pool, pool_ttl::configured(), ident)
    } else {
        read_card_info(&mut None, Duration::ZERO, ident)
    }
    .map_err(card_err)?;
    session.cards.insert(info.clone());
    Ok(info)
}

/// Make sure the session holds a snapshot of every card PC/SC lists.
/// Enumerates when `rescan` is set or when the session knows of no card
/// yet; otherwise reads only the cards that have no snapshot.
fn ensure_all_cards(session: &mut Session, rescan: bool) -> Result<(), HandlerError> {
    if rescan || session.cards.present().is_empty() {
        let present = enumerate_cards().map_err(card_err)?;
        session.cards.set_present(present);
    }
    for ident in session.cards.unread() {
        tracing::info!(%ident, "reading card snapshot");
        read_snapshot(session, ident.as_ref())?;
    }
    Ok(())
}

/// Find the card holding `keygrip` (uppercase hex) and the key's usage.
/// A miss reads any card that has no snapshot yet. With `rescan`, a miss
/// also re-enumerates first: KEYINFO is how gpg-agent checks whether the
/// card it asked the user to insert has arrived.
fn locate_keygrip(
    session: &mut Session,
    keygrip: &str,
    rescan: bool,
) -> Result<Option<(String, KeyUsage)>, HandlerError> {
    let lookup = |cards: &KnownCards| {
        cards
            .find_keygrip(keygrip)
            .map(|(ident, usage)| (ident.0.clone(), usage))
    };
    if let Some(found) = lookup(&session.cards) {
        return Ok(Some(found));
    }
    ensure_all_cards(session, rescan)?;
    Ok(lookup(&session.cards))
}

async fn emit_learn_status(conn: &mut Connection, info: &CardInfo) -> Result<(), HandlerError> {
    // Matches the order and shape of the Phase 0 LEARN --force trace.
    status(
        conn,
        "READER",
        &format!("{} card reader", info.manufacturer_name),
    )
    .await?;
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
    conn.write_status(keyword, data)
        .await
        .map_err(|e| handler_io(&e))
}

fn keypairinfo_payload(key: &KeyInfo) -> String {
    let grip = key.keygrip.as_deref().unwrap_or("X");
    let slot = key.usage.openpgp_slot();
    let usage = key.usage.scd_usage();
    let created = key.created.unwrap_or(0);
    let algo = key
        .algorithm
        .as_deref()
        .map_or_else(|| "unknown".into(), algo_to_scd_token);
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
    let usage = match filter {
        "" => None,
        "encr" => Some(KeyUsage::Decryption),
        "sign" => Some(KeyUsage::Signing),
        "auth" => Some(KeyUsage::Authentication),
        other => {
            return Err(HandlerError::new(
                err::INV_ARG,
                format!("unknown KEYINFO filter {other}"),
            ));
        }
    };
    ensure_all_cards(session, false)?;
    if session.current_ident.is_none() {
        // A session with no card binds the first one, as it always has, so
        // the SERIALNO that follows in gpg-agent's flows is served from
        // memory.
        if let Some(first) = choose(session.cards.present(), Wanted::First).cloned() {
            session.bind_card(first.as_ref());
        }
    }
    for line in keyinfo_lines(&session.cards, session.current_ident.as_deref(), usage) {
        status(conn, "KEYINFO", &line).await?;
    }
    Ok(())
}

/// `KEYINFO --list` payloads for the keys on every card, bound card first,
/// limited to one slot usage when `usage` is set.
fn keyinfo_lines(cards: &KnownCards, bound: Option<&str>, usage: Option<KeyUsage>) -> Vec<String> {
    cards
        .listing(bound)
        .into_iter()
        .flat_map(|info| {
            info.keys
                .iter()
                .filter(move |key| usage.is_none_or(|wanted| wanted == key.usage))
                .filter_map(move |key| {
                    let grip = key.keygrip.as_deref()?;
                    Some(keyinfo_payload(grip, info.ident.as_ref(), key.usage))
                })
        })
        .collect()
}

fn keyinfo_payload(keygrip: &str, ident: &str, usage: KeyUsage) -> String {
    format!(
        "{keygrip} T {ident} OPENPGP.{} {}",
        usage.openpgp_slot(),
        usage.scd_usage()
    )
}

async fn keyinfo_single(
    session: &mut Session,
    conn: &mut Connection,
    keygrip: &str,
) -> Result<(), HandlerError> {
    let keygrip = keygrip.to_ascii_uppercase();
    let Some((ident, usage)) = locate_keygrip(session, &keygrip, true)? else {
        return Err(HandlerError::new(
            err::NOT_FOUND,
            format!("unknown keygrip {keygrip}"),
        ));
    };
    session.bind_card(&ident);
    status(conn, "KEYINFO", &keyinfo_payload(&keygrip, &ident, usage)).await
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
                let algo = key
                    .algorithm
                    .as_deref()
                    .map_or_else(|| "unknown".into(), algo_to_scd_token);
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
    let parse =
        |s: &str| hex::decode(s).map_err(|e| HandlerError::new(err::INV_ARG, e.to_string()));
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
    let (ident, usage) = resolve_key(session, keygrip)?;
    if usage != KeyUsage::Signing && usage != KeyUsage::Authentication {
        return Err(HandlerError::new(
            err::INV_ID,
            format!("keygrip {keygrip} is not a signing key"),
        ));
    }
    let digest_info = session.take_data();
    if digest_info.is_empty() {
        return Err(HandlerError::new(err::INV_ARG, "no SETDATA buffered"));
    }
    session.bind_card(&ident);
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
    // Clone the cached PIN so the immutable borrow ends before we hand
    // `&mut session.card_pool` to sign_digest_info.
    let cached = session.cached_pin_bytes().map(<[u8]>::to_vec);
    let pool_ttl = pool_ttl::configured();
    if let Some(cached) = cached {
        match sign_digest_info(
            &mut session.card_pool,
            pool_ttl,
            ident,
            &cached,
            digest_info,
        ) {
            Ok(sig) => {
                tracing::debug!("PKSIGN served from PIN cache");
                session.touch_pin();
                return Ok(sig);
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
    let signature = sign_digest_info(
        &mut session.card_pool,
        pool_ttl,
        ident,
        &pin_bytes,
        digest_info,
    )
    .map_err(card_err)?;
    session.cache_pin(pin_bytes);
    Ok(signature)
}

async fn pkdecrypt(
    session: &mut Session,
    conn: &mut Connection,
    args: &str,
) -> Result<(), HandlerError> {
    let keygrip = args.trim();
    let (ident, usage) = resolve_key(session, keygrip)?;
    if usage != KeyUsage::Decryption {
        return Err(HandlerError::new(
            err::INV_ID,
            format!("keygrip {keygrip} is not a decryption key"),
        ));
    }
    let ciphertext = session.take_data();
    if ciphertext.is_empty() {
        return Err(HandlerError::new(err::INV_ARG, "no SETDATA buffered"));
    }
    session.bind_card(&ident);
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
    let cached = session.cached_pin_bytes().map(<[u8]>::to_vec);
    let pool_ttl = pool_ttl::configured();
    if let Some(cached) = cached {
        match decrypt(&mut session.card_pool, pool_ttl, ident, &cached, ciphertext) {
            Ok(plain) => {
                tracing::debug!("PKDECRYPT served from PIN cache");
                session.touch_pin();
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
    let plaintext = decrypt(
        &mut session.card_pool,
        pool_ttl,
        ident,
        &pin_bytes,
        ciphertext,
    )
    .map_err(card_err)?;
    session.cache_pin(pin_bytes);
    Ok(plaintext)
}

/// The card holding `keygrip` and the key's usage, for PKSIGN and
/// PKDECRYPT. A miss here does not re-enumerate: gpg-agent asks KEYINFO
/// (which does) before diverting to a card, while its decrypt flow also
/// tries keygrips that are on no card, and each would cost an enumeration.
fn resolve_key(session: &mut Session, keygrip: &str) -> Result<(String, KeyUsage), HandlerError> {
    locate_keygrip(session, &keygrip.to_ascii_uppercase(), false)?
        .ok_or_else(|| HandlerError::new(err::NO_SECRET_KEY, format!("unknown keygrip {keygrip}")))
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
    // These tests never hold a PIN: sign_digest_info and decrypt talk to
    // real PC/SC, and a PIN that reached them on a developer's machine
    // would cost a retry on a real card.

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

    use super::*;
    use crate::cards::fixtures::{
        both, ident, nitrokey, yubikey, NITROKEY, NITROKEY_ENCR, NITROKEY_SIGN, YUBIKEY,
        YUBIKEY_ENCR, YUBIKEY_SIGN,
    };
    use crate::state::CachedPin;

    /// A session that has enumerated and read both fixture cards.
    fn session_with_both_cards(bound: Option<&str>) -> Session {
        let mut session = Session::default();
        session.cards.set_present(both());
        session.cards.insert(yubikey());
        session.cards.insert(nitrokey());
        session.current_ident = bound.map(ToString::to_string);
        session
    }

    fn with_pin(mut session: Session) -> Session {
        session.cached_pin = Some(CachedPin::new(
            b"123456".to_vec(),
            std::time::Duration::from_secs(600),
        ));
        session
    }

    /// A connection over an in-memory pipe, and the client end of it.
    fn pipe() -> (Connection, BufReader<DuplexStream>) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(server);
        (
            Connection::new(Box::new(read), Box::new(write)),
            BufReader::new(client),
        )
    }

    /// Everything the server wrote, once the handler is done with `conn`.
    async fn written(conn: Connection, client: BufReader<DuplexStream>) -> Vec<String> {
        drop(conn);
        let mut lines = client.lines();
        let mut out = Vec::new();
        while let Some(line) = lines.next_line().await.expect("read pipe") {
            out.push(line);
        }
        out
    }

    #[test]
    fn serialno_request_parsing() {
        let parse = |args| SerialnoRequest::parse(args).map_err(|e| e.code);
        let first = SerialnoRequest {
            wanted: Wanted::First,
            reset: false,
        };
        assert_eq!(parse(""), Ok(first));
        assert_eq!(parse("--all").map(|r| r.wanted), Ok(Wanted::First));
        assert_eq!(parse("openpgp").map(|r| r.wanted), Ok(Wanted::First));
        assert_eq!(parse("--reset").map(|r| r.reset), Ok(true));
        let demand = format!("--demand={NITROKEY}");
        assert_eq!(parse(&demand).map(|r| r.wanted), Ok(Wanted::Aid(NITROKEY)));
        assert_eq!(parse("--demand"), Err(100_663_341));
        assert_eq!(parse("--demand="), Err(100_663_341));
    }

    #[test]
    fn served_by_answers_only_for_the_bound_card() {
        let request = |args| SerialnoRequest::parse(args).expect("parses");
        let demand_nitrokey = format!("--demand={NITROKEY}");
        let stock_form_yubikey = "--demand=D2760001240100000006000000010000";
        assert_eq!(request("").served_by(Some(NITROKEY)), Some(NITROKEY));
        assert_eq!(request("--all").served_by(Some(NITROKEY)), Some(NITROKEY));
        assert_eq!(request("").served_by(None), None);
        assert_eq!(request("--reset").served_by(Some(NITROKEY)), None);
        assert_eq!(
            request(&demand_nitrokey).served_by(Some(NITROKEY)),
            Some(NITROKEY)
        );
        assert_eq!(request(&demand_nitrokey).served_by(Some(YUBIKEY)), None);
        assert_eq!(
            request(stock_form_yubikey).served_by(Some(YUBIKEY)),
            Some(YUBIKEY)
        );
    }

    #[tokio::test]
    async fn bare_serialno_serves_the_bound_card_without_enumerating() {
        for args in ["", "--all"] {
            let mut session = session_with_both_cards(Some(NITROKEY));
            let (mut conn, client) = pipe();
            serialno(&mut session, &mut conn, args)
                .await
                .expect("served");
            assert_eq!(
                written(conn, client).await,
                [format!("S SERIALNO {NITROKEY}")]
            );
        }
    }

    #[test]
    fn bare_serialno_binds_the_first_card_listed() {
        let mut session = Session::default();
        assert_eq!(
            bind_from(&mut session, both(), Wanted::First)
                .ok()
                .as_deref(),
            Some(YUBIKEY)
        );
        assert_eq!(session.current_ident.as_deref(), Some(YUBIKEY));
        assert_eq!(session.cards.present(), both().as_slice());
    }

    #[test]
    fn demand_binds_the_demanded_card_and_drops_the_old_pin() {
        let mut session = with_pin(session_with_both_cards(Some(YUBIKEY)));
        let bound = bind_from(&mut session, both(), Wanted::Aid(NITROKEY));
        assert_eq!(bound.ok().as_deref(), Some(NITROKEY));
        assert_eq!(session.current_ident.as_deref(), Some(NITROKEY));
        assert!(session.cached_pin.is_none());
    }

    #[test]
    fn demand_for_an_absent_card_fails_like_stock_and_keeps_the_binding() {
        let mut session = with_pin(session_with_both_cards(Some(YUBIKEY)));
        let err = bind_from(&mut session, vec![ident(YUBIKEY)], Wanted::Aid(NITROKEY))
            .expect_err("Nitrokey is absent");
        // Stock: `ERR 100696144 No such device <SCD>`.
        assert_eq!(err.code, 100_696_144);
        assert_eq!(session.current_ident.as_deref(), Some(YUBIKEY));
        assert!(session.cached_pin.is_some());
        assert!(
            session.cards.get(NITROKEY).is_none(),
            "absent card's snapshot dropped"
        );
    }

    #[test]
    fn no_card_at_all_is_card_not_present() {
        let mut session = Session::default();
        let err = bind_from(&mut session, Vec::new(), Wanted::First).expect_err("no card");
        assert_eq!(err.code, 100_663_408);
        assert!(session.current_ident.is_none());
    }

    #[tokio::test]
    async fn keyinfo_finds_a_keygrip_on_the_second_card_and_binds_it() {
        let mut session = session_with_both_cards(Some(YUBIKEY));
        let (mut conn, client) = pipe();
        let lowercase = NITROKEY_SIGN.to_ascii_lowercase();
        keyinfo(&mut session, &mut conn, &lowercase)
            .await
            .expect("found");
        assert_eq!(
            written(conn, client).await,
            [format!(
                "S KEYINFO {NITROKEY_SIGN} T {NITROKEY} OPENPGP.1 sc"
            )]
        );
        assert_eq!(session.current_ident.as_deref(), Some(NITROKEY));
    }

    #[tokio::test]
    async fn keyinfo_list_covers_every_card_bound_card_first() {
        let mut session = session_with_both_cards(Some(NITROKEY));
        let (mut conn, client) = pipe();
        keyinfo(&mut session, &mut conn, "--list")
            .await
            .expect("listed");
        let lines = written(conn, client).await;
        let idents: Vec<&str> = lines
            .iter()
            .map(|line| line.split(' ').nth(4).expect("ident field"))
            .collect();
        assert_eq!(
            idents,
            [NITROKEY, NITROKEY, NITROKEY, YUBIKEY, YUBIKEY, YUBIKEY]
        );
        assert_eq!(
            lines[0],
            format!("S KEYINFO {NITROKEY_SIGN} T {NITROKEY} OPENPGP.1 sc")
        );
    }

    #[test]
    fn keyinfo_lines_filter_by_usage_across_cards() {
        let session = session_with_both_cards(Some(YUBIKEY));
        assert_eq!(
            keyinfo_lines(&session.cards, Some(YUBIKEY), Some(KeyUsage::Decryption)),
            [
                format!("{YUBIKEY_ENCR} T {YUBIKEY} OPENPGP.2 e"),
                format!("{NITROKEY_ENCR} T {NITROKEY} OPENPGP.2 e"),
            ]
        );
        assert_eq!(keyinfo_lines(&session.cards, None, None).len(), 6);
    }

    #[tokio::test]
    async fn keyinfo_list_rejects_an_unknown_filter() {
        let mut session = session_with_both_cards(Some(YUBIKEY));
        let (mut conn, _client) = pipe();
        let err = keyinfo(&mut session, &mut conn, "--list=bogus")
            .await
            .expect_err("bad filter");
        assert_eq!(err.code, 100_663_341);
    }

    #[tokio::test]
    async fn pksign_routes_to_the_card_holding_the_keygrip() {
        let mut session = session_with_both_cards(Some(YUBIKEY));
        session.setdata = b"digest-info".to_vec();
        let (mut conn, mut client) = pipe();
        let args = format!("--hash=sha512 {NITROKEY_SIGN}");
        // Dropping the connection once PKSIGN returns ends the client's
        // read, so a PKSIGN that never asks for a PIN fails the test
        // instead of hanging it.
        let sign = async move {
            let result = pksign(&mut session, &mut conn, &args).await;
            drop(conn);
            (result, session)
        };
        let cancel_pin_request = async {
            let mut inquire = String::new();
            client.read_line(&mut inquire).await.expect("read pipe");
            if !inquire.is_empty() {
                client
                    .get_mut()
                    .write_all(b"CAN\n")
                    .await
                    .expect("send CAN");
            }
            inquire
        };

        let ((result, session), inquire) = tokio::join!(sign, cancel_pin_request);

        assert!(inquire.starts_with("INQUIRE NEEDPIN "), "got {inquire:?}");
        assert!(
            inquire.contains(NITROKEY),
            "prompt names the Nitrokey: {inquire:?}"
        );
        assert!(result.is_err(), "cancelled PIN request fails the sign");
        assert_eq!(session.current_ident.as_deref(), Some(NITROKEY));
    }

    #[tokio::test]
    async fn pksign_unknown_keygrip_is_no_secret_key() {
        let mut session = session_with_both_cards(Some(YUBIKEY));
        session.setdata = b"digest-info".to_vec();
        let (mut conn, _client) = pipe();
        let args = format!("--hash=sha512 {}", "C".repeat(40));
        let err = pksign(&mut session, &mut conn, &args)
            .await
            .expect_err("no such key");
        assert_eq!(err.code, 100_663_313);
        assert_eq!(session.current_ident.as_deref(), Some(YUBIKEY));
    }

    #[tokio::test]
    async fn pkdecrypt_with_a_signing_key_keeps_the_binding() {
        let mut session = with_pin(session_with_both_cards(Some(NITROKEY)));
        session.setdata = b"ciphertext".to_vec();
        let (mut conn, _client) = pipe();
        let err = pkdecrypt(&mut session, &mut conn, YUBIKEY_SIGN)
            .await
            .expect_err("wrong usage");
        assert_eq!(err.code, 100_663_414);
        assert_eq!(session.current_ident.as_deref(), Some(NITROKEY));
        assert!(
            session.cached_pin.is_some(),
            "a refused op must not cost the PIN cache"
        );
    }

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
