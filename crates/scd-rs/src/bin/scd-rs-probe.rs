//! Hardware-in-the-loop probe for validating per-operation card discipline.
//!
//! Every subcommand re-establishes a fresh PC/SC context and card handle
//! through `scd_rs_card`; nothing persists between iterations. The `loop`
//! subcommand is the primary regression harness for Phase 1.

use std::process::ExitCode;
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use scd_rs::pool_ttl;
use scd_rs_card::{enumerate_cards, read_card_info, CardError, CardInfo, KeyInfo};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "scd-rs-probe",
    version,
    about = "Exercise scd-rs-card against real hardware"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enumerate every `OpenPGP` card visible via PC/SC and print their idents.
    Serial,
    /// Dump the full card info snapshot for the given ident.
    Info {
        #[arg(long)]
        ident: String,
    },
    /// Alternate serial enumeration and info dump N times.
    Loop {
        #[arg(long)]
        ident: String,
        #[arg(long, default_value_t = 50)]
        count: u32,
        #[arg(long, default_value_t = 0)]
        delay_ms: u64,
    },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,scd_rs_card=debug")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Serial => run_serial(),
        Command::Info { ident } => run_info(&ident),
        Command::Loop {
            ident,
            count,
            delay_ms,
        } => run_loop(&ident, count, delay_ms),
    }
}

fn run_serial() -> ExitCode {
    match enumerate_cards() {
        Ok(idents) if idents.is_empty() => {
            warn!("no OpenPGP cards found");
            ExitCode::from(2)
        }
        Ok(idents) => {
            for i in &idents {
                println!("{i}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "serial failed");
            ExitCode::FAILURE
        }
    }
}

fn run_info(ident: &str) -> ExitCode {
    // One-shot tool: no pool. Pass Duration::ZERO to force the fresh path.
    let mut pool = None;
    match read_card_info(&mut pool, Duration::ZERO, ident) {
        Ok(info) => {
            print_info(&info);
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!(error = %e, "info failed");
            ExitCode::FAILURE
        }
    }
}

fn run_loop(ident: &str, count: u32, delay_ms: u64) -> ExitCode {
    let mut successes = 0u32;
    let mut failures = 0u32;
    let start = Instant::now();

    // Share a single pool across iterations so `SCD_RS_CARD_POOL_TTL` has the
    // same effect here as in the daemon.
    let pool_ttl = pool_ttl::configured();
    let mut pool = None;

    for i in 1..=count {
        let step = if i.is_multiple_of(2) { "info" } else { "serial" };
        let result = if step == "serial" {
            enumerate_cards().and_then(|ids| {
                if ids.iter().any(|id| id.as_ref() == ident) {
                    Ok(())
                } else {
                    Err(CardError::NotFound)
                }
            })
        } else {
            read_card_info(&mut pool, pool_ttl, ident).map(|_| ())
        };

        match result {
            Ok(()) => {
                successes += 1;
                info!(iteration = i, step, "ok");
            }
            Err(e) => {
                failures += 1;
                error!(iteration = i, step, error = %e, retryable = e.is_retryable(), "failed");
            }
        }

        if delay_ms > 0 {
            sleep(Duration::from_millis(delay_ms));
        }
    }

    let elapsed = start.elapsed();
    println!(
        "loop done: {successes}/{count} ok, {failures} failed, {:.2}s elapsed",
        elapsed.as_secs_f64()
    );

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_info(info: &CardInfo) {
    println!("ident:           {}", info.ident);
    println!("app:             0x{:02X}", info.app);
    println!(
        "app version:     {}.{}",
        info.app_version_bcd >> 8,
        info.app_version_bcd & 0xFF
    );
    println!(
        "manufacturer:    {} (0x{:04X})",
        info.manufacturer_name, info.manufacturer_id
    );
    println!("serial:          0x{:08X}", info.serial_number);
    if let Some(n) = &info.cardholder_name {
        println!("cardholder:      {n}");
    }
    if let Some(l) = &info.cardholder_lang {
        println!("lang:            {l}");
    }
    if let Some(u) = &info.pubkey_url {
        println!("pubkey url:      {u}");
    }
    println!("sig counter:     {}", info.sig_counter);
    println!(
        "CHV retries:     pw1={} rc={} pw3={}",
        info.chv_status.pw1_retries, info.chv_status.rc_retries, info.chv_status.pw3_retries
    );
    println!(
        "sign PIN mode:   {}",
        if info.chv_status.signing_pin_multi_op {
            "multi-op"
        } else {
            "single-op"
        }
    );
    for k in &info.keys {
        print_key(k);
    }
}

fn print_key(k: &KeyInfo) {
    let slot = k.usage.openpgp_slot();
    match (&k.fingerprint, &k.algorithm, k.created) {
        (Some(fp), Some(algo), Some(created)) => {
            let grip = k.keygrip.as_deref().unwrap_or("<none>");
            println!(
                "key OPENPGP.{} ({}): fpr={} grip={} algo={} created={}",
                slot,
                k.usage.scd_usage(),
                fp,
                grip,
                algo,
                created
            );
        }
        _ => {
            println!("key OPENPGP.{} ({}): <empty>", slot, k.usage.scd_usage());
        }
    }
}
