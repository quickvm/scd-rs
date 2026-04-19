//! `scd-rs` daemon entry point.
//!
//! Two server modes:
//! - Default / `--multi-server` / `--server`: Assuan on stdin/stdout.
//!   This is how `gpg-agent`'s `assuan_pipe_connect` invokes scdaemon.
//! - `--socket <path>`: bind a Unix socket for direct testing / debugging.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use clap::Parser;
use scd_rs_assuan::{serve_stdio_with_trace, AssuanServer, TraceSink};
use scd_rs_bin::{pin_ttl, pool_ttl, ScdHandler};

#[derive(Parser, Debug)]
#[command(name = "scd-rs", about = "Sequoia-backed scdaemon replacement")]
struct Cli {
    /// gpg-agent compat. Alias for stdio server mode (the default).
    #[arg(long)]
    server: bool,

    /// gpg-agent compat. Alias for stdio server mode (the default).
    #[arg(long)]
    multi_server: bool,

    /// Accepted for compat with scdaemon's CLI but otherwise ignored.
    #[arg(long)]
    homedir: Option<PathBuf>,

    /// Accepted for compat; we always serve Assuan on stdio unless
    /// `--socket` is passed.
    #[arg(long)]
    daemon: bool,

    /// Bind a Unix socket instead of using stdio.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Log to this file in addition to / instead of stderr.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Tee every Assuan wire line to this file with `<- ` / `-> ` direction
    /// markers. Intended for trace-diffing against stock scdaemon's
    /// `debug ipc` output — see scripts/capture-scdrs-traces.sh.
    #[arg(long)]
    trace_file: Option<PathBuf>,

    /// Accepted for compat — scdaemon uses this for its debug subsystem
    /// masks. We treat the flag as enabling debug-level tracing.
    #[arg(long)]
    debug: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_file = cli
        .log_file
        .clone()
        .or_else(|| std::env::var_os("SCD_RS_LOG").map(PathBuf::from));
    init_tracing(log_file.as_deref(), cli.debug.is_some())?;
    let trace = open_trace(cli.trace_file.as_deref())?;
    // Resolve PIN + pool TTLs eagerly so the configured values show up in the
    // startup log rather than on first use.
    let _ = pin_ttl::configured();
    let _ = pool_ttl::configured();
    let _ = (cli.server, cli.multi_server, cli.homedir, cli.daemon);

    if let Some(path) = cli.socket {
        run_unix(path, trace).await
    } else {
        tracing::info!("serving on stdio");
        serve_stdio_with_trace(ScdHandler, trace).await?;
        Ok(())
    }
}

async fn run_unix(socket: PathBuf, trace: Option<TraceSink>) -> Result<()> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create socket parent {}: {e}", parent.display()))?;
    }
    if socket.exists() {
        std::fs::remove_file(&socket)
            .map_err(|e| anyhow!("remove stale socket {}: {e}", socket.display()))?;
    }
    tracing::info!(path = %socket.display(), "binding unix socket");
    let mut server = AssuanServer::bind(&socket, ScdHandler)?;
    if let Some(sink) = trace {
        server = server.with_trace(sink);
    }
    server.serve().await?;
    Ok(())
}

fn open_trace(path: Option<&std::path::Path>) -> Result<Option<TraceSink>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| anyhow!("open trace file {}: {e}", path.display()))?;
    tracing::info!(path = %path.display(), "tracing Assuan wire to file");
    Ok(Some(Arc::new(Mutex::new(file))))
}

fn init_tracing(log_file: Option<&std::path::Path>, verbose: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(if verbose {
            "debug,scd_rs_card=trace"
        } else {
            "info,scd_rs_card=debug"
        })
    });
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr);
    if let Some(path) = log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow!("open log file {}: {e}", path.display()))?;
        builder.with_writer(std::sync::Mutex::new(file)).init();
    } else {
        builder.init();
    }
    Ok(())
}
