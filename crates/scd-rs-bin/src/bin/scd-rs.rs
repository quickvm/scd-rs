//! `scd-rs` daemon entry point.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Parser;
use scd_rs_assuan::AssuanServer;
use scd_rs_bin::ScdHandler;

#[derive(Parser, Debug)]
#[command(name = "scd-rs", about = "Sequoia-backed scdaemon replacement")]
struct Cli {
    /// Unix socket path to bind. Defaults to
    /// `$XDG_RUNTIME_DIR/scd-rs/socket` (or `/tmp` fallback).
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,scd_rs_card=debug")),
        )
        .init();

    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(default_socket_path);

    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("create socket parent {}: {e}", parent.display()))?;
    }
    // Clean up a stale socket from a previous run.
    if socket.exists() {
        std::fs::remove_file(&socket)
            .map_err(|e| anyhow!("remove stale socket {}: {e}", socket.display()))?;
    }

    tracing::info!(path = %socket.display(), "binding");
    let server = AssuanServer::bind(&socket, ScdHandler)?;
    tracing::info!("serving");
    server.serve().await?;
    Ok(())
}

fn default_socket_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from);
    base.join("scd-rs").join("socket")
}
