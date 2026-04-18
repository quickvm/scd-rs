//! Hardware-in-the-loop probe for validating per-operation card discipline.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "scd-rs-probe",
    about = "Exercise scd-rs-card against real hardware"
)]
struct Cli {
    /// Card ident (Sequoia identifier); auto-selects the first card if omitted.
    #[arg(long)]
    ident: Option<String>,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!(ident = ?cli.ident, "probe skeleton — no ops yet");
}
