use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mailclad", version, about = "Package-manager security audit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Read-only audit of one directory tree (never mutates anything)
    Scan(ScanArgs),
}

#[derive(clap::Args)]
pub struct ScanArgs {
    /// Directory to scan (defaults to the current directory)
    pub path: Option<PathBuf>,

    /// Policy preset
    #[arg(long, value_enum)]
    pub preset: Option<PresetArg>,

    /// Max concurrent audits (defaults to min(cpus*2, 16))
    #[arg(long)]
    pub jobs: Option<usize>,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Ignore cached advisory results for this run and re-fetch
    #[arg(long)]
    pub refresh: bool,

    /// Disable the advisory cache entirely (no reads, no writes)
    #[arg(long)]
    pub no_cache: bool,

    /// Suppress progress output
    #[arg(long, short)]
    pub quiet: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PresetArg {
    Relaxed,
    Standard,
    Strict,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
}
