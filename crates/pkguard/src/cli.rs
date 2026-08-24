use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pkguard", version, about = "Package-manager security audit")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Audit one directory tree. Read-only unless `--fix` is passed
    #[command(alias = "audit")]
    Scan(ScanArgs),

    /// Write a starter config file
    Init(InitArgs),

    /// Emit the docs-site catalog as JSON (builds the docs site)
    #[command(hide = true, name = "dump-catalog")]
    DumpCatalog,
}

#[derive(clap::Args)]
pub struct InitArgs {
    /// Write `.pkguard.toml` in the current directory instead of the user config
    #[arg(long)]
    pub local: bool,

    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
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

    /// Write the safe settings into each manager's config file
    #[arg(long)]
    pub fix: bool,

    /// Allow `--fix` on a dirty git tree
    #[arg(long, requires = "fix")]
    pub force: bool,

    /// With `--fix`, show the changes and write nothing
    #[arg(long, requires = "fix")]
    pub dry_run: bool,

    /// Skip every live package-manager audit (offline)
    #[arg(long)]
    pub no_audit: bool,
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
