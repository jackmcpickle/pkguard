mod cli;
mod render;
mod scan;

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = cli::Cli::parse();
    let code = match args.command {
        cli::Command::Scan(scan_args) => scan::run(scan_args).await,
    };
    std::process::exit(code);
}
