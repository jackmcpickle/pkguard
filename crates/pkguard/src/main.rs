mod catalog;
mod cli;
mod init;
mod paths;
mod render;
mod report;
mod scan;

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = cli::Cli::parse();
    let code = match args.command {
        cli::Command::Scan(scan_args) => scan::run(scan_args).await,
        cli::Command::Init(init_args) => init::run(init_args),
        cli::Command::DumpCatalog => {
            catalog::print();
            0
        }
    };
    std::process::exit(code);
}
