mod app;
mod cli;
mod config;
mod crypto;
mod db;
mod progress;
mod remote;
mod scanner;
mod syncer;
mod watcher;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    app::run(cli)
}
