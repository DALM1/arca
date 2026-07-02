mod app;
mod cli;
mod config;
mod db;
mod remote;
mod scanner;
mod watcher;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    app::run(cli)
}
