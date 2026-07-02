use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "arca",
    version,
    about = "Synchronisation chiffree E2EE orientee CLI",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Init {
        #[arg(long, default_value = "default")]
        workspace_name: String,
        #[arg(long, default_value = ".")]
        path: String,
        #[arg(long)]
        force: bool,
    },
    Register {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Login {
        #[arg(long)]
        server_url: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    Watch {
        #[arg(long)]
        once: bool,
    },
    Upload {
        #[arg(long)]
        path: String,
        #[arg(long)]
        remote_path: Option<String>,
    },
    Share {
        #[arg(long)]
        path: String,
        #[arg(long)]
        with_user: String,
    },
    Pull,
    Status,
    Diff,
    History,
    Restore,
    Nuke {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        yes: bool,
    },
}
