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
        #[arg(long)]
        sync: bool,
    },
    Push,
    Upload {
        #[arg(value_name = "PATH")]
        path: Option<String>,
        #[arg(long, hide = true)]
        path_flag: Option<String>,
        #[arg(short = 's', long = "secret")]
        secret: bool,
        #[arg(long)]
        remote_path: Option<String>,
    },
    Share {
        #[arg(value_name = "PATH")]
        path: Option<String>,
        #[arg(value_name = "USER")]
        with_user: Option<String>,
        #[arg(long, hide = true)]
        path_flag: Option<String>,
        #[arg(long, hide = true)]
        with_user_flag: Option<String>,
    },
    Unshare {
        #[arg(value_name = "PATH")]
        path: Option<String>,
        #[arg(value_name = "USER")]
        with_user: Option<String>,
        #[arg(long, hide = true)]
        path_flag: Option<String>,
        #[arg(long, hide = true)]
        with_user_flag: Option<String>,
    },
    List,
    Pull {
        #[arg(value_name = "REMOTE_PATH")]
        remote_path: Option<String>,
        #[arg(value_name = "OUTPUT")]
        output: Option<String>,
        #[arg(long, hide = true)]
        remote_path_flag: Option<String>,
        #[arg(long, hide = true)]
        output_flag: Option<String>,
    },
    Delete {
        #[arg(value_name = "REMOTE_PATH")]
        remote_path: Option<String>,
        #[arg(long, hide = true)]
        remote_path_flag: Option<String>,
    },
    Status,
    Diff,
    History {
        #[arg(long)]
        path: Option<String>,
    },
    Restore {
        #[arg(long)]
        target_dir: Option<String>,
    },
    Nuke {
        #[arg(long)]
        local: bool,
        #[arg(long)]
        remote: bool,
        #[arg(long)]
        yes: bool,
    },
}
