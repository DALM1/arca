use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::cli::{Cli, Command};
use crate::config::{
    AppConfig, ensure_dirs, load_config, load_session, project_paths, save_config, save_session,
};
use crate::db;

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init {
            workspace_name,
            path,
            force,
        } => init(workspace_name, path, force),
        Command::Register {
            server_url,
            username,
            password,
        } => register(server_url, username, password),
        Command::Login {
            server_url,
            username,
            password,
        } => login(server_url, username, password),
        Command::Status => status(),
        Command::Watch { once } => watch(once),
        Command::Upload { path, remote_path } => upload(path, remote_path),
        Command::Share { path, with_user } => share(path, with_user),
        Command::Nuke { local, remote, yes } => nuke(local, remote, yes),
        Command::Pull => not_implemented("pull"),
        Command::Diff => not_implemented("diff"),
        Command::History => not_implemented("history"),
        Command::Restore => not_implemented("restore"),
        Command::Push => not_implemented("push"),
    }
}

fn init(workspace_name: String, path: String, force: bool) -> Result<()> {
    let paths = project_paths()?;
    let workspace_root = normalize_workspace_root(path)?;

    if paths.config_file.exists() && !force {
        bail!("Le projet est deja initialise. Utilise --force pour regenerer la configuration.");
    }

    ensure_dirs(&paths)?;

    let config = AppConfig::new(workspace_name, workspace_root);
    save_config(&paths.config_file, &config)?;

    let connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;
    connection.execute(
        "INSERT OR REPLACE INTO devices (id, status) VALUES (?1, ?2)",
        [&config.device_id.to_string(), "authorized"],
    )?;

    println!("Initialisation terminee");
    println!("Config  : {}", paths.config_file.display());
    println!("Base    : {}", paths.database_file.display());
    println!("Device  : {}", config.device_id);
    println!("Workspace: {}", config.workspace_id);
    println!("Root    : {}", config.workspace_root.display());

    Ok(())
}

fn status() -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let connection = db::connect(&paths.database_file)?;
    let snapshot = db::status(&connection)?;

    println!("Etat du projet");
    println!(
        "Workspace : {} ({})",
        config.workspace_name, config.workspace_id
    );
    println!("Root      : {}", config.workspace_root.display());
    println!("Device    : {}", config.device_id);
    println!("Schema    : {}", snapshot.schema_version);
    println!("Devices   : {}", snapshot.known_devices);
    println!("Fichiers  : {}", snapshot.file_indexed);
    println!("Queue     : {}", snapshot.pending_ops);
    println!("Config    : {}", paths.config_file.display());
    println!("SQLite    : {}", paths.database_file.display());
    if let Ok(session) = load_session(&paths.session_file) {
        println!("Session   : {} @ {}", session.username, session.server_url);
    } else {
        println!("Session   : non connecte");
    }

    Ok(())
}

fn register(server_url: String, username: String, password: String) -> Result<()> {
    crate::remote::register(&server_url, username.clone(), password)?;
    println!("Compte cree pour `{username}` sur {server_url}");
    Ok(())
}

fn login(server_url: String, username: String, password: String) -> Result<()> {
    let paths = project_paths()?;
    ensure_dirs(&paths)?;
    let session = crate::remote::login(&server_url, username.clone(), password)?;
    save_session(&paths.session_file, &session)?;
    println!("Connexion reussie pour `{username}`");
    println!("Session  : {}", paths.session_file.display());
    Ok(())
}

fn watch(once: bool) -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let mut connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;
    crate::watcher::run(&mut connection, &config.workspace_root, once)
}

fn upload(path: String, remote_path: Option<String>) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let local_path = PathBuf::from(&path);
    if !local_path.is_file() {
        bail!(
            "Le chemin d'upload doit etre un fichier: {}",
            local_path.display()
        );
    }

    let remote_path = remote_path.unwrap_or_else(|| default_remote_path(&local_path));
    crate::remote::upload_file(&session, &local_path, remote_path.clone())?;
    println!("Upload termine");
    println!("Local  : {}", local_path.display());
    println!("Remote : {}", remote_path);
    Ok(())
}

fn share(path: String, with_user: String) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    crate::remote::share_file(&session, path.clone(), with_user.clone())?;
    println!("Partage termine");
    println!("Fichier : {}", path);
    println!("Avec    : {}", with_user);
    Ok(())
}

fn nuke(local: bool, remote: bool, yes: bool) -> Result<()> {
    if !yes {
        bail!("Refus de destruction sans --yes");
    }

    if !local && !remote {
        bail!("Selectionne au moins une cible avec --local ou --remote");
    }

    if remote {
        return Err(anyhow!(
            "Le nuke distant n'est pas encore implemente. Le protocole serveur reste a definir."
        ));
    }

    let paths = project_paths()?;

    if paths.config_dir.exists() {
        fs::remove_dir_all(&paths.config_dir)
            .with_context(|| format!("Suppression impossible: {}", paths.config_dir.display()))?;
    }

    if paths.data_dir.exists() {
        fs::remove_dir_all(&paths.data_dir)
            .with_context(|| format!("Suppression impossible: {}", paths.data_dir.display()))?;
    }

    println!("Nuke local termine");
    println!("Les cles, la configuration et la base locale ont ete supprimees.");
    println!("Note: la suppression locale reste best effort selon le systeme de fichiers.");

    Ok(())
}

fn not_implemented(command: &str) -> Result<()> {
    bail!(
        "La commande `{}` est prevue dans le MVP mais n'est pas encore implemente.",
        command
    )
}

fn normalize_workspace_root(path: String) -> Result<PathBuf> {
    let root = PathBuf::from(path);
    let canonical = root
        .canonicalize()
        .with_context(|| format!("Chemin de workspace invalide: {}", root.display()))?;
    if !canonical.is_dir() {
        bail!(
            "Le workspace doit etre un repertoire: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn default_remote_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "upload.bin".to_string())
}
