use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::fs;
use std::fs::File;
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
        Command::Watch { once, sync } => watch(once, sync),
        Command::Push => push(),
        Command::Upload {
            path,
            path_flag,
            secret,
            remote_path,
        } => upload(resolve_path_arg(path, path_flag, "upload")?, remote_path, secret),
        Command::Share {
            path,
            with_user,
            path_flag,
            with_user_flag,
        } => share(
            resolve_path_arg(path, path_flag, "share")?,
            resolve_value_arg(with_user, with_user_flag, "share", "destinataire")?,
        ),
        Command::Unshare {
            path,
            with_user,
            path_flag,
            with_user_flag,
        } => unshare(
            resolve_path_arg(path, path_flag, "unshare")?,
            resolve_value_arg(with_user, with_user_flag, "unshare", "destinataire")?,
        ),
        Command::List => list_remote_files(),
        Command::Pull {
            remote_path,
            remote_path_flag,
            output,
            output_flag,
        } => pull(
            resolve_value_arg(remote_path, remote_path_flag, "pull", "chemin distant")?,
            resolve_output_arg(output, output_flag)?,
        ),
        Command::Delete {
            remote_path,
            remote_path_flag,
        } => delete_remote(resolve_value_arg(
            remote_path,
            remote_path_flag,
            "delete",
            "chemin distant",
        )?),
        Command::Nuke { local, remote, yes } => nuke(local, remote, yes),
        Command::Diff => diff(),
        Command::History { path } => history(path),
        Command::Restore { target_dir } => restore(target_dir),
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
    db::reset_local_state(&connection)?;
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
    let (_, public_key_b64) =
        crate::crypto::derive_identity_keypair(&username, &server_url, &password)?;
    crate::remote::register(&server_url, username.clone(), password, public_key_b64)?;
    println!("Compte cree pour `{username}` sur {server_url}");
    Ok(())
}

fn login(server_url: String, username: String, password: String) -> Result<()> {
    let paths = project_paths()?;
    ensure_dirs(&paths)?;
    let (private_key_b64, public_key_b64) =
        crate::crypto::derive_identity_keypair(&username, &server_url, &password)?;
    let mut session = crate::remote::login(
        &server_url,
        username.clone(),
        password,
        public_key_b64.clone(),
    )?;
    session.e2ee_private_key_b64 = private_key_b64;
    session.e2ee_public_key_b64 = public_key_b64;
    save_session(&paths.session_file, &session)?;
    println!("Connexion reussie pour `{username}`");
    println!("Session  : {}", paths.session_file.display());
    Ok(())
}

fn watch(once: bool, sync: bool) -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let mut connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;
    let session = if sync {
        Some(
            load_session(&paths.session_file)
                .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?,
        )
    } else {
        None
    };
    crate::watcher::run(
        &mut connection,
        &config.workspace_root,
        once,
        session.as_ref(),
    )
}

fn push() -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;

    let records = crate::scanner::scan_workspace(&config.workspace_root)?;
    let summary = db::reconcile_file_index(&connection, &records)?;
    println!(
        "Workspace reconcile: {} upserts, {} deletes",
        summary.upserts, summary.deletes
    );

    let synced = crate::syncer::sync_pending_ops(&connection, &config.workspace_root, &session)?;
    println!(
        "Push termine: {} uploads, {} deletes, {} deja absents, {} ops purgees",
        synced.uploads, synced.deletes, synced.already_absent_deletes, synced.purged
    );
    Ok(())
}

fn upload(path: String, remote_path: Option<String>, secret: bool) -> Result<()> {
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
    let secret_password = if secret {
        Some(prompt_secret_password_for_upload(&remote_path)?)
    } else {
        None
    };
    let plaintext = read_file_with_progress(&local_path)?;

    let encrypt_progress = crate::progress::spinner_progress(&format!("Encrypting {}", remote_path));
    let encrypted = crate::crypto::encrypt_for_upload_with_options(
        &session.e2ee_public_key_b64,
        &remote_path,
        &plaintext,
        secret_password.as_deref(),
    )?;
    encrypt_progress.finish_with_message(format!("Encrypting {} done", remote_path));

    let encode_progress = crate::progress::spinner_progress(&format!("Encoding {}", remote_path));
    let body = crate::remote::prepare_upload_payload(
        encrypted.blob,
        remote_path.clone(),
        encrypted.owner_wrapped_key_b64,
    );
    encode_progress.finish_with_message(format!("Encoding {} done", remote_path));

    let upload_label = format!("Uploading {}", remote_path);
    crate::remote::send_upload_payload_with_progress(&session, body, &upload_label)?;
    println!("Upload termine");
    println!("Local  : {}", local_path.display());
    println!("Remote : {}", remote_path);
    println!(
        "Mode   : {}",
        if encrypted.secret_protected {
            "E2EE + secret"
        } else {
            "E2EE"
        }
    );
    println!(
        "Store  : {}",
        if encrypted.compressed {
            "compressed"
        } else {
            "raw"
        }
    );
    Ok(())
}

fn share(path: String, with_user: String) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let recipient_public_key = crate::remote::get_user_public_key(&session, &with_user)?;
    let downloaded = crate::remote::download_file(&session, path.clone())?;
    let file_key = crate::crypto::unwrap_for_reshare(
        &session.e2ee_private_key_b64,
        &path,
        &downloaded.wrapped_key_b64,
    )?;
    let wrapped_key_b64 = crate::crypto::wrap_file_key(&file_key, &path, &recipient_public_key)?;
    crate::remote::share_file_with_wrapped_key(
        &session,
        path.clone(),
        with_user.clone(),
        wrapped_key_b64,
    )?;
    println!("Partage termine");
    println!("Fichier : {}", path);
    println!("Avec    : {}", with_user);
    Ok(())
}

fn unshare(path: String, with_user: String) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    crate::remote::unshare_file(&session, path.clone(), with_user.clone())?;
    println!("Partage revoque");
    println!("Fichier : {}", path);
    println!("Avec    : {}", with_user);
    Ok(())
}

fn list_remote_files() -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let files = crate::remote::list_files(&session)?;

    println!("Fichiers distants accessibles");
    if files.is_empty() {
        println!("Aucun fichier distant");
        return Ok(());
    }

    for file in files {
        let access = if file.shared { "shared" } else { "owned" };
        println!(
            "- {} | owner={} | access={} | size={} bytes",
            file.path, file.owner, access, file.size_bytes
        );
    }

    Ok(())
}

fn pull(remote_path: String, output: String) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let output_path = PathBuf::from(output);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creation impossible: {}", parent.display()))?;
        }
    }

    let progress_label = format!("Downloading {}", remote_path);
    let response =
        crate::remote::download_file_with_progress(&session, remote_path.clone(), &progress_label)?;
    let plaintext = decrypt_with_optional_secret_prompt(&session, &remote_path, &response)?;
    fs::write(&output_path, plaintext)
        .with_context(|| format!("Ecriture impossible: {}", output_path.display()))?;
    let access = if response.shared { "shared" } else { "owned" };
    println!("Download termine");
    println!("Remote : {}", response.path);
    println!("Owner  : {}", response.owner);
    println!("Access : {}", access);
    println!("Output : {}", output_path.display());
    println!("Mode   : E2EE");
    Ok(())
}

fn delete_remote(remote_path: String) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    crate::remote::delete_file(&session, remote_path.clone())?;
    println!("Suppression distante terminee");
    println!("Remote : {}", remote_path);
    Ok(())
}

fn resolve_path_arg(
    path: Option<String>,
    path_flag: Option<String>,
    command: &str,
) -> Result<String> {
    match (path, path_flag) {
        (Some(path), None) | (None, Some(path)) => Ok(path),
        (Some(_), Some(_)) => bail!(
            "Utilise soit l'argument positionnel soit `--path` pour `{command}`, pas les deux."
        ),
        (None, None) => bail!("Chemin manquant pour `{command}`."),
    }
}

fn read_file_with_progress(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(path).with_context(|| format!("Lecture metadata impossible: {}", path.display()))?;
    let total_bytes = metadata.len();
    let label = format!("Reading {}", path.display());
    let progress = crate::progress::byte_progress(&label, total_bytes);
    let mut file =
        File::open(path).with_context(|| format!("Lecture impossible: {}", path.display()))?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = Vec::with_capacity(total_bytes.min(usize::MAX as u64) as usize);

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        progress.inc(read as u64);
    }

    progress.set_position(total_bytes);
    progress.finish_with_message(format!("Reading {} done", path.display()));
    Ok(bytes)
}

fn prompt_secret_password_for_upload(remote_path: &str) -> Result<String> {
    let password = rpassword::prompt_password(format!(
        "Secret password for `{remote_path}`: "
    ))?;
    if password.is_empty() {
        bail!("Mot de passe secret vide interdit");
    }
    let confirmation = rpassword::prompt_password(format!(
        "Confirm secret password for `{remote_path}`: "
    ))?;
    if password != confirmation {
        bail!("Confirmation du mot de passe secret invalide");
    }
    Ok(password)
}

fn prompt_secret_password_for_download(remote_path: &str) -> Result<String> {
    let password = rpassword::prompt_password(format!(
        "Secret password required for `{remote_path}`: "
    ))?;
    if password.is_empty() {
        bail!("Mot de passe secret vide interdit");
    }
    Ok(password)
}

fn decrypt_with_optional_secret_prompt(
    session: &crate::config::AuthSession,
    remote_path: &str,
    response: &crate::remote::DownloadedBlob,
) -> Result<Vec<u8>> {
    match crate::crypto::decrypt_downloaded_blob_with_secret(
        &session.e2ee_private_key_b64,
        remote_path,
        &response.wrapped_key_b64,
        &response.content,
        None,
    ) {
        Ok(plaintext) => Ok(plaintext),
        Err(error) if error.to_string().contains("mot de passe secret") => {
            let password = prompt_secret_password_for_download(remote_path)?;
            crate::crypto::decrypt_downloaded_blob_with_secret(
                &session.e2ee_private_key_b64,
                remote_path,
                &response.wrapped_key_b64,
                &response.content,
                Some(&password),
            )
        }
        Err(error) => Err(error),
    }
}

fn resolve_value_arg(
    value: Option<String>,
    value_flag: Option<String>,
    command: &str,
    field_name: &str,
) -> Result<String> {
    match (value, value_flag) {
        (Some(value), None) | (None, Some(value)) => Ok(value),
        (Some(_), Some(_)) => bail!(
            "Utilise soit l'argument positionnel soit l'option legacy pour `{command}` ({field_name}), pas les deux."
        ),
        (None, None) => bail!("Argument manquant pour `{command}`: {field_name}."),
    }
}

fn resolve_output_arg(output: Option<String>, output_flag: Option<String>) -> Result<String> {
    match (output, output_flag) {
        (Some(output), None) | (None, Some(output)) => Ok(output),
        (Some(_), Some(_)) => bail!(
            "Utilise soit l'argument positionnel soit `--output` pour `pull`, pas les deux."
        ),
        (None, None) => bail!(
            "Chemin de sortie manquant pour `pull`. Utilise `arca pull <remote_path> <output>`."
        ),
    }
}

fn diff() -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;

    let local_records = crate::scanner::scan_workspace(&config.workspace_root)?;
    let remote_files = crate::remote::list_files(&session)?;
    let pending_ops = db::list_pending_ops(&connection, 10_000)?;

    let local_paths = local_records
        .iter()
        .map(|record| record.relative_path.clone())
        .collect::<HashSet<_>>();
    let remote_by_path = remote_files
        .into_iter()
        .map(|file| (file.path.clone(), file))
        .collect::<HashMap<_, _>>();
    let remote_paths = remote_by_path.keys().cloned().collect::<HashSet<_>>();

    let mut pending_upserts = HashSet::new();
    let mut pending_deletes = HashSet::new();
    for op in pending_ops {
        match (op.op_type.as_str(), op.target_path) {
            ("file_upsert", Some(path)) => {
                pending_upserts.insert(path);
            }
            ("file_delete", Some(path)) => {
                pending_deletes.insert(path);
            }
            _ => {}
        }
    }

    let all_paths = local_paths
        .union(&remote_paths)
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut pending_upload_lines = Vec::new();
    let mut pending_delete_lines = Vec::new();
    let mut local_only_lines = Vec::new();
    let mut remote_only_lines = Vec::new();
    let mut both_without_pending = 0usize;

    for path in all_paths {
        let local_exists = local_paths.contains(&path);
        let remote = remote_by_path.get(&path);
        let has_pending_upsert = pending_upserts.contains(&path);
        let has_pending_delete = pending_deletes.contains(&path);

        if has_pending_delete {
            pending_delete_lines.push(path);
            continue;
        }

        if has_pending_upsert {
            let state = if remote.is_some() {
                "local changes pending upload"
            } else {
                "new local file pending upload"
            };
            pending_upload_lines.push(format!("{path} | {state}"));
            continue;
        }

        match (local_exists, remote) {
            (true, Some(_)) => both_without_pending += 1,
            (true, None) => local_only_lines.push(path),
            (false, Some(file)) => {
                let access = if file.shared { "shared" } else { "owned" };
                remote_only_lines.push(format!(
                    "{} | owner={} | access={}",
                    file.path, file.owner, access
                ));
            }
            (false, None) => {}
        }
    }

    println!("Diff local / distant");
    println!("Workspace : {}", config.workspace_root.display());
    println!("Local scan : {} fichiers", local_paths.len());
    println!("Remote     : {} fichiers accessibles", remote_paths.len());
    println!("Both       : {} chemins presents des deux cotes sans pending op", both_without_pending);
    println!("Pending up : {}", pending_upload_lines.len());
    println!("Pending del: {}", pending_delete_lines.len());
    println!("Local only : {}", local_only_lines.len());
    println!("Remote only: {}", remote_only_lines.len());

    if pending_upload_lines.is_empty()
        && pending_delete_lines.is_empty()
        && local_only_lines.is_empty()
        && remote_only_lines.is_empty()
    {
        println!("Aucune difference evidente detectee.");
        println!("Note: ce diff MVP compare les chemins et la file locale pending_ops, pas le contenu chiffre distant.");
        return Ok(());
    }

    if !pending_upload_lines.is_empty() {
        println!("\nPending uploads");
        for line in &pending_upload_lines {
            println!("- {line}");
        }
    }

    if !pending_delete_lines.is_empty() {
        println!("\nPending deletes");
        for path in &pending_delete_lines {
            println!("- {path}");
        }
    }

    if !local_only_lines.is_empty() {
        println!("\nLocal only");
        for path in &local_only_lines {
            println!("- {path}");
        }
    }

    if !remote_only_lines.is_empty() {
        println!("\nRemote only");
        for line in &remote_only_lines {
            println!("- {line}");
        }
    }

    println!("\nNote: ce diff MVP compare les chemins et la file locale pending_ops, pas le contenu chiffre distant.");
    Ok(())
}

fn history(path: Option<String>) -> Result<()> {
    let paths = project_paths()?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let events = crate::remote::history(&session, path)?;

    println!("Historique distant");
    if events.is_empty() {
        println!("Aucun evenement");
        return Ok(());
    }

    for event in events {
        match event.target_username {
            Some(target_username) => println!(
                "- {} | action={} | path={} | owner={} | actor={} | target={}",
                event.created_at,
                event.action,
                event.path,
                event.owner,
                event.actor,
                target_username
            ),
            None => println!(
                "- {} | action={} | path={} | owner={} | actor={}",
                event.created_at, event.action, event.path, event.owner, event.actor
            ),
        }
    }

    Ok(())
}

fn restore(target_dir: Option<String>) -> Result<()> {
    let paths = project_paths()?;
    let config = load_config(&paths.config_file)
        .with_context(|| "Projet non initialise. Lance d'abord `arca init`.".to_string())?;
    let session = load_session(&paths.session_file)
        .with_context(|| "Aucune session. Lance d'abord `arca login`.".to_string())?;
    let connection = db::connect(&paths.database_file)?;
    db::initialize(&connection)?;

    let destination_root = match target_dir {
        Some(path) => PathBuf::from(path),
        None => config.workspace_root.clone(),
    };
    fs::create_dir_all(&destination_root)
        .with_context(|| format!("Creation impossible: {}", destination_root.display()))?;

    let files = crate::remote::list_files(&session)?;
    if files.is_empty() {
        println!("Aucun fichier distant a restaurer");
        return Ok(());
    }

    let update_workspace_index = destination_root == config.workspace_root;
    let mut restored = 0usize;
    let mut failed = Vec::new();

    for file in files {
        let output_path = destination_root.join(&file.path);
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Creation impossible: {}", parent.display()))?;
        }

        let restore_result = (|| -> Result<()> {
            let progress_label = format!("Downloading {}", file.path);
            let response = crate::remote::download_file_with_progress(
                &session,
                file.path.clone(),
                &progress_label,
            )?;
            let plaintext = decrypt_with_optional_secret_prompt(&session, &file.path, &response)?;
            fs::write(&output_path, plaintext)
                .with_context(|| format!("Ecriture impossible: {}", output_path.display()))?;

            if update_workspace_index {
                let record =
                    crate::scanner::file_record_from_path(&config.workspace_root, &output_path)?;
                db::upsert_file_index_only(&connection, &record)?;
                db::delete_pending_ops_for_path(&connection, &file.path)?;
            }

            let access = if response.shared { "shared" } else { "owned" };
            println!(
                "Restored {} -> {} ({})",
                file.path,
                output_path.display(),
                access
            );
            Ok(())
        })();

        match restore_result {
            Ok(()) => restored += 1,
            Err(error) => {
                let message = format!("{}: {error}", file.path);
                eprintln!("Restore skipped {message}");
                failed.push(message);
            }
        }
    }

    println!("Restauration terminee: {} fichiers", restored);
    println!("Destination : {}", destination_root.display());
    if update_workspace_index {
        println!("Index local : mis a jour sans ajouter d'operations pending");
    } else {
        println!("Index local : non modifie (dossier cible externe au workspace)");
    }

    if !failed.is_empty() {
        eprintln!("Fichiers non restaures: {}", failed.len());
        for failure in &failed {
            eprintln!("- {failure}");
        }
        bail!(
            "Restauration partielle: {} fichier(s) restaure(s), {} echec(s)",
            restored,
            failed.len()
        );
    }

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
