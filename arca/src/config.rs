use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const QUALIFIER: &str = "dev";
const ORGANIZATION: &str = "arca";
const APPLICATION: &str = "arca";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
    pub session_file: PathBuf,
    pub database_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub workspace_id: Uuid,
    pub workspace_name: String,
    pub workspace_root: PathBuf,
    pub device_id: Uuid,
    pub schema_version: u32,
    pub panic_grace_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub server_url: String,
    pub username: String,
    pub token: String,
}

impl AppConfig {
    pub fn new(workspace_name: String, workspace_root: PathBuf) -> Self {
        Self {
            workspace_id: Uuid::new_v4(),
            workspace_name,
            workspace_root,
            device_id: Uuid::new_v4(),
            schema_version: 1,
            panic_grace_seconds: 30,
        }
    }
}

pub fn project_paths() -> Result<AppPaths> {
    let dirs = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .context("Impossible de determiner les repertoires applicatifs")?;

    let config_dir = dirs.config_dir().to_path_buf();
    let data_dir = dirs.data_dir().to_path_buf();

    Ok(AppPaths {
        config_file: config_dir.join("config.toml"),
        session_file: config_dir.join("session.toml"),
        database_file: data_dir.join("state.sqlite"),
        config_dir,
        data_dir,
    })
}

pub fn ensure_dirs(paths: &AppPaths) -> Result<()> {
    fs::create_dir_all(&paths.config_dir)
        .with_context(|| format!("Creation impossible: {}", paths.config_dir.display()))?;
    fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("Creation impossible: {}", paths.data_dir.display()))?;
    Ok(())
}

pub fn load_config(path: &Path) -> Result<AppConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Lecture impossible: {}", path.display()))?;
    let config =
        toml::from_str(&raw).with_context(|| format!("Config invalide: {}", path.display()))?;
    Ok(config)
}

pub fn save_config(path: &Path, config: &AppConfig) -> Result<()> {
    let serialized = toml::to_string_pretty(config).context("Serialization TOML impossible")?;
    fs::write(path, serialized).with_context(|| format!("Ecriture impossible: {}", path.display()))
}

pub fn load_session(path: &Path) -> Result<AuthSession> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Lecture impossible: {}", path.display()))?;
    let session =
        toml::from_str(&raw).with_context(|| format!("Session invalide: {}", path.display()))?;
    Ok(session)
}

pub fn save_session(path: &Path, session: &AuthSession) -> Result<()> {
    let serialized = toml::to_string_pretty(session).context("Serialization TOML impossible")?;
    fs::write(path, serialized).with_context(|| format!("Ecriture impossible: {}", path.display()))
}
