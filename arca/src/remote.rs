use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use ureq::Response;

use crate::config::AuthSession;

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct UploadRequest {
    pub path: String,
    pub content_base64: String,
}

#[derive(Debug, Serialize)]
pub struct ShareRequest {
    pub path: String,
    pub target_username: String,
}

pub fn register(server_url: &str, username: String, password: String) -> Result<()> {
    let response = ureq::post(&api_url(server_url, "/api/register"))
        .send_json(RegisterRequest { username, password })
        .map_err(read_ureq_error)
        .context("Echec de connexion au serveur")?;

    ensure_success(response.status(), read_body(response))
}

pub fn login(server_url: &str, username: String, password: String) -> Result<AuthSession> {
    let response = ureq::post(&api_url(server_url, "/api/login"))
        .send_json(LoginRequest {
            username: username.clone(),
            password,
        })
        .map_err(read_ureq_error)
        .context("Echec de connexion au serveur")?;

    let status = response.status();
    let body = read_body(response);
    if !(200..300).contains(&status) {
        bail!("Erreur serveur ({status}): {body}");
    }

    let parsed: AuthResponse =
        serde_json::from_str(&body).context("Reponse login invalide du serveur")?;
    Ok(AuthSession {
        server_url: server_url.trim_end_matches('/').to_string(),
        username,
        token: parsed.token,
    })
}

pub fn upload_file(session: &AuthSession, local_path: &Path, remote_path: String) -> Result<()> {
    let content = fs::read(local_path)
        .with_context(|| format!("Lecture impossible: {}", local_path.display()))?;
    let payload = UploadRequest {
        path: remote_path,
        content_base64: STANDARD.encode(content),
    };

    let response = ureq::post(&api_url(&session.server_url, "/api/upload"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .send_json(payload)
        .map_err(read_ureq_error)
        .context("Upload impossible")?;

    ensure_success(response.status(), read_body(response))
}

pub fn share_file(session: &AuthSession, path: String, target_username: String) -> Result<()> {
    let response = ureq::post(&api_url(&session.server_url, "/api/share"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .send_json(ShareRequest {
            path,
            target_username,
        })
        .map_err(read_ureq_error)
        .context("Partage impossible")?;

    ensure_success(response.status(), read_body(response))
}

fn api_url(server_url: &str, path: &str) -> String {
    format!("{}{}", server_url.trim_end_matches('/'), path)
}

fn ensure_success(status: u16, body: String) -> Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        bail!("Erreur serveur ({status}): {body}");
    }
}

fn read_ureq_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => {
            anyhow::anyhow!("Erreur serveur ({status}): {}", read_body(response))
        }
        ureq::Error::Transport(error) => anyhow::anyhow!(error.to_string()),
    }
}

fn read_body(response: Response) -> String {
    response.into_string().unwrap_or_default()
}
