use std::io::Cursor;
use std::io::Read;

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
    pub public_key_b64: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub public_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Debug)]
pub struct PreparedUpload {
    pub path: String,
    pub content: Vec<u8>,
    pub owner_wrapped_key_b64: String,
}

#[derive(Debug, Serialize)]
pub struct ShareRequest {
    pub path: String,
    pub target_username: String,
    pub wrapped_key_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteRequest {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoteFileSummary {
    pub path: String,
    pub owner: String,
    pub shared: bool,
    pub size_bytes: i64,
}

#[derive(Debug, Deserialize)]
pub struct DownloadResponse {
    pub path: String,
    pub owner: String,
    pub shared: bool,
    pub content_base64: String,
    pub wrapped_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoteHistoryEvent {
    pub path: String,
    pub owner: String,
    pub actor: String,
    pub action: String,
    pub target_username: Option<String>,
    pub created_at: String,
}

#[derive(Debug)]
pub struct DownloadedBlob {
    pub path: String,
    pub owner: String,
    pub shared: bool,
    pub content: Vec<u8>,
    pub wrapped_key_b64: String,
}

pub fn register(
    server_url: &str,
    username: String,
    password: String,
    public_key_b64: String,
) -> Result<()> {
    let response = ureq::post(&api_url(server_url, "/api/register"))
        .send_json(RegisterRequest {
            username,
            password,
            public_key_b64,
        })
        .map_err(read_ureq_error)
        .context("Echec de connexion au serveur")?;

    ensure_success(response.status(), read_body(response))
}

pub fn login(
    server_url: &str,
    username: String,
    password: String,
    public_key_b64: String,
) -> Result<AuthSession> {
    let response = ureq::post(&api_url(server_url, "/api/login"))
        .send_json(LoginRequest {
            username: username.clone(),
            password,
            public_key_b64: public_key_b64.clone(),
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
        e2ee_private_key_b64: String::new(),
        e2ee_public_key_b64: public_key_b64,
    })
}

pub fn upload_file(
    session: &AuthSession,
    content: Vec<u8>,
    remote_path: String,
    owner_wrapped_key_b64: String,
) -> Result<()> {
    let payload = prepare_upload_payload(content, remote_path, owner_wrapped_key_b64);
    send_upload_payload(session, payload)
}

pub fn prepare_upload_payload(
    content: Vec<u8>,
    remote_path: String,
    owner_wrapped_key_b64: String,
) -> PreparedUpload {
    PreparedUpload {
        path: remote_path,
        content,
        owner_wrapped_key_b64,
    }
}

pub fn send_upload_payload(session: &AuthSession, payload: PreparedUpload) -> Result<()> {
    send_upload_payload_internal(session, payload, None)
}

pub fn send_upload_payload_with_progress(
    session: &AuthSession,
    payload: PreparedUpload,
    label: &str,
) -> Result<()> {
    send_upload_payload_internal(session, payload, Some(label))
}

fn send_upload_payload_internal(
    session: &AuthSession,
    payload: PreparedUpload,
    progress_label: Option<&str>,
) -> Result<()> {
    let content_length = payload.content.len() as u64;
    let encoded_path = url_encode_path(&payload.path);
    let request = ureq::post(&api_url(&session.server_url, "/api/upload"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .set("Content-Type", "application/octet-stream")
        .set("X-Arca-Path", &encoded_path)
        .set("X-Arca-Owner-Wrapped-Key", &payload.owner_wrapped_key_b64)
        .set("Content-Length", &content_length.to_string());

    let response = if let Some(label) = progress_label {
        let progress = crate::progress::byte_progress(label, content_length);
        let reader =
            crate::progress::ProgressReader::new(Cursor::new(payload.content), progress.clone());
        let response = request
            .send(reader)
            .map_err(read_ureq_error)
            .context("Upload impossible");
        progress.set_position(content_length);
        progress.finish_with_message(format!("{label} done"));
        response?
    } else {
        request
            .send_bytes(&payload.content)
            .map_err(read_ureq_error)
            .context("Upload impossible")?
    };

    ensure_success(response.status(), read_body(response))
}

pub fn share_file_with_wrapped_key(
    session: &AuthSession,
    path: String,
    target_username: String,
    wrapped_key_b64: String,
) -> Result<()> {
    let response = ureq::post(&api_url(&session.server_url, "/api/share"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .send_json(ShareRequest {
            path,
            target_username,
            wrapped_key_b64: Some(wrapped_key_b64),
        })
        .map_err(read_ureq_error)
        .context("Partage impossible")?;

    ensure_success(response.status(), read_body(response))
}

pub fn unshare_file(session: &AuthSession, path: String, target_username: String) -> Result<()> {
    let response = ureq::post(&api_url(&session.server_url, "/api/unshare"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .send_json(ShareRequest {
            path,
            target_username,
            wrapped_key_b64: None,
        })
        .map_err(read_ureq_error)
        .context("Revocation impossible")?;

    ensure_success(response.status(), read_body(response))
}

pub fn list_files(session: &AuthSession) -> Result<Vec<RemoteFileSummary>> {
    let response = ureq::get(&api_url(&session.server_url, "/api/files"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .call()
        .map_err(read_ureq_error)
        .context("Listing distant impossible")?;

    let body = read_body(response);
    let files = serde_json::from_str::<Vec<RemoteFileSummary>>(&body)
        .context("Reponse liste fichiers invalide")?;
    Ok(files)
}

pub fn get_user_public_key(session: &AuthSession, username: &str) -> Result<String> {
    let encoded = url_encode_path(username);
    let response = ureq::get(&api_url(
        &session.server_url,
        &format!("/api/public-key?username={encoded}"),
    ))
    .set("Authorization", &format!("Bearer {}", session.token))
    .call()
    .map_err(read_ureq_error)
    .context("Lecture de cle publique impossible")?;

    let body = read_body(response);
    let payload = serde_json::from_str::<PublicKeyResponse>(&body)
        .context("Reponse cle publique invalide")?;
    Ok(payload.public_key_b64)
}

pub fn download_file(session: &AuthSession, remote_path: String) -> Result<DownloadedBlob> {
    download_file_internal(session, remote_path, None)
}

pub fn download_file_with_progress(
    session: &AuthSession,
    remote_path: String,
    label: &str,
) -> Result<DownloadedBlob> {
    download_file_internal(session, remote_path, Some(label))
}

fn download_file_internal(
    session: &AuthSession,
    remote_path: String,
    progress_label: Option<&str>,
) -> Result<DownloadedBlob> {
    let encoded = url_encode_path(&remote_path);
    let response = ureq::get(&api_url(
        &session.server_url,
        &format!("/api/download?path={encoded}"),
    ))
    .set("Authorization", &format!("Bearer {}", session.token))
    .call()
    .map_err(read_ureq_error)
    .context("Download impossible")?;

    let body = read_body_with_progress(response, progress_label)
        .context("Lecture du corps download impossible")?;
    let payload =
        serde_json::from_str::<DownloadResponse>(&body).context("Reponse download invalide")?;
    let content = STANDARD
        .decode(payload.content_base64.as_bytes())
        .context("Contenu telecharge invalide")?;
    Ok(DownloadedBlob {
        path: payload.path,
        owner: payload.owner,
        shared: payload.shared,
        content,
        wrapped_key_b64: payload.wrapped_key_b64,
    })
}

pub fn history(session: &AuthSession, path: Option<String>) -> Result<Vec<RemoteHistoryEvent>> {
    let suffix = match path {
        Some(path) => format!("/api/history?path={}", url_encode_path(&path)),
        None => "/api/history".to_string(),
    };
    let response = ureq::get(&api_url(&session.server_url, &suffix))
        .set("Authorization", &format!("Bearer {}", session.token))
        .call()
        .map_err(read_ureq_error)
        .context("Lecture historique impossible")?;

    let body = read_body(response);
    let events = serde_json::from_str::<Vec<RemoteHistoryEvent>>(&body)
        .context("Reponse historique invalide")?;
    Ok(events)
}

pub fn delete_file(session: &AuthSession, remote_path: String) -> Result<()> {
    let response = ureq::post(&api_url(&session.server_url, "/api/delete"))
        .set("Authorization", &format!("Bearer {}", session.token))
        .send_json(DeleteRequest { path: remote_path })
        .map_err(read_ureq_error)
        .context("Suppression distante impossible")?;

    ensure_success(response.status(), read_body(response))
}

fn api_url(server_url: &str, path: &str) -> String {
    format!("{}{}", server_url.trim_end_matches('/'), path)
}

fn ensure_success(status: u16, body: String) -> Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        bail!("{}", format_server_error(status, &body));
    }
}

fn read_ureq_error(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(status, response) => anyhow::anyhow!(
            "{}",
            format_server_error(status, &read_body(response))
        ),
        ureq::Error::Transport(error) => anyhow::anyhow!(error.to_string()),
    }
}

fn read_body(response: Response) -> String {
    response.into_string().unwrap_or_default()
}

fn read_body_with_progress(response: Response, progress_label: Option<&str>) -> Result<String> {
    let total_bytes = response
        .header("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let mut reader = response.into_reader();
    let mut buffer = [0_u8; 16 * 1024];
    let mut bytes = Vec::new();
    let progress = progress_label.map(|label| crate::progress::download_progress(label, total_bytes));

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(progress) = progress.as_ref() {
            progress.inc(read as u64);
        }
    }

    if let Some(progress) = progress {
        if let Some(total_bytes) = total_bytes {
            progress.set_position(total_bytes);
        }
        progress.finish();
    }

    String::from_utf8(bytes).context("Corps HTTP non UTF-8")
}

fn url_encode_path(path: &str) -> String {
    path.replace('%', "%25")
        .replace('/', "%2F")
        .replace(' ', "%20")
}

fn format_server_error(status: u16, body: &str) -> String {
    match status {
        401 => "Authentification requise ou session invalide. Lance d'abord `arca login`."
            .to_string(),
        413 => {
            let suffix = if body.trim().is_empty() {
                String::new()
            } else {
                format!(" Detail serveur: {}", body.trim())
            };
            format!(
                "Erreur serveur (413): payload trop volumineux. Reduis la taille ou augmente `ARCA_SERVER_MAX_BODY_MB` sur le serveur.{suffix}"
            )
        }
        _ => format!("Erreur serveur ({status}): {body}"),
    }
}
