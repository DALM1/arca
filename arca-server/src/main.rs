use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::OsRng;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
}

#[derive(Debug, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct UploadRequest {
    path: String,
    content_base64: String,
}

#[derive(Debug, Deserialize)]
struct ShareRequest {
    path: String,
    target_username: String,
}

#[derive(Debug, Serialize)]
struct FileSummary {
    path: String,
    owner: String,
    shared: bool,
    size_bytes: i64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let database_path =
        std::env::var("ARCA_SERVER_DB").unwrap_or_else(|_| "arca-server.sqlite".to_string());
    let bind = std::env::var("ARCA_SERVER_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());

    let connection = Connection::open(&database_path)
        .with_context(|| format!("Ouverture SQLite impossible: {database_path}"))?;
    initialize(&connection)?;

    let state = AppState {
        db: Arc::new(Mutex::new(connection)),
    };

    let app = Router::new()
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/upload", post(upload))
        .route("/api/share", post(share))
        .route("/api/files", get(list_files))
        .with_state(state);

    let addr: SocketAddr = bind.parse().context("Adresse bind invalide")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Arca server on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<Credentials>,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    match create_user(&mut db, payload) {
        Ok(()) => (StatusCode::CREATED, "registered".to_string()),
        Err(error) => map_error(error),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<Credentials>,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    match create_session(&mut db, payload) {
        Ok(token) => (
            StatusCode::OK,
            serde_json::to_string(&AuthResponse { token }).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(error) => map_error(error),
    }
}

async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UploadRequest>,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match store_file(&mut db, user_id, payload) {
        Ok(()) => (StatusCode::OK, "uploaded".to_string()),
        Err(error) => map_error(error),
    }
}

async fn share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ShareRequest>,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match share_file(&mut db, user_id, payload) {
        Ok(()) => (StatusCode::OK, "shared".to_string()),
        Err(error) => map_error(error),
    }
}

async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match accessible_files(&db, user_id) {
        Ok(files) => (
            StatusCode::OK,
            serde_json::to_string(&files).unwrap_or_else(|_| "[]".to_string()),
        ),
        Err(error) => map_error(error),
    }
}

fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            content BLOB NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(owner_id, path),
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shares (
            file_id INTEGER NOT NULL,
            target_user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(file_id, target_user_id),
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(target_user_id) REFERENCES users(id)
        );
        "#,
    )?;
    Ok(())
}

fn create_user(connection: &mut Connection, payload: Credentials) -> Result<()> {
    let username = payload.username.trim();
    if username.is_empty() || payload.password.len() < 8 {
        return Err(anyhow!(
            "Le username est obligatoire et le mot de passe doit faire au moins 8 caracteres"
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .context("Hash password impossible")?
        .to_string();

    connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        params![username, password_hash],
    )?;
    Ok(())
}

fn create_session(connection: &mut Connection, payload: Credentials) -> Result<String> {
    let user = connection
        .query_row(
            "SELECT id, password_hash FROM users WHERE username = ?1",
            params![payload.username],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Utilisateur inconnu"))?;

    let parsed_hash = PasswordHash::new(&user.1).context("Hash stocke invalide")?;
    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| anyhow!("Mot de passe invalide"))?;

    let token = Uuid::new_v4().to_string();
    connection.execute(
        "INSERT INTO sessions (token, user_id) VALUES (?1, ?2)",
        params![token, user.0],
    )?;
    Ok(token)
}

fn authenticate(connection: &Connection, headers: &HeaderMap) -> Option<i64> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    connection
        .query_row(
            "SELECT user_id FROM sessions WHERE token = ?1",
            params![token],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
}

fn store_file(connection: &mut Connection, user_id: i64, payload: UploadRequest) -> Result<()> {
    let content = STANDARD
        .decode(payload.content_base64)
        .context("Contenu base64 invalide")?;
    let content_hash = blake3::hash(&content).to_hex().to_string();

    connection.execute(
        "INSERT INTO files (owner_id, path, content_hash, size_bytes, content, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
         ON CONFLICT(owner_id, path) DO UPDATE SET
             content_hash = excluded.content_hash,
             size_bytes = excluded.size_bytes,
             content = excluded.content,
             updated_at = CURRENT_TIMESTAMP",
        params![
            user_id,
            payload.path,
            content_hash,
            content.len() as i64,
            content,
        ],
    )?;
    Ok(())
}

fn share_file(connection: &mut Connection, user_id: i64, payload: ShareRequest) -> Result<()> {
    let file_id = connection
        .query_row(
            "SELECT id FROM files WHERE owner_id = ?1 AND path = ?2",
            params![user_id, payload.path],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Fichier introuvable ou non possede"))?;

    let target_user_id = connection
        .query_row(
            "SELECT id FROM users WHERE username = ?1",
            params![payload.target_username],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Utilisateur cible introuvable"))?;

    connection.execute(
        "INSERT OR IGNORE INTO shares (file_id, target_user_id) VALUES (?1, ?2)",
        params![file_id, target_user_id],
    )?;
    Ok(())
}

fn accessible_files(connection: &Connection, user_id: i64) -> Result<Vec<FileSummary>> {
    let mut statement = connection.prepare(
        r#"
        SELECT f.path, u.username, CASE WHEN f.owner_id = ?1 THEN 0 ELSE 1 END, f.size_bytes
        FROM files f
        JOIN users u ON u.id = f.owner_id
        LEFT JOIN shares s ON s.file_id = f.id AND s.target_user_id = ?1
        WHERE f.owner_id = ?1 OR s.target_user_id = ?1
        ORDER BY f.path
        "#,
    )?;

    let rows = statement.query_map(params![user_id], |row| {
        Ok(FileSummary {
            path: row.get(0)?,
            owner: row.get(1)?,
            shared: row.get::<_, i64>(2)? == 1,
            size_bytes: row.get(3)?,
        })
    })?;

    let mut files = Vec::new();
    for row in rows {
        files.push(row?);
    }
    Ok(files)
}

fn map_error(error: anyhow::Error) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("UNIQUE constraint failed") {
        err(StatusCode::CONFLICT, "Utilisateur deja existant")
    } else if message.contains("Mot de passe invalide") || message.contains("Utilisateur inconnu") {
        err(StatusCode::UNAUTHORIZED, &message)
    } else if message.contains("introuvable") || message.contains("non possede") {
        err(StatusCode::NOT_FOUND, &message)
    } else if message.contains("obligatoire") || message.contains("invalide") {
        err(StatusCode::BAD_REQUEST, &message)
    } else {
        err(StatusCode::INTERNAL_SERVER_ERROR, &message)
    }
}

fn err(status: StatusCode, message: &str) -> (StatusCode, String) {
    (status, message.to_string())
}
