use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
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
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct ShareRequest {
    path: String,
    target_username: String,
    wrapped_key_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeleteRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct FileSummary {
    path: String,
    owner: String,
    shared: bool,
    size_bytes: i64,
}

#[derive(Debug, Serialize)]
struct DownloadResponse {
    path: String,
    owner: String,
    shared: bool,
    content_base64: String,
    wrapped_key_b64: String,
}

#[derive(Debug, Serialize)]
struct HistoryEvent {
    path: String,
    owner: String,
    actor: String,
    action: String,
    target_username: Option<String>,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    username: String,
    public_key_b64: String,
}

#[derive(Debug, Deserialize)]
struct DownloadQuery {
    path: String,
}

#[derive(Debug, Deserialize)]
struct UserQuery {
    username: String,
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let database_path =
        std::env::var("ARCA_SERVER_DB").unwrap_or_else(|_| "arca-server.sqlite".to_string());
    let bind = std::env::var("ARCA_SERVER_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let max_body_mb = std::env::var("ARCA_SERVER_MAX_BODY_MB")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(512);
    let max_body_bytes = max_body_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow!("ARCA_SERVER_MAX_BODY_MB trop grand"))?;

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
        .route("/api/unshare", post(unshare))
        .route("/api/delete", post(delete_file))
        .route("/api/public-key", get(public_key))
        .route("/api/files", get(list_files))
        .route("/api/history", get(history))
        .route("/api/download", get(download))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state);

    let addr: SocketAddr = bind.parse().context("Adresse bind invalide")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Arca server on http://{}", listener.local_addr()?);
    println!(
        "Upload body limit: {} MiB (ARCA_SERVER_MAX_BODY_MB)",
        max_body_mb
    );
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
    body: Bytes,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    let (path, owner_wrapped_key_b64) = match parse_upload_headers(&headers) {
        Ok(values) => values,
        Err(error) => return map_error(error),
    };

    match store_file(&mut db, user_id, path, owner_wrapped_key_b64, body.to_vec()) {
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

async fn unshare(
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

    match unshare_file(&mut db, user_id, payload) {
        Ok(()) => (StatusCode::OK, "unshared".to_string()),
        Err(error) => map_error(error),
    }
}

async fn delete_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DeleteRequest>,
) -> impl IntoResponse {
    let mut db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match delete_owned_file(&mut db, user_id, &payload.path) {
        Ok(()) => (StatusCode::OK, "deleted".to_string()),
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

async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DownloadQuery>,
) -> impl IntoResponse {
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match fetch_file_for_user(&db, user_id, &query.path) {
        Ok(file) => (
            StatusCode::OK,
            serde_json::to_string(&file).unwrap_or_else(|_| "{}".to_string()),
        ),
        Err(error) => map_error(error),
    }
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    let Some(user_id) = authenticate(&db, &headers) else {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    };

    match list_history(&db, user_id, query.path.as_deref()) {
        Ok(events) => (
            StatusCode::OK,
            serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string()),
        ),
        Err(error) => map_error(error),
    }
}

async fn public_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserQuery>,
) -> impl IntoResponse {
    let db = match state.db.lock() {
        Ok(db) => db,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "DB lock poisoned"),
    };

    if authenticate(&db, &headers).is_none() {
        return err(StatusCode::UNAUTHORIZED, "Invalid or missing token");
    }

    match get_user_public_key(&db, &query.username) {
        Ok(payload) => (
            StatusCode::OK,
            serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
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
            public_key_b64 TEXT,
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
            owner_wrapped_key_b64 TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(owner_id, path),
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS shares (
            file_id INTEGER NOT NULL,
            target_user_id INTEGER NOT NULL,
            wrapped_key_b64 TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(file_id, target_user_id),
            FOREIGN KEY(file_id) REFERENCES files(id),
            FOREIGN KEY(target_user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            path TEXT NOT NULL,
            actor_user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_username TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id),
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_file_events_owner_path_id
            ON file_events(owner_id, path, id DESC);
        "#,
    )?;
    ensure_column(connection, "users", "public_key_b64", "TEXT")?;
    ensure_column(connection, "files", "owner_wrapped_key_b64", "TEXT")?;
    ensure_column(connection, "shares", "wrapped_key_b64", "TEXT")?;
    Ok(())
}

fn create_user(connection: &mut Connection, payload: Credentials) -> Result<()> {
    let username = payload.username.trim();
    if username.is_empty() || payload.password.len() < 8 || payload.public_key_b64.trim().is_empty()
    {
        return Err(anyhow!(
            "Le username, la cle publique et le mot de passe sont obligatoires"
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|error| anyhow!("Hash password impossible: {error}"))?
        .to_string();

    connection.execute(
        "INSERT INTO users (username, password_hash, public_key_b64) VALUES (?1, ?2, ?3)",
        params![username, password_hash, payload.public_key_b64],
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

    let parsed_hash =
        PasswordHash::new(&user.1).map_err(|error| anyhow!("Hash stocke invalide: {error}"))?;
    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| anyhow!("Mot de passe invalide"))?;

    connection.execute(
        "UPDATE users SET public_key_b64 = ?1 WHERE id = ?2",
        params![payload.public_key_b64, user.0],
    )?;

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

fn store_file(
    connection: &mut Connection,
    user_id: i64,
    path: String,
    owner_wrapped_key_b64: String,
    content: Vec<u8>,
) -> Result<()> {
    if path.trim().is_empty() {
        return Err(anyhow!("Chemin upload obligatoire"));
    }
    if owner_wrapped_key_b64.trim().is_empty() {
        return Err(anyhow!("Cle proprietaire upload obligatoire"));
    }

    let content_hash = blake3::hash(&content).to_hex().to_string();
    let action = if connection
        .query_row(
            "SELECT 1 FROM files WHERE owner_id = ?1 AND path = ?2",
            params![user_id, path],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        "update"
    } else {
        "upload"
    };

    connection.execute(
        "INSERT INTO files (owner_id, path, content_hash, size_bytes, content, owner_wrapped_key_b64, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)
         ON CONFLICT(owner_id, path) DO UPDATE SET
             content_hash = excluded.content_hash,
             size_bytes = excluded.size_bytes,
             content = excluded.content,
             owner_wrapped_key_b64 = excluded.owner_wrapped_key_b64,
             updated_at = CURRENT_TIMESTAMP",
        params![
            user_id,
            path,
            content_hash,
            content.len() as i64,
            content,
            owner_wrapped_key_b64,
        ],
    )?;
    append_file_event(connection, user_id, &path, user_id, action, None)?;
    Ok(())
}

fn parse_upload_headers(headers: &HeaderMap) -> Result<(String, String)> {
    let encoded_path = headers
        .get("x-arca-path")
        .ok_or_else(|| anyhow!("Header upload manquant: X-Arca-Path"))?
        .to_str()
        .context("Header upload invalide: X-Arca-Path")?;
    let owner_wrapped_key_b64 = headers
        .get("x-arca-owner-wrapped-key")
        .ok_or_else(|| anyhow!("Header upload manquant: X-Arca-Owner-Wrapped-Key"))?
        .to_str()
        .context("Header upload invalide: X-Arca-Owner-Wrapped-Key")?
        .to_string();

    Ok((url_decode_path(encoded_path)?, owner_wrapped_key_b64))
}

fn url_decode_path(path: &str) -> Result<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(anyhow!("Chemin upload encode invalide"));
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .context("Chemin upload encode invalide")?;
            let value =
                u8::from_str_radix(hex, 16).map_err(|_| anyhow!("Chemin upload encode invalide"))?;
            decoded.push(value);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).context("Chemin upload non UTF-8")
}

fn share_file(connection: &mut Connection, user_id: i64, payload: ShareRequest) -> Result<()> {
    let path = payload.path;
    let target_username = payload.target_username;
    let wrapped_key_b64 = payload
        .wrapped_key_b64
        .ok_or_else(|| anyhow!("Cle partagee manquante"))?;
    let file_id = connection
        .query_row(
            "SELECT id FROM files WHERE owner_id = ?1 AND path = ?2",
            params![user_id, path],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Fichier introuvable ou non possede"))?;

    let target_user_id = connection
        .query_row(
            "SELECT id FROM users WHERE username = ?1",
            params![target_username],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Utilisateur cible introuvable"))?;

    connection.execute(
        "INSERT INTO shares (file_id, target_user_id, wrapped_key_b64) VALUES (?1, ?2, ?3)
         ON CONFLICT(file_id, target_user_id) DO UPDATE SET wrapped_key_b64 = excluded.wrapped_key_b64",
        params![file_id, target_user_id, wrapped_key_b64],
    )?;
    append_file_event(connection, user_id, &path, user_id, "share", Some(&target_username))?;
    Ok(())
}

fn unshare_file(connection: &mut Connection, user_id: i64, payload: ShareRequest) -> Result<()> {
    let path = payload.path;
    let target_username = payload.target_username;
    let file_id = connection
        .query_row(
            "SELECT id FROM files WHERE owner_id = ?1 AND path = ?2",
            params![user_id, path],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Fichier introuvable ou non possede"))?;

    let target_user_id = connection
        .query_row(
            "SELECT id FROM users WHERE username = ?1",
            params![target_username],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Utilisateur cible introuvable"))?;

    let changed = connection.execute(
        "DELETE FROM shares WHERE file_id = ?1 AND target_user_id = ?2",
        params![file_id, target_user_id],
    )?;

    if changed == 0 {
        return Err(anyhow!("Partage introuvable"));
    }

    append_file_event(
        connection,
        user_id,
        &path,
        user_id,
        "unshare",
        Some(&target_username),
    )?;
    Ok(())
}

fn delete_owned_file(connection: &mut Connection, user_id: i64, path: &str) -> Result<()> {
    let file_id = connection
        .query_row(
            "SELECT id FROM files WHERE owner_id = ?1 AND path = ?2",
            params![user_id, path],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| anyhow!("Fichier introuvable ou non possede"))?;

    let transaction = connection.transaction()?;
    transaction.execute("DELETE FROM shares WHERE file_id = ?1", params![file_id])?;
    transaction.execute("DELETE FROM files WHERE id = ?1", params![file_id])?;
    append_file_event(&transaction, user_id, path, user_id, "delete", None)?;
    transaction.commit()?;
    Ok(())
}

fn append_file_event(
    connection: &Connection,
    owner_id: i64,
    path: &str,
    actor_user_id: i64,
    action: &str,
    target_username: Option<&str>,
) -> Result<()> {
    connection.execute(
        "INSERT INTO file_events (owner_id, path, actor_user_id, action, target_username)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![owner_id, path, actor_user_id, action, target_username],
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

fn fetch_file_for_user(
    connection: &Connection,
    user_id: i64,
    path: &str,
) -> Result<DownloadResponse> {
    let mut statement = connection.prepare(
        r#"
        SELECT
            f.path,
            u.username,
            CASE WHEN f.owner_id = ?1 THEN 0 ELSE 1 END,
            f.content,
            CASE
                WHEN f.owner_id = ?1 THEN f.owner_wrapped_key_b64
                ELSE s.wrapped_key_b64
            END
        FROM files f
        JOIN users u ON u.id = f.owner_id
        LEFT JOIN shares s ON s.file_id = f.id AND s.target_user_id = ?1
        WHERE (f.owner_id = ?1 OR s.target_user_id = ?1) AND f.path = ?2
        LIMIT 1
        "#,
    )?;

    let file = statement
        .query_row(params![user_id, path], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? == 1,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .optional()?
        .ok_or_else(|| anyhow!("Fichier introuvable ou acces refuse"))?;

    let wrapped_key_b64 = file.4.ok_or_else(|| {
        if file.2 {
            anyhow!(
                "Partage legacy incompatible: la cle partagee est absente pour ce fichier. Le proprietaire doit repartager ce fichier."
            )
        } else {
            anyhow!(
                "Fichier incompatible: la cle proprietaire est absente. Le proprietaire doit reuploader ce fichier."
            )
        }
    })?;

    Ok(DownloadResponse {
        path: file.0,
        owner: file.1,
        shared: file.2,
        content_base64: STANDARD.encode(file.3),
        wrapped_key_b64,
    })
}

fn list_history(connection: &Connection, user_id: i64, path: Option<&str>) -> Result<Vec<HistoryEvent>> {
    let username = connection.query_row(
        "SELECT username FROM users WHERE id = ?1",
        params![user_id],
        |row| row.get::<_, String>(0),
    )?;

    let mut statement = connection.prepare(
        r#"
        SELECT
            e.path,
            owner.username,
            actor.username,
            e.action,
            e.target_username,
            e.created_at
        FROM file_events e
        JOIN users owner ON owner.id = e.owner_id
        JOIN users actor ON actor.id = e.actor_user_id
        LEFT JOIN files f ON f.owner_id = e.owner_id AND f.path = e.path
        LEFT JOIN shares s ON s.file_id = f.id AND s.target_user_id = ?1
        WHERE (
            e.owner_id = ?1
            OR e.actor_user_id = ?1
            OR e.target_username = ?2
            OR s.target_user_id = ?1
        )
          AND (?3 IS NULL OR e.path = ?3)
        ORDER BY e.id DESC
        LIMIT 200
        "#,
    )?;

    let rows = statement.query_map(params![user_id, username, path], |row| {
        Ok(HistoryEvent {
            path: row.get(0)?,
            owner: row.get(1)?,
            actor: row.get(2)?,
            action: row.get(3)?,
            target_username: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

fn get_user_public_key(connection: &Connection, username: &str) -> Result<PublicKeyResponse> {
    connection
        .query_row(
            "SELECT public_key_b64 FROM users WHERE username = ?1",
            params![username],
            |row| {
                let public_key_b64: Option<String> = row.get(0)?;
                Ok(PublicKeyResponse {
                    username: username.to_string(),
                    public_key_b64: public_key_b64.unwrap_or_default(),
                })
            },
        )
        .optional()?
        .ok_or_else(|| anyhow!("Utilisateur cible introuvable"))
        .and_then(|payload| {
            if payload.public_key_b64.is_empty() {
                Err(anyhow!(
                    "L'utilisateur cible doit se connecter au moins une fois pour publier sa cle publique"
                ))
            } else {
                Ok(payload)
            }
        })
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;

    for row in rows {
        if row? == column {
            return Ok(());
        }
    }

    connection.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn map_error(error: anyhow::Error) -> (StatusCode, String) {
    let message = error.to_string();
    if message.contains("UNIQUE constraint failed") {
        err(StatusCode::CONFLICT, "Utilisateur deja existant")
    } else if message.contains("Mot de passe invalide") || message.contains("Utilisateur inconnu") {
        err(StatusCode::UNAUTHORIZED, &message)
    } else if message.contains("introuvable")
        || message.contains("non possede")
        || message.contains("acces refuse")
        || message.contains("Partage introuvable")
    {
        err(StatusCode::NOT_FOUND, &message)
    } else if message.contains("obligatoire")
        || message.contains("invalide")
        || message.contains("Header upload manquant")
    {
        err(StatusCode::BAD_REQUEST, &message)
    } else if message.contains("legacy incompatible")
        || message.contains("cle partagee est absente")
        || message.contains("cle proprietaire est absente")
    {
        err(StatusCode::CONFLICT, &message)
    } else {
        err(StatusCode::INTERNAL_SERVER_ERROR, &message)
    }
}

fn err(status: StatusCode, message: &str) -> (StatusCode, String) {
    (status, message.to_string())
}
