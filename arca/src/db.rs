use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug)]
pub struct StatusSnapshot {
    pub schema_version: i64,
    pub known_devices: i64,
    pub file_indexed: i64,
    pub pending_ops: i64,
}

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub relative_path: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

pub fn connect(database_path: &Path) -> Result<Connection> {
    Connection::open(database_path)
        .with_context(|| format!("Ouverture SQLite impossible: {}", database_path.display()))
}

pub fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS file_index (
            path TEXT PRIMARY KEY,
            content_hash TEXT,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS pending_ops (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            op_type TEXT NOT NULL,
            target_path TEXT,
            payload TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;

    connection.execute(
        "INSERT OR IGNORE INTO meta (key, value) VALUES (?1, ?2)",
        params!["schema_version", "1"],
    )?;

    Ok(())
}

pub fn status(connection: &Connection) -> Result<StatusSnapshot> {
    let schema_version = connection
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params!["schema_version"],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| "0".to_string())
        .parse::<i64>()
        .context("Version de schema invalide")?;

    let known_devices = count(connection, "SELECT COUNT(*) FROM devices")?;
    let file_indexed = count(connection, "SELECT COUNT(*) FROM file_index")?;
    let pending_ops = count(connection, "SELECT COUNT(*) FROM pending_ops")?;

    Ok(StatusSnapshot {
        schema_version,
        known_devices,
        file_indexed,
        pending_ops,
    })
}

fn count(connection: &Connection, query: &str) -> Result<i64> {
    let value = connection.query_row(query, [], |row| row.get(0))?;
    Ok(value)
}

pub fn replace_file_index(connection: &mut Connection, records: &[FileRecord]) -> Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute("DELETE FROM file_index", [])?;

    {
        let mut statement = transaction.prepare(
            "INSERT INTO file_index (path, content_hash, size_bytes, updated_at)
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)",
        )?;

        for record in records {
            statement.execute(params![
                record.relative_path,
                record.content_hash,
                record.size_bytes as i64,
            ])?;
        }
    }

    enqueue_pending_op(
        &transaction,
        "scan_complete",
        None,
        Some(format!("indexed={}", records.len())),
    )?;

    transaction.commit()?;
    Ok(())
}

pub fn upsert_file(connection: &Connection, record: &FileRecord) -> Result<()> {
    connection.execute(
        "INSERT INTO file_index (path, content_hash, size_bytes, updated_at)
         VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
         ON CONFLICT(path) DO UPDATE SET
             content_hash = excluded.content_hash,
             size_bytes = excluded.size_bytes,
             updated_at = CURRENT_TIMESTAMP",
        params![
            record.relative_path,
            record.content_hash,
            record.size_bytes as i64,
        ],
    )?;

    enqueue_pending_op(
        connection,
        "file_upsert",
        Some(record.relative_path.clone()),
        Some(record.content_hash.clone()),
    )
}

pub fn delete_file(connection: &Connection, relative_path: &str) -> Result<()> {
    connection.execute(
        "DELETE FROM file_index WHERE path = ?1",
        params![relative_path],
    )?;
    enqueue_pending_op(
        connection,
        "file_delete",
        Some(relative_path.to_string()),
        None,
    )
}

fn enqueue_pending_op(
    connection: &Connection,
    op_type: &str,
    target_path: Option<String>,
    payload: Option<String>,
) -> Result<()> {
    connection.execute(
        "INSERT INTO pending_ops (op_type, target_path, payload) VALUES (?1, ?2, ?3)",
        params![op_type, target_path, payload],
    )?;
    Ok(())
}
