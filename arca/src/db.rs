use std::collections::HashMap;
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

#[derive(Debug, Clone)]
pub struct PendingOp {
    pub id: i64,
    pub op_type: String,
    pub target_path: Option<String>,
    pub payload: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileSummary {
    pub upserts: usize,
    pub deletes: usize,
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

pub fn reset_local_state(connection: &Connection) -> Result<()> {
    connection.execute("DELETE FROM file_index", [])?;
    connection.execute("DELETE FROM pending_ops", [])?;
    connection.execute("DELETE FROM devices", [])?;
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

pub fn reconcile_file_index(
    connection: &Connection,
    records: &[FileRecord],
) -> Result<ReconcileSummary> {
    let existing = list_indexed_files(connection)?
        .into_iter()
        .map(|record| (record.relative_path.clone(), record))
        .collect::<HashMap<_, _>>();
    let scanned = records
        .iter()
        .cloned()
        .map(|record| (record.relative_path.clone(), record))
        .collect::<HashMap<_, _>>();

    let mut summary = ReconcileSummary::default();

    for record in records {
        let changed = match existing.get(&record.relative_path) {
            Some(previous) => {
                previous.content_hash != record.content_hash
                    || previous.size_bytes != record.size_bytes
            }
            None => true,
        };

        if changed {
            upsert_file(connection, record)?;
            summary.upserts += 1;
        }
    }

    for path in existing.keys() {
        if !scanned.contains_key(path) {
            delete_file(connection, path)?;
            summary.deletes += 1;
        }
    }

    Ok(summary)
}

pub fn upsert_file(connection: &Connection, record: &FileRecord) -> Result<i64> {
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

pub fn upsert_file_index_only(connection: &Connection, record: &FileRecord) -> Result<()> {
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
    Ok(())
}

pub fn delete_file(connection: &Connection, relative_path: &str) -> Result<i64> {
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
) -> Result<i64> {
    connection.execute(
        "INSERT INTO pending_ops (op_type, target_path, payload) VALUES (?1, ?2, ?3)",
        params![op_type, target_path, payload],
    )?;
    Ok(connection.last_insert_rowid())
}

pub fn list_pending_ops(connection: &Connection, limit: usize) -> Result<Vec<PendingOp>> {
    let mut statement = connection.prepare(
        "SELECT id, op_type, target_path, payload
         FROM pending_ops
         ORDER BY id ASC
         LIMIT ?1",
    )?;
    let rows = statement.query_map(params![limit as i64], |row| {
        Ok(PendingOp {
            id: row.get(0)?,
            op_type: row.get(1)?,
            target_path: row.get(2)?,
            payload: row.get(3)?,
        })
    })?;

    let mut ops = Vec::new();
    for row in rows {
        ops.push(row?);
    }
    Ok(ops)
}

pub fn delete_pending_op(connection: &Connection, id: i64) -> Result<()> {
    connection.execute("DELETE FROM pending_ops WHERE id = ?1", params![id])?;
    Ok(())
}

pub fn delete_pending_ops_for_path(connection: &Connection, path: &str) -> Result<()> {
    connection.execute(
        "DELETE FROM pending_ops WHERE target_path = ?1",
        params![path],
    )?;
    Ok(())
}

fn list_indexed_files(connection: &Connection) -> Result<Vec<FileRecord>> {
    let mut statement = connection
        .prepare("SELECT path, content_hash, size_bytes FROM file_index ORDER BY path")?;
    let rows = statement.query_map([], |row| {
        Ok(FileRecord {
            relative_path: row.get(0)?,
            content_hash: row.get(1)?,
            size_bytes: row.get::<_, i64>(2)? as u64,
        })
    })?;

    let mut files = Vec::new();
    for row in rows {
        files.push(row?);
    }
    Ok(files)
}
