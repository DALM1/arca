use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::config::AuthSession;
use crate::crypto;
use crate::db;

#[derive(Debug, Default, Clone, Copy)]
pub struct SyncSummary {
    pub uploads: usize,
    pub deletes: usize,
    pub already_absent_deletes: usize,
    pub purged: usize,
}

pub fn sync_pending_ops(
    connection: &Connection,
    workspace_root: &Path,
    session: &AuthSession,
) -> Result<SyncSummary> {
    let pending = db::list_pending_ops(connection, 10_000)?;
    let mut summary = SyncSummary::default();

    for op in pending {
        match op.op_type.as_str() {
            "file_upsert" => {
                if let Some(relative_path) = op.target_path.as_deref() {
                    upload_indexed_file(session, workspace_root, relative_path)?;
                    db::delete_pending_op(connection, op.id)?;
                    println!("Synced {}", relative_path);
                    summary.uploads += 1;
                    summary.purged += 1;
                }
            }
            "scan_complete" => {
                db::delete_pending_op(connection, op.id)?;
                summary.purged += 1;
            }
            "file_delete" => {
                if let Some(relative_path) = op.target_path.as_deref() {
                    match crate::remote::delete_file(session, relative_path.to_string()) {
                        Ok(()) => {
                            db::delete_pending_op(connection, op.id)?;
                            println!("Deleted remote {}", relative_path);
                            summary.deletes += 1;
                            summary.purged += 1;
                        }
                        Err(error) if is_not_found_error(&error) => {
                            db::delete_pending_op(connection, op.id)?;
                            eprintln!(
                                "Remote already absent or inaccessible for {}, purging local delete op",
                                relative_path
                            );
                            summary.already_absent_deletes += 1;
                            summary.purged += 1;
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            _ => {
                let payload = op.payload.as_deref().unwrap_or_default();
                eprintln!("Unknown pending op `{}` {}", op.op_type, payload);
            }
        }
    }

    Ok(summary)
}

pub fn upload_indexed_file(
    session: &AuthSession,
    workspace_root: &Path,
    relative_path: &str,
) -> Result<()> {
    let local_path = workspace_root.join(relative_path);
    let plaintext = std::fs::read(&local_path)
        .with_context(|| format!("Lecture impossible: {}", local_path.display()))?;
    let encrypted =
        crypto::encrypt_for_upload(&session.e2ee_public_key_b64, relative_path, &plaintext)?;
    crate::remote::upload_file(
        session,
        encrypted.blob,
        relative_path.to_string(),
        encrypted.owner_wrapped_key_b64,
    )
}

fn is_not_found_error(error: &anyhow::Error) -> bool {
    error.to_string().contains("Erreur serveur (404)")
}
