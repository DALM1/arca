use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::Connection;

use crate::config::AuthSession;
use crate::db;
use crate::scanner;
use crate::syncer;

pub fn run(
    connection: &mut Connection,
    workspace_root: &Path,
    once: bool,
    session: Option<&AuthSession>,
) -> Result<()> {
    initial_scan(connection, workspace_root, session)?;

    if once {
        println!("Scan unique termine");
        return Ok(());
    }

    let (sender, receiver) = channel();
    let mut watcher = RecommendedWatcher::new(sender, notify::Config::default())
        .context("Creation du watcher impossible")?;

    watcher
        .watch(workspace_root, RecursiveMode::Recursive)
        .with_context(|| format!("Surveillance impossible: {}", workspace_root.display()))?;

    let running = Arc::new(AtomicBool::new(true));
    let signal = Arc::clone(&running);
    ctrlc::set_handler(move || {
        signal.store(false, Ordering::SeqCst);
    })
    .context("Installation du handler Ctrl-C impossible")?;

    println!("Watch actif sur {}", workspace_root.display());
    println!("Ctrl-C pour arreter");

    while running.load(Ordering::SeqCst) {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(event)) => handle_event(connection, workspace_root, event, session)?,
            Ok(Err(error)) => eprintln!("Watcher error: {error}"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(error) => return Err(error).context("Canal watcher interrompu"),
        }
    }

    println!("Watch arrete");
    Ok(())
}

fn initial_scan(
    connection: &mut Connection,
    workspace_root: &Path,
    session: Option<&AuthSession>,
) -> Result<()> {
    let records = scanner::scan_workspace(workspace_root)?;
    let summary = db::reconcile_file_index(connection, &records)?;
    println!(
        "Workspace scanne: {} fichiers indexes depuis {} ({} upserts, {} deletes)",
        records.len(),
        workspace_root.display(),
        summary.upserts,
        summary.deletes
    );
    if let Some(session) = session {
        syncer::sync_pending_ops(connection, workspace_root, session)?;
    }
    Ok(())
}

fn handle_event(
    connection: &Connection,
    workspace_root: &Path,
    event: Event,
    session: Option<&AuthSession>,
) -> Result<()> {
    for path in event.paths {
        if scanner::should_ignore_path(workspace_root, &path) {
            continue;
        }

        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                if path.is_file() {
                    let record = scanner::file_record_from_path(workspace_root, &path)?;
                    let op_id = db::upsert_file(connection, &record)?;
                    println!("Indexed {}", record.relative_path);
                    if let Some(session) = session {
                        if let Err(error) = syncer::upload_indexed_file(
                            session,
                            workspace_root,
                            &record.relative_path,
                        ) {
                            eprintln!("Sync error for {}: {error}", record.relative_path);
                        } else {
                            db::delete_pending_op(connection, op_id)?;
                            println!("Synced {}", record.relative_path);
                        }
                    }
                }
            }
            EventKind::Remove(_) => {
                let relative = scanner::normalize_relative(workspace_root, &path)?;
                let _ = db::delete_file(connection, &relative)?;
                println!("Removed {}", relative);
            }
            _ => {}
        }
    }

    Ok(())
}
