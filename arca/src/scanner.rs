use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::{DirEntry, WalkDir};

use crate::db::FileRecord;

const IGNORED_DIRS: &[&str] = &[".git", "target", ".DS_Store"];

pub fn scan_workspace(root: &Path) -> Result<Vec<FileRecord>> {
    let mut records = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| should_traverse(root, entry))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let absolute_path = entry.path();
        let relative_path = normalize_relative(root, absolute_path)?;
        let (content_hash, size_bytes) = hash_file(absolute_path)?;

        records.push(FileRecord {
            relative_path,
            content_hash,
            size_bytes,
        });
    }

    records.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(records)
}

pub fn file_record_from_path(root: &Path, absolute_path: &Path) -> Result<FileRecord> {
    let relative_path = normalize_relative(root, absolute_path)?;
    let (content_hash, size_bytes) = hash_file(absolute_path)?;

    Ok(FileRecord {
        relative_path,
        content_hash,
        size_bytes,
    })
}

pub fn normalize_relative(root: &Path, absolute_path: &Path) -> Result<String> {
    let relative = absolute_path
        .strip_prefix(root)
        .with_context(|| format!("Chemin hors workspace: {}", absolute_path.display()))?;
    Ok(path_to_unix(relative))
}

pub fn should_ignore_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return true;
    };

    relative
        .components()
        .any(|component| IGNORED_DIRS.contains(&component.as_os_str().to_string_lossy().as_ref()))
}

fn should_traverse(root: &Path, entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }

    !should_ignore_path(root, entry.path())
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let file =
        File::open(path).with_context(|| format!("Ouverture impossible: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .with_context(|| format!("Lecture impossible: {}", path.display()))?;
        if read == 0 {
            break;
        }
        size += read as u64;
        hasher.update(&buffer[..read]);
    }

    Ok((hasher.finalize().to_hex().to_string(), size))
}

fn path_to_unix(path: &Path) -> String {
    let path_buf: PathBuf = path.into();
    path_buf.to_string_lossy().replace('\\', "/")
}
