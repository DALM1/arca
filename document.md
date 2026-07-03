# Arca CLI Commands

This document lists the current Arca CLI commands and shows how to use them.

## Overview

Arca is a CLI-first encrypted file sync prototype.

Current capabilities include:

- workspace initialization
- account registration and login
- local indexing and watch mode
- encrypted upload and download
- file sharing and access revocation
- remote file deletion
- bulk restore of accessible remote files

## General Syntax

Run commands from the project root with:

```bash
cargo run -p arca -- <command> [options]
```

If you already built the binary:

```bash
./target/debug/arca <command> [options]
```

To install the CLI in your `PATH` and call it directly as `arca`:

```bash
cargo install --path arca --locked
```

Then you can run commands like:

```bash
arca upload ./file.txt
```

Server note:

- the server accepts upload bodies up to `512 MiB` by default
- override with `ARCA_SERVER_MAX_BODY_MB=<n>` before starting `arca-server`
- uploads now send the encrypted blob as raw binary HTTP data, which avoids the old
  `base64 + JSON` overhead
- encrypted uploads still add some metadata and encryption overhead, so the payload
  is not always exactly the same size as the source file

Useful environment overrides:

- `ARCA_CONFIG_DIR`: override the local config/session directory
- `ARCA_DATA_DIR`: override the local SQLite state directory

These overrides are useful for isolated tests and for environments where the
default application directories are restricted.

## Commands

### `init`

Initialize the local workspace and SQLite state.

```bash
cargo run -p arca -- init --workspace-name demo --path .
```

Options:

- `--workspace-name <name>`: logical workspace name
- `--path <path>`: local root directory to manage
- `--force`: overwrite existing local configuration

### `register`

Create a user account on the remote server.

```bash
cargo run -p arca -- register \
  --server-url http://127.0.0.1:8787 \
  --username alice \
  --password alicepass123
```

Options:

- `--server-url <url>`: remote API base URL
- `--username <name>`: account name
- `--password <password>`: account password

### `login`

Authenticate and create a local session.

```bash
cargo run -p arca -- login \
  --server-url http://127.0.0.1:8787 \
  --username alice \
  --password alicepass123
```

This command also derives the local E2EE identity material used for encrypted
upload, pull, and sharing.

### `status`

Display local workspace status.

```bash
cargo run -p arca -- status
```

Shows:

- workspace metadata
- local device id
- SQLite schema version
- indexed file count
- pending queue size
- current session state

### `watch`

Scan or watch the local workspace.

Single scan:

```bash
cargo run -p arca -- watch --once
```

Continuous watch:

```bash
cargo run -p arca -- watch
```

Continuous watch with automatic upload of created or modified files:

```bash
cargo run -p arca -- watch --sync
```

Notes:

- `--sync` requires a valid local session from `login`
- current sync mode uploads created and modified files
- local deletions are also propagated to the remote server when possible
- if the remote file is already absent, the local delete operation is purged

### `push`

Replay the local SQLite queue and upload pending file changes without starting a
watch process.

```bash
cargo run -p arca -- push
```

Behavior:

- scans the workspace
- reconciles the current state with the local SQLite index
- uploads pending file creations and modifications
- propagates pending file deletions to the remote server
- purges delete operations if the remote file is already absent

### `upload`

Encrypt a local file and upload it to the remote server.

```bash
arca upload /tmp/report.txt \
  --remote-path docs/report.txt
```

Secret mode with an extra password prompt:

```bash
arca upload -s /tmp/report.txt --remote-path docs/report.txt
```

Options:

- `<path>`: local file to upload
- `-s`, `--secret`: prompt for an extra secret password before upload
- `--remote-path <remote-path>`: logical remote path

If `--remote-path` is omitted, Arca uses the local filename.

Advanced upload progress:

- shows a `Reading` progress bar while loading the local file
- applies strong `zstd` compression when it makes the payload smaller
- sends the encrypted payload as raw binary instead of JSON/base64 to reduce transfer size
- shows an `Encrypting` step while building the E2EE payload
- shows an `Encoding` step while preparing the upload metadata
- shows an `Uploading` progress bar with percentage, transfer rate, and ETA during the HTTP transfer
- if `-s` is enabled, Arca prompts for a secret password and protects the file with an extra client-side layer before the normal E2EE upload

Notes:

- `upload` requires an existing account from `register` and a valid local session from `login`
- already compressed formats such as `gif`, `jpg`, `png`, `mp4`, or `zip` may shrink very little
- `-s` secret protection requires the same password again when downloading or restoring the file

Compatibility note:

- `--path <local-file>` is still accepted for older usage patterns

### `list`

List the remote files accessible to the current user.

```bash
cargo run -p arca -- list
```

The output shows:

- remote path
- owner username
- access mode (`owned` or `shared`)
- stored size

### `pull`

Download and decrypt a remote file locally.

```bash
arca pull docs/report.txt /tmp/report.txt
```

Options:

- `<remote-path>`: remote logical path
- `<output>`: destination path on disk

Behavior:

- shows a visual download loader with percentage, transfer rate, and ETA when the HTTP body size is known
- falls back to a spinner-style loader with throughput and elapsed time when the server does not expose a content length
- prompts for the extra secret password automatically when downloading a file uploaded with `-s`

Compatibility note:

- `--remote-path <remote-path>` and `--output <local-path>` are still accepted
  for older usage patterns

### `share`

Share a remote file with another user.

```bash
arca share docs/report.txt bob
```

This command keeps end-to-end encryption by re-wrapping the file key for the
recipient.

Important:

- the recipient must have logged in at least once so their public key is known
  by the server

Compatibility note:

- `--path` and `--with-user` are still accepted for older usage patterns

### `unshare`

Revoke access previously granted to another user.

```bash
arca unshare docs/report.txt bob
```

Compatibility note:

- `--path` and `--with-user` are still accepted for older usage patterns

### `delete`

Delete a remote file that you own.

```bash
arca delete docs/report.txt
```

Compatibility note:

- `--remote-path` is still accepted for older usage patterns

### `nuke`

Destroy local state or request remote destruction in the future.

Local wipe:

```bash
cargo run -p arca -- nuke --local --yes
```

Notes:

- `--yes` is required
- remote nuke is still not implemented

### `diff`

Compare the current local workspace against the accessible remote file set.

```bash
cargo run -p arca -- diff
```

Behavior:

- scans the current local workspace
- loads the local SQLite pending queue
- compares local paths with accessible remote paths
- reports `pending upload`, `pending delete`, `local only`, and `remote only`
- shows paths present on both sides without pending operations as a summary count

Important:

- `diff` requires both `init` and `login`
- this MVP compares path presence and local pending operations, not exact file
  content equality
- because the server stores encrypted blobs, this command does not yet prove that
  two files with the same path have identical plaintext content

### `history`

Show recent remote file events visible to the current user.

```bash
cargo run -p arca -- history
```

Filter one remote path:

```bash
cargo run -p arca -- history --path docs/report.txt
```

Behavior:

- shows recent upload, update, share, unshare, and delete events
- includes the owner, actor, timestamp, and optional share target
- reads remote server history, not local SQLite pending operations
- currently returns the most recent server-side events only

### `restore`

Restore every remote file accessible to the current user into a local directory.

```bash
cargo run -p arca -- restore --target-dir /tmp/restore-output
```

Options:

- `--target-dir <path>`: restore destination directory

Behavior:

- downloads and decrypts all accessible remote files
- shows a visual download loader with percentage for each file when possible
- prompts for the extra secret password on secret-protected files
- restores both owned and explicitly shared files
- recreates remote directory structure under the target directory
- updates the local SQLite index only when restoring into the configured
  workspace root
- skips incompatible files one by one, then returns a partial-failure error at
  the end if at least one file could not be restored

Important:

- `restore` requires a valid local session from `login`
- if `--target-dir` is omitted, Arca restores into the configured workspace root
- legacy shared files missing a wrapped recipient key must be re-shared by the
  owner before they can be restored

## Typical Flow

### 1. Initialize

```bash
cargo run -p arca -- init --workspace-name demo --path .
```

### 2. Register and login

```bash
cargo run -p arca -- register --server-url http://127.0.0.1:8787 --username alice --password alicepass123
cargo run -p arca -- login --server-url http://127.0.0.1:8787 --username alice --password alicepass123
```

### 3. Upload an encrypted file

```bash
arca upload /tmp/file.txt --remote-path secure/file.txt
```

### 4. List and pull

```bash
cargo run -p arca -- list
arca pull secure/file.txt /tmp/file-copy.txt
```

### 5. Share and revoke

```bash
arca share secure/file.txt bob
arca unshare secure/file.txt bob
```

### 6. Restore all accessible files

```bash
cargo run -p arca -- restore --target-dir /tmp/restore-output
```

## Current Limitations

- remote panic/nuke is not implemented
- full real-time sync with remote replay is still under development
- legacy shares created without a recipient wrapped key cannot be decrypted
  until the owner shares the file again with a current client
- remote history is an MVP event log, not a full versioned restore system yet
- `diff` is an MVP path/pending-queue comparison, not a cryptographic content diff
