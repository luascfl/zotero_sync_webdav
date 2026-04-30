---
type: doc
name: data-flow
description: How data moves through the system and external integrations
category: data-flow
generated: 2026-04-30
status: filled
---

# Data flow and integrations

The main data path starts with local configuration, then combines Zotero attachment metadata with local WebDAV PDFs and local Zotero storage files. The script uses normalized names and SHA-256 hashes to decide whether each PDF is already synced, updated, renamed, or new.

## Module dependencies
- `zotero_sync_webdav.py` depends on `pyzotero`, `tqdm`, the Python standard library, the WebDAV mount, and local Zotero storage.
- `zotero_diagnostico.py` depends on `pyzotero`, the WebDAV folder, and duplicate/missing-file comparison helpers.
- `zotero_remove_duplicatas.py` depends on `pyzotero` and Zotero attachment metadata.
- `zotero_mirror_collections_to_obsidian.py` depends on `pyzotero` and a local target directory for Obsidian.

## High-level main sync flow
1. Load environment variables from `.env` or the configured environment file.
2. Connect to Zotero through `pyzotero.Zotero`.
3. Page through all Zotero attachments and build normalized filename indexes.
4. Build a local storage hash index from `~/Zotero/storage`.
5. Scan PDFs in `ZOTERO_SYNC_TARGET_FOLDER`.
6. For each PDF:
   - If name and hash match, skip as already synced.
   - If name exists but hash differs, update local storage from WebDAV.
   - If name differs but hash matches local storage, reconcile the filename based on mtime.
   - If neither name nor hash exists, add the file to Zotero and copy it to local storage.
   - If Zotero has the name but local storage is missing, recreate the local copy.
7. Save hash cache and emit final stats, logs, and optional notification.

## External integrations
- Zotero API: attachment listing, attachment creation, item lookup, item update, and deletion in the cleanup script.
- Mounted WebDAV directory: local filesystem interface to the sync source.
- Local Zotero storage: local copy and hash comparison target.
- Obsidian vault: optional folder tree target for collection mirroring.

## Data entities
- Attachment item: Zotero API item with `key`, `data.filename`, `data.path`, `data.dateAdded`, and optional `data.parentItem`.
- WebDAV PDF: local file path, basename, mtime, size, and SHA-256 hash.
- Hash cache entry: normalized file path, stat metadata, and hash.
- Duplicate group: normalized filename key plus grouped Zotero attachment keys.

## Observability and failure modes
The current scripts primarily use console output and Python logging. The main sync writes a daily log under `~/.cache/zotero_sync_webdav/logs`. Known failure boundaries include missing credentials, missing WebDAV mount, Zotero API failures, permission errors, failed copies, failed renames, and malformed API responses.
