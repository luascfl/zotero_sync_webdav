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
- `zotero_sync_webdav.py` depends on `pyzotero`, `tqdm`, the Python standard library, the WebDAV mount, local Zotero storage, the embedded autostart shell backend, and the merged Obsidian workflow helpers.

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
- Obsidian vault: Lives natively at the Google Drive target root (`zoterodb`). No separate physical mirroring step is necessary since the script enforces Zotero collections directly onto the drive structure, which Obsidian reads. Synchronization of the vault to Google Drive is handled by Obsidian's **Remotely Save** plugin, abstracting away the need for OS-level sync mechanisms for the Markdown side.

## Two-way sync between Drive folders and Zotero collections
The identity of a collection is its Zotero key. The ledger `.zotero_folders.json` in the vault root (key to relative path, written atomically at the end of a clean run) is the memory between runs. Each run compares ledger, Zotero and Drive and mirrors a structural change on the side that did not change, instead of creating a collection, moving every PDF and deleting the old collection.

| Event since the last run | Action |
|---|---|
| Collection renamed or moved in Zotero | The Drive directory is renamed in one operation and the hash cache is re-keyed; an existing non-empty destination is a reported conflict and nothing moves |
| Folder renamed on the Drive or in Obsidian | The Zotero collection is renamed in place (same key, items and subcollections kept), only if exactly one unmapped sibling folder shares at least 50% of the PDFs on both sides |
| Collection deleted in Zotero | Only an empty Drive directory is removed; PDFs are never deleted |
| Folder deleted on the Drive | Only an empty, childless collection is deleted; a collection with items gets its folder back |

Order inside `run_sync_mode`: `reconcile_collection_folder_renames` (ledger driven renames) runs before `ensure_drive_content_collections` and `reconcile_drive_collection_paths`, which records old to new collection evidence; afterwards `prune_superseded_collections` runs `merge_drive_renamed_collections` and `cleanup_empty_duplicate_zotero_collections`, and `write_folder_ledger_if_clean` closes the run.

Safeguards: no drive-driven action when the ledger is non-empty but none of its folders exist (unmounted drive); a ledger older than 14 days (`ZOTERO_FOLDER_LEDGER_MAX_AGE_DAYS`) is only renewed; at most 10 collection deletions per run; each rename or deletion is appended to `~/.cache/zotero_sync_webdav/duplicate_actions.jsonl`; `ZOTERO_FOLDER_SYNC_DRY_RUN=1` logs the plan and changes nothing, including the ledger.

## Data entities
- Attachment item: Zotero API item with `key`, `data.filename`, `data.path`, `data.dateAdded`, and optional `data.parentItem`.
- WebDAV PDF: local file path, basename, mtime, size, and SHA-256 hash.
- Hash cache entry: normalized file path, stat metadata, and hash.
- Duplicate group: normalized filename key plus grouped Zotero attachment keys.

## Observability and failure modes
The current scripts primarily use console output and Python logging. The main sync writes a daily log under `~/.cache/zotero_sync_webdav/logs`. Known failure boundaries include missing credentials, missing WebDAV mount, Zotero API failures, permission errors, failed copies, failed renames, and malformed API responses.
