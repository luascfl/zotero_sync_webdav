---
type: doc
name: architecture
description: System architecture, layers, patterns, and design decisions
category: architecture
generated: 2026-04-30
status: filled
---

# Architecture

The repository is a script-oriented automation codebase. There is no server, UI, database, package module, or separate product boundary. Each script is an executable workflow over local files and the Zotero API.

## System architecture overview
The primary topology is a local automation script that reads configuration from environment files, scans a mounted WebDAV folder, indexes Zotero attachment metadata, compares names and hashes, then mutates Zotero and local files when needed. Control stays in one process and pivots between filesystem operations, cache operations, and Zotero API calls.

## Architectural layers
- Configuration: `.env`, `~/.config/zotero_sync_webdav/zotero_sync.env`, and path resolution helpers.
- External API access: `pyzotero.Zotero` calls for attachment discovery, creation, deletion, metadata updates, diagnostics, and duplicate cleanup.
- Filesystem scanning: WebDAV PDF discovery, local Zotero storage discovery, rename, and copy operations.
- Hash/cache layer: SHA-256 hashes stored under `~/.cache/zotero_sync_webdav/hash_cache.json`.
- Reporting layer: console output, logging, daily log file, optional desktop notification.
- Unified operations layer: the main script now exposes sync, diagnostics, duplicate cleanup, and autostart setup from one CLI.
- Support utilities: unified collection routing, removing the need for a separate physical Obsidian mirror since `zoterodb` serves as the primary vault.

## Core Architecture Paradigm: Unified Vault
The Google Drive directory (`zoterodb`) serves concurrently as the Zotero physical storage target and the primary Obsidian Vault.
- The script enforces Zotero's collection structure onto the Drive directory, organizing PDFs into collection folders.
- Obsidian reads this identical folder structure natively.
- Zotero exclusively manages the `.pdf` attachments. Obsidian manages the `.md` notes. The script strictly filters for `.pdf` files, actively ignoring Markdown notes and the `.obsidian` configuration folder, preventing pollution of the Zotero bibliographic database.

## Detected design patterns
| Pattern | Confidence | Locations | Description |
| --- | ---: | --- | --- |
| Script workflow | High | `main()` in each Python file | Each file owns a complete command-line workflow. |
| Environment file loader | High | `load_env_file`, `load_env` | Reads simple key/value configuration before execution. |
| Cache-as-index | High | `HASH_CACHE`, `load_hash_cache`, `save_hash_cache` | Avoids recomputing hashes when file metadata has not changed. |
| Defensive filesystem operation | Medium | `rename_webdav_file`, `copy_to_local_storage` | Refuses overwrites and logs failures instead of raising in every case. |
| Paged API collection | High | `collect_all_attachments`, `fetch_all_attachments` | Walks Zotero attachment pages to avoid incomplete indexes. |

## Entry points
- `zotero_sync_webdav.py`: primary unified automation path with subcommands for sync, diagnostics, duplicate cleanup, autostart setup, and Obsidian workflows.

## Public API surface
Important callable units observed in the unified script include `collect_all_pdfs`, `collect_all_attachments`, `compute_sha256`, `rename_webdav_file`, `rename_local_attachment`, `copy_to_local_storage`, `build_duplicate_groups`, `find_missing_drive_pdfs_in_zotero`, `run_diagnostic_mode`, and `run_duplicate_cleanup_mode`.

## External service dependencies
- Zotero API: requires `ZOTERO_LIBRARY_ID`, `ZOTERO_LIBRARY_TYPE`, and `ZOTERO_API_KEY`.
- WebDAV mount: the configured `ZOTERO_SYNC_TARGET_FOLDER` must exist as a Linux directory.
- Local Zotero storage: defaults to `~/Zotero/storage`.
- Desktop notification: optional `notify-send` and `xdg-open` integration.

## Key decisions and trade-offs
- Keep the main synchronizer automated. The user confirmed this is the desired operating mode.
- Hardening should focus on truthful failure reporting and testability, not adding manual confirmation prompts to the main path.
- The current single-file main script is convenient for operation but makes import-time side effects and unit testing harder. The first hardening cycle should address that boundary before deeper behavior changes.

## Risks and constraints
- Live API and filesystem mutations can affect the user's Zotero library and mounted WebDAV folder.
- Import-time environment validation currently makes automated tests harder [observed in code].
- Hash and rename logic needs regression tests because it decides whether to create, update, or rename attachments.
