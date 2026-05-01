---
type: doc
name: project-overview
description: High-level overview of the project, its purpose, and key components
category: overview
generated: 2026-04-30
status: filled
---

# Project overview

`zotero_sync_webdav` automates a Linux Zotero workflow where PDFs live in a mounted WebDAV folder and need to stay aligned with Zotero attachments and local Zotero storage. The codebase is script-based, not a product suite. The main value is unattended synchronization with clear diagnostics when something is unsafe or broken.

## Quick facts
- Root: `/home/lucas/Downloads/zotero_sync_webdav`
- Language: Python, 2 active script files observed.
- Runtime target: Linux with a mounted WebDAV directory.
- Primary external dependency: `pyzotero` for the Zotero API.
- Supporting dependency: `tqdm` for progress display in the main sync script.
- Secrets and paths: `.env` or `~/.config/zotero_sync_webdav/zotero_sync.env`.

## Entry points
- [`zotero_sync_webdav.py`](../../zotero_sync_webdav.py): primary unified CLI for sync, diagnostics, duplicate cleanup, and autostart setup.
- [`zotero_mirror_collections_to_obsidian.py`](../../zotero_mirror_collections_to_obsidian.py): mirrors Zotero collections into Obsidian folders.

## Code organization
- Root Python scripts hold all runtime behavior.
- `.context/docs/` holds project documentation and planning context.
- `.context/prd_ralph/` holds Ralph PRD state.
- `.context/workflow/` holds PREVC workflow status.
- `.ralph/` may be created by Ralph when a build loop runs.

## Technology stack summary
The project uses Python scripts instead of a package layout. It talks to Zotero through `pyzotero`, reads local files through the standard library, stores hash cache data under `~/.cache/zotero_sync_webdav`, and uses Linux desktop integration for notifications and log opening when available.

## Getting started checklist
1. Create `.env` or `~/.config/zotero_sync_webdav/zotero_sync.env` with `ZOTERO_LIBRARY_ID`, `ZOTERO_LIBRARY_TYPE`, `ZOTERO_API_KEY`, and `ZOTERO_SYNC_TARGET_FOLDER`.
2. Ensure the WebDAV folder is mounted and readable.
3. Install runtime dependencies, at least `pyzotero` and `tqdm`.
4. Run syntax validation with `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
5. Run `python3 zotero_sync_webdav.py diagnostico` before destructive cleanup work.
6. Run `python3 zotero_sync_webdav.py` for the automated sync path.

## Current direction
The active workstream is hardening: make the main synchronizer import-safe, testable, explicit about failures, and reliable in unattended Linux/WebDAV use.
