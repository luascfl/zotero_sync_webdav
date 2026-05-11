# AGENTS.md

## Project role
This repository contains automation scripts for a personal Linux Zotero/WebDAV workflow. The scripts are not separate products. Treat the synchronizer as the primary workflow and the diagnostic, duplicate cleanup, and Obsidian mirror scripts as supporting utilities.

## Operating constraints
- Target environment: Linux with a mounted WebDAV folder.
- Primary runtime: Python 3.
- External systems: Zotero API, local Zotero storage, mounted WebDAV directory, optional Obsidian vault folder.
- Automation goal: the main synchronizer should run unattended once configured. Do not add manual confirmation gates to the normal sync path unless a story explicitly asks for an emergency guardrail.
- Secrets belong in `.env` or `~/.config/zotero_sync_webdav/zotero_sync.env`. Never commit secrets.

## Current commands
- Syntax check active scripts:
  ```bash
  python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py zotero_storage_quota_audit.py
  ```
- Main sync:
  ```bash
  python3 zotero_sync_webdav.py
  ```
- Diagnostics:
  ```bash
  python3 zotero_sync_webdav.py diagnostico
  ```
- Duplicate removal dry run:
  ```bash
  python3 zotero_sync_webdav.py remove-duplicatas
  ```
- Duplicate removal real run:
  ```bash
  python3 zotero_sync_webdav.py remove-duplicatas --executar
  ```
- Setup autostart:
  ```bash
  python3 zotero_sync_webdav.py setup-autostart
  ```
- Obsidian mirror dry run:
  ```bash
  python3 zotero_sync_webdav.py obsidian-mirror --dry-run
  ```
- Obsidian config verify:
  ```bash
  python3 zotero_sync_webdav.py obsidian-verify --kind auto
  ```
- Obsidian config export:
  ```bash
  python3 zotero_sync_webdav.py obsidian-export --source auto --out /tmp/obsidian-bundle
  ```
- Obsidian config apply:
  ```bash
  python3 zotero_sync_webdav.py obsidian-apply --target deb --bundle /tmp/obsidian-bundle --dry-run
  ```
- Obsidian combined setup:
  ```bash
  python3 zotero_sync_webdav.py obsidian-setup --target deb --bundle /tmp/obsidian-bundle --dry-run
  ```
- Legacy mirror wrapper:
  ```bash
  python3 zotero_mirror_collections_to_obsidian.py --dry-run
  ```

- Storage audit:
  ```bash
  python3 zotero_storage_quota_audit.py --top 25
  ```

## Development rules
- Preserve automated operation for the main script.
- Make failures explicit. A failed API call, missing mount, missing secret, failed copy, or failed rename must be logged as a failure, not presented as success.
- Prefer pure, testable helpers for path resolution, filename normalization, cache behavior, and filesystem decisions.
- Do not contact Zotero API in tests unless a story explicitly defines an integration test with credentials.
- Add or update validation evidence in `.context/docs/planning_gsd/STATE.md` when a cycle changes behavior.

## Ralph and GSD
- PRD source: `.context/prd_ralph/prd.json`.
- GSD plan: `.context/docs/planning_gsd/PROJECT.md`.
- Current state: `.context/docs/planning_gsd/STATE.md`.
- Execute one Ralph story per cycle.
