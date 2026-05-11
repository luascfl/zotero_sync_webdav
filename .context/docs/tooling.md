---
type: doc
name: tooling
description: Scripts, IDE settings, automation, and developer productivity tips
category: tooling
generated: 2026-04-30
status: filled
---

# Tooling and productivity guide

The project is intentionally lightweight. Tooling should improve reliability without introducing package or service complexity unless a Ralph story requires it.

## Required tooling
- Python 3: runtime for all scripts.
- `pyzotero`: Zotero API client used by all Zotero-facing scripts.
- `tqdm`: progress display used by `zotero_sync_webdav.py`.
- Linux WebDAV mount: required for the main workflow.
- Optional desktop tools: `notify-send` and `xdg-open` for completion notification and log opening.

## Recommended automation
- Keep a syntax gate available:
  ```bash
  python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py
  ```
- After tests are introduced:
  ```bash
  python3 -m unittest discover -s tests
  ```
- Use Ralph with the PRD path:
  ```bash
  ralph build 1 --prd .context/prd_ralph/prd.json
  ```

## Configuration files
- `.env`: local project configuration, ignored by Git.
- `~/.config/zotero_sync_webdav/zotero_sync.env`: service-level configuration path used by scripts.
- `.context/prd_ralph/prd.json`: Ralph story source.
- `.context/docs/planning_gsd/STATE.md`: current milestone and validation evidence.

## Productivity tips
- Run the diagnostic script before cleanup or after unexpected sync behavior.
- Use temporary directories in tests for all file mutation logic.
- Keep live Zotero API calls out of unit tests.
