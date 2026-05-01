---
slug: getting-started
category: getting-started
generatedAt: 2026-04-30
---

# How do I set up and run this project?

## Prerequisites
- Linux with the WebDAV folder mounted as a local directory.
- Python 3.
- Python packages: `pyzotero` and `tqdm`.
- Zotero API credentials.

## Configuration
Create `.env` in the repository root or `~/.config/zotero_sync_webdav/zotero_sync.env` with:

```env
ZOTERO_LIBRARY_ID=...
ZOTERO_LIBRARY_TYPE=user
ZOTERO_API_KEY=...
ZOTERO_SYNC_TARGET_FOLDER=/path/to/mounted/webdav/folder
```

Optional for the Obsidian mirror script:

```env
OBSIDIAN_ZOTERO_MIRROR_ROOT=/path/to/ObsidianLocal
```

## Run commands
- Validate syntax:
  ```bash
  python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py
  ```
- Run the main sync:
  ```bash
  python3 zotero_sync_webdav.py
  ```
- Run diagnostics:
  ```bash
  python3 zotero_sync_webdav.py diagnostico
  ```
- Configure autostart:
  ```bash
  python3 zotero_sync_webdav.py setup-autostart
  ```
- Mirror Zotero collections to Obsidian folders in dry-run mode:
  ```bash
  python3 zotero_mirror_collections_to_obsidian.py --dry-run
  ```
