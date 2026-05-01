# PRD Overview: Zotero WebDAV sync hardening

- File: .context/prd_ralph/prd.json
- Stories: 4 total (4 open, 0 in_progress, 0 done)

## Quality Gates
- python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py
- python3 -m unittest discover -s tests

## Stories
- [open] US-001: Make main sync import-safe and testable
- [open] US-002: Test filesystem mutation helpers (depends on: US-001)
- [open] US-003: Add automated preflight checks (depends on: US-001)
- [open] US-004: Make run outcome truthful (depends on: US-001)
