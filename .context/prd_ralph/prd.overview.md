# PRD Overview: Zotero WebDAV sync hardening

- File: .context/prd_ralph/prd.json
- Stories: 16 total (1 open, 0 in_progress, 15 done)

## Quality Gates
- python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py
- python3 -m unittest discover -s tests

## Stories
- [done] US-001: Make main sync import-safe and testable
- [done] US-002: Test filesystem mutation helpers (depends on: US-001)
- [done] US-003: Add automated preflight checks (depends on: US-001)
- [done] US-004: Make run outcome truthful (depends on: US-001)
- [done] US-005: Rclone timeout resilience and hashing bypass
- [done] US-006: Orphaned file recovery pass
- [done] US-007: Add test coverage for folder deduplication and single-instance locks
- [done] US-008: Present sync status in the existing Zotero extension (depends on: US-001, US-004)
- [done] US-009: Maintain a recent-PDF Zotero Web cache (depends on: US-004)
- [done] US-010: Quarantine and audit trail for duplicate file removal (depends on: US-009)
- [done] US-011: Read-only duplicates report and safer Zotero item removal (depends on: US-010)
- [done] US-012: Scan the drive once per sync run (depends on: US-011)
- [done] US-013: Incremental Zotero library fetch (depends on: US-012)
- [todo] US-014: Content-hash view shared by report and sync (depends on: US-012)
- [done] US-015: Make the Obsidian vault share the Drive root (depends on: US-012)
- [done] US-016: Classify in-place PDFs by unified collection path (depends on: US-015)
