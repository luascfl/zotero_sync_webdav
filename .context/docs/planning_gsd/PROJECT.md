# GSD project plan

## Project objective
Harden the existing Linux Zotero/WebDAV automation scripts, with `zotero_sync_webdav.py` as the primary workflow, so unattended sync behavior is testable, explicit about failures, and safe against silent data drift.

## Non-goals
- Do not turn the helper scripts into separate products.
- Do not add a UI, web server, package restructure, or cross-platform support unless a later PRD story explicitly adds it.
- Do not add manual confirmation prompts to the normal main sync path.
- Do not use live Zotero API calls in unit tests.

## Milestone 0: governance bootstrap
Status: complete.

## Milestone 1: main synchronizer hardening
Status: complete.

## Milestone 2: Obsidian Integration & Collections Routing
Status: complete.

Goal:
Integrate Obsidian staging, drive-authoritative collection mapping, Desktop API bypass, and copy-marker cleanup.

## Milestone 3: Rclone Resilience & Scalability
Status: complete. Completed on 2026-07-03.

Goal:
Fix the systemic timeout issue causing the full sync to abort after 1 hour due to stalled PDF hashing over the rclone mount. Resolve the 291 missing/orphaned file paths safely.

Story order:
1. US-005: Rclone timeout resilience and hashing bypass.
2. US-006: Orphaned file recovery pass.

Dependencies:
- Milestone 2 complete.
