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

## Milestone 4: Zotero sync status panel
Status: complete. Completed on 2026-09-13.

Goal:
Extend the existing `zotero-sync-recognizer` extension with a local read-only panel that exposes the active sync progress, last completion, errors, and duplicate-review counts without changing its recognition, import, fallback, or HTTP endpoint roles.

Story order:
1. US-008: Publish and present local sync status.

Dependencies:
- Milestones 1–3 complete.
- The existing extension and desktop connector remain the integration boundary.

## Milestone 5: Zotero Web recency cache
Status: complete. Completed on 2026-09-14.

Goal:
Maintain a bounded, read-only-in-practice cache group in Zotero File Storage containing the most recently added readable PDFs from the primary library, without changing the primary library, local storage, or WebDAV.

Story order:
1. US-009: Reconcile a recent-PDF Zotero Web cache group.

Dependencies:
- Milestone 4 complete.
- The private cache group ID is configured locally and reachable with the existing API key.

## Milestone 6: Duplicate handling safety
Status: complete. Completed on 2026-10-07.

Goal:
Make duplicate handling content-addressed and reversible. Today four mechanisms use filename similarity, two of them act without a report, and removals leave no audit trail or undo path.

Story order:
1. US-010: Quarantine and audit trail for duplicate file removal.
2. US-011: Read-only duplicates report and safer Zotero item removal.

Dependencies:
- Milestone 5 complete.
- The collection-flip guard (`find_ambiguous_drive_names`) is already in place.

## Milestone 7: Sync run cost
Status: in progress (US-012 and US-013 done; US-014 conditional on measured need).

Goal:
Cut the fixed cost of each sync run using measurements from the live library (1850 PDFs, rclone mount). Measured on 2026-10-07: connect 6.9 s, full attachment listing 44.4 s, full bibliographic listing 55.5 s, collections 0.7 s, one recursive drive scan 41.5 s, hashing of size-colliding candidates under 0.1 s with a warm cache. Hashing is not the bottleneck; the API listings and the repeated drive scans are.

Story order:
1. US-012: Scan the drive once per sync run (includes removing the extra scan added with the collection-flip guard).
2. US-013: Incremental Zotero library fetch.
3. US-014: Content-hash view shared by report and sync (conditional on measured need).

Dependencies:
- Milestone 6 complete.

## Milestone 8: Unified Obsidian vault
Status: in progress.

Goal:
Make the configured Drive target the single physical root for Zotero PDFs and the Obsidian vault, with collection paths shared in place and no sync-time copy or move between separate roots.

Story order:
1. US-015: Make the Obsidian vault share the Drive root.
2. US-016: Classify in-place PDFs by unified collection path.
3. Follow-up: register the configured Drive root as the Obsidian vault during setup.

Dependencies:
- Milestone 7's shared recursive scan is complete.
- The existing collection-path model remains the sole source of physical collection paths.
