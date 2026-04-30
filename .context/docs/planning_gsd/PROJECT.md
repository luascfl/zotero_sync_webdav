# GSD project plan

## Project objective
Harden the existing Linux Zotero/WebDAV automation scripts, with `zotero_sync_webdav.py` as the primary workflow, so unattended sync behavior is testable, explicit about failures, and safe against silent data drift.

## Non-goals
- Do not turn the helper scripts into separate products.
- Do not add a UI, web server, package restructure, or cross-platform support unless a later PRD story explicitly adds it.
- Do not add manual confirmation prompts to the normal main sync path.
- Do not use live Zotero API calls in unit tests.

## Milestone 0: governance bootstrap
Status: active for this orchestration cycle.

Deliverables:
- `.context/docs/` filled with current project context.
- `.context/docs/planning_gsd/PROJECT.md` and `STATE.md` created.
- `.context/prd_ralph/prd.json` and README created.
- `.context/workflow/status.yaml` initialized.
- `AGENTS.md` and `GEMINI.md` made operational for this project.

Dependencies:
- User clarification on scope, automation posture, target environment, priority, and removed file status. Completed on 2026-04-30.

Exit criteria:
- Canonical context files exist.
- PRD contains executable Ralph stories with quality gates.
- Next story has DoD and Gemini prompt.

## Milestone 1: main synchronizer hardening
Status: next.

Goal:
Make `zotero_sync_webdav.py` testable and truthful before changing deeper sync behavior.

Story order:
1. US-001: make the main synchronizer import-safe and add a first unit-test harness.
2. US-002: cover filesystem mutation helpers for copy, rename, and hash cache behavior.
3. US-003: add preflight checks for Linux WebDAV, dependency availability, and local storage writability.
4. US-004: make final reporting and process exit status reflect critical failures.

Dependencies:
- Milestone 0 must be complete.
- US-002 depends on US-001.
- US-003 depends on US-001.
- US-004 depends on US-001 and should reuse the test harness.

## Milestone 2: support script consistency
Status: planned.

Goal:
Apply the same failure and testability standards to diagnostics, duplicate cleanup, and Obsidian mirror scripts without expanding product scope.

Dependencies:
- Milestone 1 complete or stable enough to reuse patterns.
