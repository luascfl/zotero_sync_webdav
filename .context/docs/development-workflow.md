---
type: doc
name: development-workflow
description: Day-to-day engineering processes, branching, and contribution guidelines
category: workflow
generated: 2026-04-30
status: filled
---

# Development workflow

Use the GSD plus Ralph workflow for changes. GSD defines milestones and dependencies, Ralph selects exactly one story per cycle, and Gemini executes the closed implementation prompt when available. Codex owns orchestration, validation, and context updates.

## Branching and releases
- Current branch observed: `main` tracking `origin/main`.
- Remote observed: `https://github.com/luascfl/zotero_sync_webdav.git`.
- Keep meaningful code, configuration, and context changes committed before closing a cycle.
- Do not discard user changes. The deletion of `padronizar_contatos_google.py` is intentional per user clarification.

## Local development
- Syntax gate:
  ```bash
  python3 -m py_compile zotero_sync_webdav.py zotero_diagnostico.py zotero_remove_duplicatas.py zotero_mirror_collections_to_obsidian.py
  ```
- Main sync:
  ```bash
  python3 zotero_sync_webdav.py
  ```
- Diagnostics:
  ```bash
  python3 zotero_sync_webdav.py diagnostico
  ```
- Duplicate cleanup dry run:
  ```bash
  python3 zotero_sync_webdav.py remove-duplicatas
  ```
- Duplicate cleanup real run:
  ```bash
  python3 zotero_sync_webdav.py remove-duplicatas --executar
  ```
- Setup autostart:
  ```bash
  python3 zotero_sync_webdav.py setup-autostart
  ```
- Obsidian mirror dry run:
  ```bash
  python3 zotero_mirror_collections_to_obsidian.py --dry-run
  ```

## Code review expectations
- Verify live-system boundaries before editing code that calls Zotero or mutates files.
- Prefer adding tests around pure helpers and temporary directories before changing rename, copy, cache, or hash behavior.
- Keep automation as the default for the main synchronizer.
- Ensure failures are truthful in logs, exit behavior, and final reports.
- Update `.context/docs/planning_gsd/STATE.md` with validation evidence after each cycle.

## Context update rule
When behavior changes, update the relevant docs under `.context/docs/`, the GSD state file, and the PRD story status through Ralph rather than creating an external backlog.
