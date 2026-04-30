# GSD state

Updated: 2026-04-30

## Current state
- Context bootstrap is complete enough to propose the next Ralph cycle.
- User clarified that this repository is script automation, not a set of official products.
- Main sync should remain automatic.
- Target environment is Linux with mounted WebDAV.
- Active technical priority is hardening.
- `padronizar_contatos_google.py` removal is intentional because it did not belong to this repository.

## Active milestone
Milestone 0: governance bootstrap.

### Milestone 0 dependencies
- User clarification: complete.
- AI Coders Context scaffold: complete for `.context/docs/`.
- PRD JSON: created and JSON-validated at `.context/prd_ralph/prd.json`.
- GSD project plan: created at `.context/docs/planning_gsd/PROJECT.md`.
- Workflow status: initialized at `.context/workflow/status.yaml` with current phase P.
- Syntax validation: `python3 -m py_compile zotero_sync_webdav.py zotero_diagnostico.py zotero_remove_duplicatas.py zotero_mirror_collections_to_obsidian.py` passed on 2026-04-30.

## Next milestone
Milestone 1: main synchronizer hardening.

Dependencies:
- Milestone 0 complete.
- US-001 must land before deeper filesystem, preflight, and outcome hardening stories.

## Next Ralph story
- ID: US-001
- Title: Make main sync import-safe and testable
- Reason: current `zotero_sync_webdav.py` performs required environment validation and log setup at import time [observed in code], which blocks unit tests and hides runtime boundaries. Import-safety is the correct first hardening seam.

## Definition of done for next story
- `zotero_sync_webdav.py` can be imported without `ZOTERO_*` environment variables.
- Runtime config validation still fails clearly before live Zotero calls when required values are missing.
- Initial `tests/` suite exists and uses standard-library `unittest`.
- Tests cover import-safety, path resolution, filename normalization, and malformed response coercion.
- Syntax and test quality gates pass.

## Validation checklist for next story
- `python3 -m py_compile zotero_sync_webdav.py zotero_diagnostico.py zotero_remove_duplicatas.py zotero_mirror_collections_to_obsidian.py`
- `python3 -m unittest discover -s tests`
- Confirm no live Zotero API call is made during unit tests.
- Confirm `.context/docs/planning_gsd/STATE.md` is updated with evidence.
- Confirm PRD story status is advanced by Ralph or recorded manually only if Ralph is not used.

## Gemini prompt for next story
```text
You are Gemini executing one Ralph story in /home/lucas/Downloads/zotero_sync_webdav.

Read first:
1. AGENTS.md
2. GEMINI.md
3. .context/docs/README.md
4. .context/docs/planning_gsd/STATE.md
5. .context/prd_ralph/prd.json

Execute only story US-001: Make main sync import-safe and testable.

Scope:
- Touch zotero_sync_webdav.py and add tests/ files only if needed.
- Do not touch the helper scripts unless a syntax gate reveals an issue caused by this story.
- Do not contact Zotero API in tests.
- Preserve automated operation of the main sync path.

Required behavior:
- Importing zotero_sync_webdav with no ZOTERO_* environment variables must not raise.
- Runtime config validation must still fail clearly before any Zotero API call when required values are missing.
- Move import-time side effects that block tests into explicit runtime setup used by main().
- Add unittest coverage for import-safety, resolve_target_folder, normalize_filename, normalize_aggressive, and _coerce_response_items malformed/empty cases.

Verification:
- Run: python3 -m py_compile zotero_sync_webdav.py zotero_diagnostico.py zotero_remove_duplicatas.py zotero_mirror_collections_to_obsidian.py
- Run: python3 -m unittest discover -s tests
- Update .context/docs/planning_gsd/STATE.md with exact validation evidence.

Return a concise result with files changed and command results.
```

## Evidence log
- 2026-04-30: AI Coders Context mapped 4 Python scripts and symbol lists.
- 2026-04-30: `ralph --help` observed available commands: `install`, `prd`, `ping`, `log`, `build`, `overview`, `help`.
- 2026-04-30: PRD skill instructions observed in Ralph package at `/home/lucas/.nvm/versions/node/v22.21.1/lib/node_modules/@iannuttall/ralph/skills/prd/SKILL.md` because `skill://prd` was unavailable in this harness.
- 2026-04-30: `python3 -m json.tool .context/prd_ralph/prd.json` passed.
- 2026-04-30: removed generated non-canonical graphify/opencode artifacts from the bootstrap workspace; official context remains under `.context/docs`, `.context/prd_ralph`, and `.context/workflow`.
