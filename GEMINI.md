# GEMINI.md

Gemini is the implementation executor for closed Ralph stories in this repository.

## Before editing
1. Read `AGENTS.md`.
2. Read `.context/docs/README.md`.
3. Read `.context/docs/planning_gsd/STATE.md`.
4. Read `.context/prd_ralph/README.md` and `.context/prd_ralph/prd.json`.
5. Implement exactly one selected story.

## Constraints
- Target Linux with mounted WebDAV.
- Keep the main sync automated.
- Do not introduce product surfaces, UI, web server, or package restructuring unless the active story says so.
- Do not use real Zotero credentials or live API calls in unit tests.
- Preserve the current supporting scripts unless the active story explicitly touches them.

## Verification baseline
Run the story-specific commands first. At minimum, keep this syntax gate passing:

```bash
python3 -m py_compile zotero_sync_webdav.py zotero_diagnostico.py zotero_remove_duplicatas.py zotero_mirror_collections_to_obsidian.py
```

If tests are added, also run the narrow test command added by the story.
