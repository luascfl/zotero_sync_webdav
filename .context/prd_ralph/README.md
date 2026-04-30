# Ralph PRD context

Canonical PRD path: `.context/prd_ralph/prd.json`.

This PRD treats the repository as a Linux automation script project, not as a set of separate products. Ralph should execute one story per cycle. The current priority is hardening the main Zotero/WebDAV synchronizer while preserving unattended operation.

## User clarifications captured on 2026-04-30
- The goal is to do the workflow through the script, not to define separate official products.
- The main synchronizer should be automatic, not manually confirmed by default.
- The target environment is Linux with mounted WebDAV for now.
- The next technical priority is hardening.
- `padronizar_contatos_google.py` was intentionally removed because it did not belong to this repository.

## Build command
Use:

```bash
ralph build 1 --prd .context/prd_ralph/prd.json
```

If Gemini execution is handled outside Ralph, use the prompt recorded in `.context/docs/planning_gsd/STATE.md` for the selected story.
