---
slug: project-structure
category: architecture
generatedAt: 2026-04-30
---

# How is the codebase organized?

The repository is currently organized as root-level Python scripts plus `.context` governance files.

## Runtime scripts
- `zotero_sync_webdav.py`: primary unified sync CLI between mounted WebDAV PDFs, Zotero attachments, local Zotero storage, diagnostics, duplicate cleanup, and autostart setup.
- `zotero_mirror_collections_to_obsidian.py`: creates an Obsidian folder tree from Zotero collections.

## Context and workflow
- `.context/docs/`: official technical documentation.
- `.context/docs/planning_gsd/`: GSD project plan and state.
- `.context/prd_ralph/`: Ralph PRD and generated overview.
- `.context/workflow/`: AI Coders Context workflow state.

## Ignored local files
- `.env` and token files are ignored.
- `__pycache__/` and `*.pyc` are ignored.
