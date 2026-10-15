# Documentation index

This is the official project context for `zotero_sync_webdav`.

## Core guides
- [Project overview](./project-overview.md)
- [Architecture](./architecture.md)
- [Data flow](./data-flow.md)
- [Development workflow](./development-workflow.md)
- [Testing strategy](./testing-strategy.md)
- [Security](./security.md)
- [Tooling](./tooling.md)
- [Glossary](./glossary.md)

## Q&A guides
- [Q&A index](./qa/README.md)
- [Getting started](./qa/getting-started.md)
- [Project structure](./qa/project-structure.md)

## Planning and execution
- [GSD project plan](../plans/PROJECT.md)
- [GSD state](../plans/STATE.md)
- [Ralph PRD](../workflow/prd.json)
- [Ralph notes](../workflow/README.md)
- [Ralph overview](../workflow/prd.overview.md)

## Current context summary
The repository is a small Python automation codebase for a Linux Zotero/WebDAV setup. The primary script is `zotero_sync_webdav.py`; the other scripts support diagnosis, duplicate cleanup, and Obsidian folder mirroring. The first active milestone is hardening the main synchronizer without turning the helper scripts into independent products.
