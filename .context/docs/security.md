---
type: doc
name: security
description: Security policies, authentication, secrets management, and compliance requirements
category: security
generated: 2026-04-30
status: filled
---

# Security and compliance notes

This project handles personal Zotero library access, local files, and a mounted WebDAV folder. The main risks are credential leakage, unintended file mutation, silent data drift, and misleading success reports after partial failure.

## Authentication and authorization
- Zotero API access uses `ZOTERO_API_KEY` plus `ZOTERO_LIBRARY_ID` and `ZOTERO_LIBRARY_TYPE`.
- The scripts currently read credentials from environment variables, `.env`, or `~/.config/zotero_sync_webdav/zotero_sync.env`.
- No web authentication, user sessions, or role model exists in this repository.

## Secrets and sensitive data
- `.env`, token files, and API-key-looking files are ignored by `.gitignore`.
- Never commit `ZOTERO_API_KEY`, WebDAV credentials, Google tokens, or generated logs that include sensitive local paths if those paths are private.
- Do not print full secret values in logs or exceptions.

## Filesystem safety
- The main sync mutates local Zotero storage and the mounted WebDAV folder by copying and renaming files.
- Destination collisions must be treated as explicit warnings or failures, never overwritten silently.
- Missing mount or permission failures must stop the affected flow and be visible in the final report.

## Incident response
If an automated sync produces unexpected mutations:
1. Stop the autostart or scheduled runner.
2. Preserve the daily log under `~/.cache/zotero_sync_webdav/logs`.
3. Run `python3 zotero_diagnostico.py` to compare Zotero and WebDAV state.
4. Do not run duplicate deletion until the diagnostic output has been reviewed.
