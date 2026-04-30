---
type: doc
name: glossary
description: Project terminology, type definitions, domain entities, and business rules
category: glossary
generated: 2026-04-30
status: filled
---

# Glossary and domain concepts

## Core terms
- Zotero library: the user's Zotero account library addressed by `ZOTERO_LIBRARY_ID` and `ZOTERO_LIBRARY_TYPE`.
- Attachment: a Zotero item representing a linked or stored file, usually a PDF in this workflow.
- WebDAV folder: the mounted Linux directory configured by `ZOTERO_SYNC_TARGET_FOLDER` and scanned for PDFs.
- Local Zotero storage: the local directory, currently `~/Zotero/storage`, where local attachment copies are stored.
- Normalized filename: a lowercased and Unicode-normalized filename used for comparison.
- Aggressive normalization: comparison form that removes accents and strips many non-alphanumeric characters to reduce duplicate misses.
- Hash cache: JSON cache under `~/.cache/zotero_sync_webdav` that stores file hashes and stat metadata.
- Case 1: name and content already match, skip.
- Case 2: name matches but content differs, update local storage from WebDAV.
- Case 3: content hash matches but name differs, reconcile rename direction.
- Case 4: name and hash are new, add attachment to Zotero.
- Case 5: Zotero has the name but local storage is missing, recreate the local copy.

## Type definitions and enums
No exported Python type definitions or enums were observed. The code currently uses dictionaries and simple scalar values for attachment metadata, stats, and cache entries.

## Actors
- Local operator: Lucas, running the scripts on Linux.
- Zotero API: source of attachment metadata and target for attachment creation or metadata updates.
- WebDAV mount: local filesystem view of remote PDF storage.
- Obsidian vault: optional target for mirrored collection folders.

## Domain rules and invariants
- The main sync path should remain automated once configured.
- Secrets must not be committed.
- A destination file collision during rename or copy must not overwrite an existing file silently.
- Tests should not require live Zotero credentials unless explicitly marked as integration tests.
- A final report should not imply success when critical setup or mutation steps failed.
