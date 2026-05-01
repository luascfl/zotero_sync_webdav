---
type: doc
name: testing-strategy
description: Test frameworks, patterns, coverage requirements, and quality gates
category: testing
generated: 2026-04-30
status: filled
---

# Testing strategy

The repository currently has no observed automated test suite. The immediate hardening direction is to make the primary synchronizer import-safe and add unit tests around pure logic before changing live Zotero or WebDAV behavior.

## Test types
- Unit tests: should cover path resolution, filename normalization, hash cache behavior, response coercion, and filesystem decision helpers using temporary directories.
- Integration tests: should be opt-in only, because they would require real Zotero credentials and a mounted WebDAV folder.
- End-to-end tests: not defined yet. They should not be introduced until the script has a safe fixture or fake Zotero boundary.

## Running tests
- Current syntax gate:
  ```bash
  python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py
  ```
- Recommended first unit-test gate after US-001:
  ```bash
  python3 -m unittest discover -s tests
  ```

## Quality gates
The PRD currently sets these gates:
- `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`
- `python3 -m unittest discover -s tests`

The unit-test gate is expected to become valid during the first hardening story, which creates the first tests.

## Test boundaries
- Unit tests must not require `ZOTERO_API_KEY`, a live Zotero account, or a mounted WebDAV folder.
- Tests should use temporary directories for filesystem cases.
- Tests should verify negative cases, especially missing env, destination collision, unreadable file, malformed API response, and failed copy or rename.
