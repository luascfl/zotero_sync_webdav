#!/usr/bin/env python3
"""Compat wrapper para o subcomando obsidian-mirror do zotero_sync_webdav.py."""

from __future__ import annotations

import sys

from zotero_sync_webdav import main


if __name__ == "__main__":
    main(["obsidian-mirror", *sys.argv[1:]])
