#!/usr/bin/env python3
"""Wrapper legado para o modo de diagnóstico unificado."""

import os
import sys
from pathlib import Path


if __name__ == "__main__":
    script = Path(__file__).with_name("zotero_sync_webdav.py")
    os.execv(sys.executable, [sys.executable, str(script), "diagnostico", *sys.argv[1:]])
