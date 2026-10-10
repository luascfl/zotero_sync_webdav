import importlib
import os
import tempfile
import unittest
from pathlib import Path


_TEMP_DIR = tempfile.TemporaryDirectory()
_TARGET_DIR = Path(_TEMP_DIR.name) / "zoterodb"
_TARGET_DIR.mkdir()
_ENV_FILE = Path(_TEMP_DIR.name) / "zotero_sync.env"
_ENV_FILE.write_text(
    "ZOTERO_LIBRARY_ID=1\n"
    "ZOTERO_LIBRARY_TYPE=user\n"
    "ZOTERO_API_KEY=dummy\n"
    f"ZOTERO_SYNC_TARGET_FOLDER={_TARGET_DIR}\n",
    encoding="utf-8",
)
os.environ["ZOTERO_ENV_FILE"] = str(_ENV_FILE)

zsync = importlib.import_module("zotero_sync_webdav")


class UnifiedVaultTopologyTests(unittest.TestCase):
    def test_unified_vault_root_uses_configured_drive_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            drive_root = Path(temp_dir) / "drive" / "zoterodb"
            original_target = zsync.TARGET_FOLDER
            zsync.TARGET_FOLDER = str(drive_root)
            try:
                self.assertEqual(zsync.resolve_unified_vault_root(), drive_root.resolve())
            finally:
                zsync.TARGET_FOLDER = original_target

    def test_collection_directories_are_created_once_in_unified_root(self):
        collections = [
            {"key": "ROOT", "data": {"name": "Curso"}},
            {"key": "CHILD", "data": {"name": "Leituras", "parentCollection": "ROOT"}},
        ]
        collection_by_key, _, _ = zsync.build_collection_path_model(collections)
        stats = {}
        with tempfile.TemporaryDirectory() as temp_dir:
            vault_root = Path(temp_dir) / "zoterodb"
            zsync.ensure_unified_vault_collection_directories(collection_by_key, vault_root, stats)
            self.assertTrue((vault_root / "Curso").is_dir())
            self.assertTrue((vault_root / "Curso" / "Leituras").is_dir())
            self.assertEqual(stats["created_unified_vault_collection_dirs"], 2)

            zsync.ensure_unified_vault_collection_directories(collection_by_key, vault_root, stats)
            self.assertEqual(stats["created_unified_vault_collection_dirs"], 2)


if __name__ == "__main__":
    unittest.main()
