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

    def test_deb_obsidian_resolver_keeps_its_app_path_default(self):
        kind, app_dir = zsync.resolve_obsidian_app_dir("deb", None)
        self.assertEqual(kind, "deb")
        self.assertEqual(app_dir, zsync.DEFAULT_OBSIDIAN_DEB_APP_DIR)

    def test_registry_preserves_existing_vaults_when_adding_unified_root(self):
        existing = {"IMAGES": {"path": "/srv/images", "ts": 1}}
        with tempfile.TemporaryDirectory() as temp_dir:
            vault_root = Path(temp_dir) / "zoterodb"
            merged, added = zsync.ensure_unified_vault_registry_entry(existing, vault_root)

            self.assertTrue(added)
            self.assertEqual(existing, {"IMAGES": {"path": "/srv/images", "ts": 1}})
            self.assertEqual(merged["IMAGES"], existing["IMAGES"])
            self.assertIn(str(vault_root.resolve()), [entry["path"] for entry in merged.values()])

            unchanged, added_again = zsync.ensure_unified_vault_registry_entry(merged, vault_root)
            self.assertFalse(added_again)
            self.assertEqual(unchanged, merged)

    def test_setup_mode_applies_bundle_then_mirrors_unified_root(self):
        import argparse
        import json
        from unittest import mock

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            app_dir = base / "app"
            vault_root = base / "zoterodb"
            other_vault = base / "other"
            for path in (app_dir, vault_root / ".obsidian", other_vault / ".obsidian"):
                path.mkdir(parents=True)
            (app_dir / "obsidian.json").write_text(
                json.dumps({"vaults": {"OTHER": {"path": str(other_vault)}}}),
                encoding="utf-8",
            )
            bundle = base / "bundle"
            (bundle / "app").mkdir(parents=True)
            (bundle / "vaults" / "OTHER" / ".obsidian").mkdir(parents=True)
            (bundle / "app" / "obsidian.json").write_text(
                json.dumps({"vaults": {"OTHER": {"path": str(other_vault)}}}),
                encoding="utf-8",
            )
            args = argparse.Namespace(
                target="deb", app_dir=str(app_dir), bundle=str(bundle), map=None,
                create_missing_vaults=False, dry_run=False, apply=True,
            )
            original_target = zsync.TARGET_FOLDER
            zsync.TARGET_FOLDER = str(vault_root)
            try:
                with mock.patch.object(zsync, "load_config") as load_config, \
                        mock.patch.object(zsync, "connect_zotero_client", return_value=object()), \
                        mock.patch.object(zsync, "mirror_zotero_collections_to_obsidian") as mirror:
                    zsync.run_obsidian_setup_mode(args)
            finally:
                zsync.TARGET_FOLDER = original_target

            load_config.assert_called_once()
            self.assertEqual(mirror.call_args.args[1], vault_root.resolve())
            self.assertTrue(mirror.call_args.args[2])
            registered = json.loads((app_dir / "obsidian.json").read_text(encoding="utf-8"))["vaults"]
            paths = {entry["path"] for entry in registered.values()}
            self.assertEqual(paths, {str(other_vault), str(vault_root.resolve())})

    def test_transport_logging_is_quiet_unless_explicitly_enabled(self):
        import logging
        from unittest import mock

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ZOTERO_HTTP_DEBUG", None)
            zsync.configure_transport_logging()
            self.assertEqual(logging.getLogger("httpcore").level, logging.WARNING)
            self.assertEqual(logging.getLogger("httpx").level, logging.WARNING)

            os.environ["ZOTERO_HTTP_DEBUG"] = "1"
            zsync.configure_transport_logging()
            self.assertEqual(logging.getLogger("httpcore").level, logging.DEBUG)

        zsync.configure_transport_logging()

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
