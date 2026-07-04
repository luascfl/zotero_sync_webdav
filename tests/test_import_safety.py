"""Tests for US-001: import-safety and testability of zotero_sync_webdav."""
import importlib
import os
import tempfile
import unittest
from pathlib import Path


class ImportSafetyTests(unittest.TestCase):
    """Verify the module can be imported without env vars or side effects."""

    def test_import_without_env_vars(self):
        """Import succeeds even with no ZOTERO env vars set."""
        # The module is already imported by the test harness with a temp env.
        # This confirms it doesn't crash at import.
        import zotero_sync_webdav as zsync
        self.assertTrue(hasattr(zsync, 'normalize_filename'))
        self.assertTrue(hasattr(zsync, 'normalize_aggressive'))
        self.assertTrue(hasattr(zsync, 'resolve_target_folder'))
        self.assertTrue(hasattr(zsync, '_coerce_response_items'))

    def test_normalize_filename_accessible(self):
        import zotero_sync_webdav as zsync
        result = zsync.normalize_filename("Cópia de Teste.PDF")
        self.assertEqual(result, "cópia de teste.pdf")

    def test_normalize_aggressive_accessible(self):
        import zotero_sync_webdav as zsync
        result = zsync.normalize_aggressive("Formação e rompimento.pdf")
        self.assertEqual(result, "formacao e rompimento.pdf")

    def test_resolve_target_folder_with_existing_dir(self):
        import zotero_sync_webdav as zsync
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(zsync.resolve_target_folder(td), td)

    def test_resolve_target_folder_with_empty(self):
        import zotero_sync_webdav as zsync
        self.assertEqual(zsync.resolve_target_folder(""), "")
        self.assertEqual(zsync.resolve_target_folder(None), "")

    def test_coerce_response_items_with_list(self):
        import zotero_sync_webdav as zsync
        items = [{"key": "A"}, {"key": "B"}]
        result = zsync._coerce_response_items(items)
        self.assertEqual(result, items)

    def test_coerce_response_items_with_dict(self):
        import zotero_sync_webdav as zsync
        # A dict gets its values extracted as a list
        item = {"key": "A"}
        result = zsync._coerce_response_items(item)
        self.assertEqual(result, list(item.values()))

    def test_coerce_response_items_with_none(self):
        import zotero_sync_webdav as zsync
        result = zsync._coerce_response_items(None)
        self.assertEqual(result, [])


class ConfigValidationTests(unittest.TestCase):
    """Verify check_environment_requirements raises for missing config."""

    def test_missing_all_raises(self):
        import zotero_sync_webdav as zsync
        # Save originals
        orig = (zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded)
        try:
            zsync.LIBRARY_ID = ""
            zsync.API_KEY = ""
            zsync.TARGET_FOLDER_RAW = ""
            zsync._config_loaded = True  # prevent re-load from .env
            with self.assertRaises(RuntimeError) as ctx:
                zsync.check_environment_requirements()
            self.assertIn("ZOTERO_LIBRARY_ID", str(ctx.exception))
            self.assertIn("ZOTERO_API_KEY", str(ctx.exception))
        finally:
            zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded = orig

    def test_partial_missing_raises(self):
        import zotero_sync_webdav as zsync
        orig = (zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded)
        try:
            zsync.LIBRARY_ID = "12345"
            zsync.API_KEY = ""
            zsync.TARGET_FOLDER_RAW = "/tmp"
            zsync._config_loaded = True
            with self.assertRaises(RuntimeError) as ctx:
                zsync.check_environment_requirements()
            self.assertIn("ZOTERO_API_KEY", str(ctx.exception))
            self.assertNotIn("ZOTERO_LIBRARY_ID", str(ctx.exception))
        finally:
            zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded = orig

    def test_all_present_passes(self):
        import zotero_sync_webdav as zsync
        orig = (zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded)
        try:
            zsync.LIBRARY_ID = "12345"
            zsync.API_KEY = "secret"
            zsync.TARGET_FOLDER_RAW = "/tmp"
            zsync._config_loaded = True
            # Should not raise
            zsync.check_environment_requirements()
        finally:
            zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded = orig


class LoadEnvFileTests(unittest.TestCase):
    """Verify load_env_file parses env correctly."""

    def test_load_env_file_basic(self):
        import zotero_sync_webdav as zsync
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("TEST_LOAD_ENV_VAR=hello_world\n")
            f.write("# comment\n")
            f.write("\n")
            f.write('TEST_QUOTED_VAR="quoted_value"\n')
            env_path = f.name
        try:
            os.environ.pop("TEST_LOAD_ENV_VAR", None)
            os.environ.pop("TEST_QUOTED_VAR", None)
            zsync.load_env_file(env_path)
            self.assertEqual(os.environ.get("TEST_LOAD_ENV_VAR"), "hello_world")
            self.assertEqual(os.environ.get("TEST_QUOTED_VAR"), "quoted_value")
        finally:
            os.unlink(env_path)
            os.environ.pop("TEST_LOAD_ENV_VAR", None)
            os.environ.pop("TEST_QUOTED_VAR", None)

    def test_load_env_file_no_override(self):
        import zotero_sync_webdav as zsync
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("TEST_NO_OVERRIDE=from_file\n")
            env_path = f.name
        try:
            os.environ["TEST_NO_OVERRIDE"] = "from_env"
            zsync.load_env_file(env_path, override=False)
            self.assertEqual(os.environ["TEST_NO_OVERRIDE"], "from_env")
        finally:
            os.unlink(env_path)
            os.environ.pop("TEST_NO_OVERRIDE", None)

    def test_load_env_file_missing(self):
        import zotero_sync_webdav as zsync
        # Should not raise
        zsync.load_env_file("/tmp/does-not-exist-xyz.env")


if __name__ == "__main__":
    unittest.main()
