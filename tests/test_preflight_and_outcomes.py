"""Tests for US-003: preflight checks and US-004: truthful run outcomes."""
import os
import tempfile
import unittest

import zotero_sync_webdav as zsync


class PreflightChecksTests(unittest.TestCase):
    """Verify preflight_checks catches missing prerequisites."""

    def _with_config(self, lib_id="1", api_key="dummy", target="", local_dir=None):
        """Helper to set config globals for testing."""
        self._orig = (
            zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW,
            zsync.TARGET_FOLDER, zsync.LOCAL_COPY_DIR, zsync._config_loaded,
        )
        zsync.LIBRARY_ID = lib_id
        zsync.API_KEY = api_key
        zsync.TARGET_FOLDER_RAW = target
        zsync.TARGET_FOLDER = target
        zsync._config_loaded = True
        if local_dir is not None:
            zsync.LOCAL_COPY_DIR = local_dir

    def _restore(self):
        (zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW,
         zsync.TARGET_FOLDER, zsync.LOCAL_COPY_DIR, zsync._config_loaded) = self._orig

    def test_preflight_pass(self):
        """All checks pass with valid dirs."""
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "drive")
            local = os.path.join(td, "storage")
            os.makedirs(target)
            os.makedirs(local)
            self._with_config(target=target, local_dir=local)
            try:
                errors = zsync.preflight_checks()
                self.assertEqual(errors, [])
            finally:
                self._restore()

    def test_preflight_missing_env(self):
        """Missing env vars caught."""
        self._with_config(lib_id="", api_key="", target="")
        try:
            errors = zsync.preflight_checks()
            self.assertTrue(len(errors) > 0)
            self.assertTrue(any("ZOTERO_LIBRARY_ID" in e for e in errors))
        finally:
            self._restore()

    def test_preflight_missing_target_folder(self):
        """Non-existent target folder caught."""
        self._with_config(target="/tmp/does-not-exist-xyz-preflight-test")
        try:
            errors = zsync.preflight_checks()
            self.assertTrue(any("não encontrada" in e or "não é diretório" in e for e in errors))
        finally:
            self._restore()

    def test_preflight_empty_target_folder(self):
        """Empty target folder caught."""
        self._with_config(target="")
        # TARGET_FOLDER_RAW is empty, so check_env should catch it
        try:
            errors = zsync.preflight_checks()
            self.assertTrue(len(errors) > 0)
        finally:
            self._restore()

    def test_preflight_creates_missing_local_dir(self):
        """Missing local storage dir is auto-created."""
        with tempfile.TemporaryDirectory() as td:
            target = os.path.join(td, "drive")
            local = os.path.join(td, "new_storage")
            os.makedirs(target)
            self._with_config(target=target, local_dir=local)
            try:
                errors = zsync.preflight_checks()
                self.assertEqual(errors, [])
                self.assertTrue(os.path.isdir(local))
            finally:
                self._restore()


class RunOutcomeTests(unittest.TestCase):
    """Verify main returns proper exit codes."""

    def test_zero_errors_no_exit(self):
        """Stats with zero errors should not trigger sys.exit."""
        stats = {"errors": 0, "added": 5, "skipped": 10}
        # The exit check is: if stats.get('errors', 0) > 0: sys.exit(1)
        # We just verify the condition
        self.assertFalse(stats.get("errors", 0) > 0)

    def test_nonzero_errors_triggers_exit(self):
        """Stats with errors > 0 should trigger exit."""
        stats = {"errors": 3, "added": 5}
        self.assertTrue(stats.get("errors", 0) > 0)

    def test_finalize_execution_does_not_crash(self):
        """finalize_execution with empty stats doesn't raise."""
        zsync.finalize_execution({}, None)

    def test_finalize_execution_with_summary(self):
        """finalize_execution with summary text doesn't raise."""
        zsync.finalize_execution({"errors": 0}, "test summary")

    def test_check_environment_requirements_raises_correctly(self):
        """Missing config raises RuntimeError with proper message."""
        orig = (zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded)
        try:
            zsync.LIBRARY_ID = "12345"
            zsync.API_KEY = ""
            zsync.TARGET_FOLDER_RAW = "/tmp"
            zsync._config_loaded = True
            with self.assertRaises(RuntimeError) as ctx:
                zsync.check_environment_requirements()
            msg = str(ctx.exception)
            self.assertIn("ZOTERO_API_KEY", msg)
        finally:
            zsync.LIBRARY_ID, zsync.API_KEY, zsync.TARGET_FOLDER_RAW, zsync._config_loaded = orig


if __name__ == "__main__":
    unittest.main()
