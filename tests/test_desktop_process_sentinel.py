"""Regression coverage for desktop imports while Zotero was already running."""
import unittest
from unittest.mock import patch

import zotero_sync_webdav as zsync


class DesktopProcessSentinelTests(unittest.TestCase):
    def test_existing_desktop_leaves_headless_sentinel_defined_and_empty(self):
        previous = zsync._HEADLESS_ZOTERO_PROC
        self.addCleanup(setattr, zsync, "_HEADLESS_ZOTERO_PROC", previous)
        zsync._HEADLESS_ZOTERO_PROC = None

        with patch.object(zsync, "request_local_json", return_value=(200, {})), \
                patch.object(zsync.subprocess, "Popen") as popen:
            available = zsync.ensure_zotero_desktop_connector_running()

        self.assertTrue(available)
        self.assertIsNone(zsync._HEADLESS_ZOTERO_PROC)
        popen.assert_not_called()
        parent_key = None
        auto_recognize = not parent_key and zsync._HEADLESS_ZOTERO_PROC is None
        self.assertTrue(auto_recognize)


if __name__ == "__main__":
    unittest.main()
