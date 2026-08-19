"""Regression tests for pending Zotero Desktop import queue files."""
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import zotero_sync_webdav as zsync


class PendingImportQueueTests(unittest.TestCase):
    """Verify pending import queue artifacts are logged and cleared without a txt queue file."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.log_dir = Path(self.tempdir.name)
        self.pending_file = self.log_dir / "zotero_pending_imports.txt"
        self.pending_log = self.log_dir / zsync.PENDING_IMPORTS_LOG_FILE_NAME
        self.pending_log_date_file = self.log_dir / ".last_pending_imports_log_date"

        self._orig_log_dir = zsync.LOG_DIR
        self._orig_pending_log_date_file = zsync.PENDING_IMPORTS_LOG_DATE_FILE
        zsync.LOG_DIR = str(self.log_dir)
        zsync.PENDING_IMPORTS_LOG_DATE_FILE = str(self.pending_log_date_file)

        self.notify_patcher = patch.object(zsync, "send_desktop_notification")
        self.mock_send_desktop_notification = self.notify_patcher.start()

    def tearDown(self):
        self.notify_patcher.stop()
        zsync.LOG_DIR = self._orig_log_dir
        zsync.PENDING_IMPORTS_LOG_DATE_FILE = self._orig_pending_log_date_file
        self.tempdir.cleanup()

    def test_non_empty_pending_updates_daily_log_without_txt_queue_file(self):
        """A non-empty queue appends timestamped snapshots while the txt artifact stays absent."""
        first_pending = ["alpha.pdf"]
        second_pending = ["alpha.pdf", "beta.pdf"]

        with patch.object(zsync, "datetime") as mock_datetime:
            mock_datetime.now.side_effect = [
                datetime(2026, 7, 9, 9, 30, 0),
                datetime(2026, 7, 9, 9, 30, 0),
                datetime(2026, 7, 9, 11, 45, 30),
                datetime(2026, 7, 9, 11, 45, 30),
            ]
            zsync.update_pending_import_queue_files(first_pending)
            self.assertFalse(self.pending_file.exists())
            zsync.update_pending_import_queue_files(second_pending)

        self.assertFalse(self.pending_file.exists())

        log_text = self.pending_log.read_text(encoding="utf-8")
        self.assertEqual(
            log_text.count("# Log diário da fila do Zotero fechado - 2026-07-09"),
            1,
        )
        self.assertIn("--- Fila atualizada: 2026-07-09T09:30:00 ---", log_text)
        self.assertIn("Pendentes: 1", log_text)
        self.assertIn("- alpha.pdf", log_text)
        self.assertIn("--- Fila atualizada: 2026-07-09T11:45:30 ---", log_text)
        self.assertIn("Pendentes: 2", log_text)
        self.assertIn("- beta.pdf", log_text)
        self.assertEqual(self.pending_log_date_file.read_text(encoding="utf-8"), "2026-07-09")

    def test_pending_queue_notification_uses_zotero_fechado_summary(self):
        """A queue notification keeps its dedicated title instead of reusing the completion wording."""
        with patch.object(zsync, "datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2026, 7, 9, 14, 0, 0)
            zsync.update_pending_import_queue_files(["gamma.pdf"])

        self.assertEqual(zsync.PENDING_QUEUE_NOTIFICATION_SUMMARY, "Zotero fechado")
        self.assertNotEqual(
            zsync.PENDING_QUEUE_NOTIFICATION_SUMMARY,
            zsync.COMPLETION_NOTIFICATION_SUMMARY,
        )
        self.mock_send_desktop_notification.assert_called_once_with(
            "Zotero fechado",
            "1 PDF novo está na fila. Abra o Zotero para sincronizá-lo.",
            icon="zotero",
        )

    def test_empty_pending_clears_pending_log_artifacts_without_txt_queue_file(self):
        """An empty queue removes the pending log artifacts and never leaves a txt queue file behind."""
        with patch.object(zsync, "datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2026, 7, 9, 14, 0, 0)
            zsync.update_pending_import_queue_files(["gamma.pdf"])

        self.assertFalse(self.pending_file.exists())
        self.assertTrue(self.pending_log.exists())
        self.assertTrue(self.pending_log_date_file.exists())

        zsync.update_pending_import_queue_files([])

        self.assertFalse(self.pending_file.exists())
        self.assertFalse(self.pending_log.exists())
        self.assertFalse(self.pending_log_date_file.exists())


if __name__ == "__main__":
    unittest.main()
