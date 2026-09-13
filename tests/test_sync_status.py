import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zotero_sync_webdav as zsync


class SyncStatusTests(unittest.TestCase):
    """Verify the local status snapshot consumed by the Zotero extension."""

    def test_publish_running_status_exposes_progress_and_duplicate_counts(self):
        stats = {
            "sync_started_at": "2026-09-13T15:00:00+00:00",
            "processed": 18,
            "folder_total_pdfs": 40,
            "added": 2,
            "skipped": 16,
            "errors": 1,
            "blocked_duplicate_risk": 3,
            "bibliographic_duplicate_groups": 4,
            "review_tags_applied": 2,
            "auto_duplicate_cleanup_skipped": 1,
            "pending_desktop_imports": ["pending.pdf"],
            "last_error": "Falha ao importar pending.pdf",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            status_file = Path(temp_dir) / "sync_status.json"
            with patch.object(zsync, "SYNC_STATUS_FILE", str(status_file)):
                zsync.publish_sync_status(stats, "running", "Processando PDFs")

            snapshot = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertEqual(snapshot["schemaVersion"], 1)
        self.assertEqual(snapshot["state"], "running")
        self.assertEqual(snapshot["stage"], "Processando PDFs")
        self.assertEqual(snapshot["progress"], {"processed": 18, "total": 40})
        self.assertEqual(
            snapshot["counts"],
            {
                "added": 2,
                "existing": 16,
                "errors": 1,
                "duplicateBlocks": 3,
                "duplicateGroups": 4,
                "duplicateReview": 3,
                "pendingImports": 1,
            },
        )
        self.assertEqual(snapshot["lastError"], "Falha ao importar pending.pdf")

    def test_publish_completed_status_records_completion_time(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status_file = Path(temp_dir) / "sync_status.json"
            with patch.object(zsync, "SYNC_STATUS_FILE", str(status_file)):
                zsync.publish_sync_status(
                    {},
                    "completed",
                    "Sincronização finalizada",
                    "2026-09-13T15:10:00+00:00",
                )

            snapshot = json.loads(status_file.read_text(encoding="utf-8"))

        self.assertEqual(snapshot["state"], "completed")
        self.assertEqual(snapshot["completedAt"], "2026-09-13T15:10:00+00:00")
        self.assertNotIn("lastError", snapshot)

    def test_record_sync_error_preserves_latest_actionable_error(self):
        stats = {"errors": 2}

        zsync.record_sync_error(stats, "Falha ao importar exemplo.pdf")

        self.assertEqual(stats["errors"], 3)
        self.assertEqual(stats["last_error"], "Falha ao importar exemplo.pdf")
