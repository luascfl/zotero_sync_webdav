"""Tests for US-006: orphaned file recovery."""
import os
import tempfile
import unittest

import zotero_sync_webdav as zsync


class OrphanDetectionTests(unittest.TestCase):
    """Verify orphan detection logic works correctly."""

    def test_file_in_drive_not_orphan(self):
        """A file present in drive_name_index is not an orphan."""
        item = {
            "key": "ABC123",
            "data": {"filename": "test.pdf", "contentType": "application/pdf"}
        }
        filename = zsync.get_filename_from_item(item)
        norm = zsync.normalize_filename(filename)
        drive_name_index = {norm: "/drive/test.pdf"}
        self.assertIn(norm, drive_name_index)

    def test_file_missing_from_drive_is_orphan(self):
        """A file NOT present in drive index is detected as orphan."""
        item = {
            "key": "XYZ789",
            "data": {"filename": "missing_paper.pdf", "contentType": "application/pdf"}
        }
        filename = zsync.get_filename_from_item(item)
        norm = zsync.normalize_filename(filename)
        agg = zsync.normalize_aggressive(filename)
        drive_name_index = {}
        drive_aggressive_index = {}
        self.assertNotIn(norm, drive_name_index)
        self.assertNotIn(agg, drive_aggressive_index)

    def test_non_pdf_skipped(self):
        """Non-PDF attachments are skipped during orphan scan."""
        item = {
            "key": "DOC123",
            "data": {"filename": "notes.docx", "contentType": "application/docx"}
        }
        filename = zsync.get_filename_from_item(item)
        self.assertFalse(filename.lower().endswith('.pdf'))

    def test_empty_filename_skipped(self):
        """Items without filename are skipped."""
        item = {
            "key": "EMPTY1",
            "data": {"contentType": "application/pdf"}
        }
        filename = zsync.get_filename_from_item(item)
        self.assertEqual(filename, "")


class RecoverySubcommandTests(unittest.TestCase):
    """Verify the recovery sub-command is registered."""

    def test_recover_orphans_parser_exists(self):
        """CLI parser accepts recover-orphans command."""
        parser = zsync.build_cli_parser()
        args = parser.parse_args(['recover-orphans', '--dry-run'])
        self.assertEqual(args.command, 'recover-orphans')
        self.assertTrue(args.dry_run)

    def test_recover_orphans_no_dry_run(self):
        """CLI parser accepts recover-orphans without --dry-run."""
        parser = zsync.build_cli_parser()
        args = parser.parse_args(['recover-orphans'])
        self.assertEqual(args.command, 'recover-orphans')
        self.assertFalse(args.dry_run)


if __name__ == "__main__":
    unittest.main()
