"""Tests for US-010: quarantine and audit trail for duplicate file removal."""
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import zotero_sync_webdav as zsync


class QuarantineTestCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.quarantine = os.path.join(self.work, "cache", "quarantine")
        self.actions_log = os.path.join(self.work, "cache", "duplicate_actions.jsonl")
        for name, value in (
            ("QUARANTINE_DIR", self.quarantine),
            ("DUPLICATE_ACTIONS_LOG", self.actions_log),
        ):
            patcher = patch.object(zsync, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def make_pdf(self, relative, content=b"%PDF-content"):
        path = os.path.join(self.work, "drive", relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def audit_lines(self):
        if not os.path.exists(self.actions_log):
            return []
        with open(self.actions_log, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]


class QuarantineFileTests(QuarantineTestCase):
    def test_quarantine_moves_file_with_matching_content_and_audit_line(self):
        victim = self.make_pdf("B/Doc.pdf", b"same bytes")
        kept = self.make_pdf("A/Doc.pdf", b"same bytes")

        result = zsync.quarantine_file(
            victim, action="redundant_drive_duplicate", reason="same_hash", kept_path=kept,
        )

        self.assertFalse(os.path.exists(victim))
        self.assertTrue(os.path.exists(kept))
        with open(result, "rb") as handle:
            self.assertEqual(handle.read(), b"same bytes")
        (line,) = self.audit_lines()
        self.assertEqual(line["path"], victim)
        self.assertEqual(line["kept_path"], kept)
        self.assertEqual(line["quarantine_path"], result)
        self.assertEqual(line["reason"], "same_hash")
        self.assertEqual(len(line["sha256"]), 64)

    def test_same_filename_twice_in_one_day_keeps_both_copies(self):
        first = self.make_pdf("B/Doc.pdf", b"one")
        second = self.make_pdf("C/Doc.pdf", b"one")
        a = zsync.quarantine_file(first, action="x", reason="r")
        b = zsync.quarantine_file(second, action="x", reason="r")
        self.assertNotEqual(a, b)
        self.assertTrue(os.path.exists(a) and os.path.exists(b))

    def test_failed_removal_leaves_original_and_no_partial_copy_or_audit(self):
        victim = self.make_pdf("B/Doc.pdf", b"keep me")
        real_remove = os.remove

        def fail_on_victim(path, *args, **kwargs):
            if path == victim:
                raise PermissionError("denied")
            return real_remove(path, *args, **kwargs)

        with patch("zotero_sync_webdav.os.remove", side_effect=fail_on_victim):
            result = zsync.quarantine_file(victim, action="x", reason="r")

        self.assertIsNone(result)
        self.assertTrue(os.path.exists(victim))
        self.assertEqual(self.audit_lines(), [])
        leftovers = [f for _, _, files in os.walk(self.quarantine) for f in files]
        self.assertEqual(leftovers, [])

    def test_corrupted_copy_aborts_and_keeps_original(self):
        victim = self.make_pdf("B/Doc.pdf", b"original")
        real_copy = shutil.copy2

        def corrupting_copy(src, dst, *args, **kwargs):
            real_copy(src, dst, *args, **kwargs)
            with open(dst, "ab") as handle:
                handle.write(b"garbage")

        with patch("zotero_sync_webdav.shutil.copy2", side_effect=corrupting_copy):
            result = zsync.quarantine_file(victim, action="x", reason="r")

        self.assertIsNone(result)
        self.assertTrue(os.path.exists(victim))
        self.assertEqual(self.audit_lines(), [])


class PurgeQuarantineTests(QuarantineTestCase):
    def test_purge_removes_only_expired_date_directories(self):
        today = datetime(2026, 10, 7)
        old = (today - timedelta(days=45)).strftime("%Y-%m-%d")
        recent = (today - timedelta(days=5)).strftime("%Y-%m-%d")
        for name in (old, recent, "not-a-date"):
            os.makedirs(os.path.join(self.quarantine, name))
            with open(os.path.join(self.quarantine, name, "f.pdf"), "wb") as handle:
                handle.write(b"x")

        purged = zsync.purge_quarantine(retention_days=30, today=today)

        self.assertEqual(purged, 1)
        self.assertFalse(os.path.exists(os.path.join(self.quarantine, old)))
        self.assertTrue(os.path.exists(os.path.join(self.quarantine, recent, "f.pdf")))
        self.assertTrue(os.path.exists(os.path.join(self.quarantine, "not-a-date", "f.pdf")))

    def test_purge_without_quarantine_directory_is_noop(self):
        self.assertEqual(zsync.purge_quarantine(), 0)


class RedundantDuplicateRemovalTests(QuarantineTestCase):
    def test_redundant_copy_is_quarantined_and_canonical_survives(self):
        canonical = self.make_pdf("A/Doc.pdf", b"same")
        redundant = self.make_pdf("A/Cópia de Doc.pdf", b"same")

        self.assertTrue(zsync.delete_redundant_webdav_duplicate(redundant, canonical))

        self.assertTrue(os.path.exists(canonical))
        self.assertFalse(os.path.exists(redundant))
        (line,) = self.audit_lines()
        self.assertEqual(line["kept_path"], canonical)
        self.assertTrue(os.path.exists(line["quarantine_path"]))

    def test_different_content_is_never_removed_or_quarantined(self):
        canonical = self.make_pdf("A/Doc.pdf", b"one")
        other = self.make_pdf("A/Cópia de Doc.pdf", b"two")

        self.assertFalse(zsync.delete_redundant_webdav_duplicate(other, canonical))

        self.assertTrue(os.path.exists(other))
        self.assertEqual(self.audit_lines(), [])

    def test_quarantine_failure_keeps_redundant_copy_and_reports_failure(self):
        canonical = self.make_pdf("A/Doc.pdf", b"same")
        redundant = self.make_pdf("A/Cópia de Doc.pdf", b"same")

        with patch("zotero_sync_webdav.quarantine_file", return_value=None):
            self.assertFalse(zsync.delete_redundant_webdav_duplicate(redundant, canonical))

        self.assertTrue(os.path.exists(redundant))


if __name__ == "__main__":
    unittest.main()
