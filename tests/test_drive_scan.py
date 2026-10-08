"""Tests for US-012: one drive scan per sync run, never a stale one."""
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import zotero_sync_webdav as zsync


class DriveScanTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def write(self, relative, content=b"x"):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_repeated_reads_walk_the_drive_once(self):
        self.write("A/one.pdf")
        scan = zsync.DriveScan(self.root, {})
        with patch.object(zsync, "collect_all_pdfs", wraps=zsync.collect_all_pdfs) as walk:
            first = scan.paths()
            second = scan.paths()
            third = scan.paths()
        self.assertEqual(walk.call_count, 1)
        self.assertEqual(scan.scans, 1)
        self.assertIs(first, second)
        self.assertIs(second, third)

    def test_invalidate_forces_a_fresh_walk_that_no_longer_lists_a_removed_file(self):
        keep = self.write("A/keep.pdf")
        gone = self.write("A/gone.pdf")
        scan = zsync.DriveScan(self.root, {})
        self.assertCountEqual(scan.paths(), [keep, gone])

        os.remove(gone)
        scan.invalidate()

        self.assertEqual(scan.paths(), [keep])
        self.assertEqual(scan.scans, 2)

    def test_replace_installs_a_processed_list_without_another_walk(self):
        a = self.write("A/a.pdf")
        scan = zsync.DriveScan(self.root, {})
        scan.paths()
        renamed = os.path.join(self.root, "A", "b.pdf")
        os.rename(a, renamed)

        scan.replace([renamed])

        self.assertEqual(scan.paths(), [renamed])
        self.assertEqual(scan.scans, 1)

    def test_name_path_indexes_use_the_given_scan_instead_of_walking(self):
        path = self.write("Col/Doc.pdf")
        with patch.object(zsync, "collect_all_pdfs", side_effect=AssertionError("não deve varrer")):
            name, aggressive, rel, rel_aggressive = zsync.build_drive_name_path_indexes(self.root, [path])
        self.assertEqual(name[zsync.normalize_filename("Doc.pdf")], path)
        self.assertEqual(rel[zsync.normalize_relative_path_key("Col/Doc.pdf")], path)

    def test_name_path_indexes_still_walk_when_no_scan_is_given(self):
        path = self.write("Col/Doc.pdf")
        name, *_ = zsync.build_drive_name_path_indexes(self.root)
        self.assertEqual(name[zsync.normalize_filename("Doc.pdf")], path)


if __name__ == "__main__":
    unittest.main()
