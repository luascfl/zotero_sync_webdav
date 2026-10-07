import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import shutil

import zotero_sync_webdav as zsync
from zotero_sync_webdav import preprocess_drive_duplicate_folders

class TestFolderDeduplication(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dir = tempfile.mkdtemp()
        for name, value in (
            ("QUARANTINE_DIR", os.path.join(self.cache_dir, "quarantine")),
            ("DUPLICATE_ACTIONS_LOG", os.path.join(self.cache_dir, "actions.jsonl")),
        ):
            patcher = patch.object(zsync, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.test_dir)
        shutil.rmtree(self.cache_dir)
        
    def test_deduplicate_identical_pdfs(self):
        # Create identical folders
        dir1 = os.path.join(self.test_dir, "PS0018 - Psicologia")
        dir2 = os.path.join(self.test_dir, "Psicologia")
        os.makedirs(dir1)
        os.makedirs(dir2)
        
        # Add identical PDFs
        pdf1 = os.path.join(dir1, "test.pdf")
        pdf2 = os.path.join(dir2, "test.pdf")
        with open(pdf1, 'wb') as f: f.write(b"content")
        with open(pdf2, 'wb') as f: f.write(b"content")
        
        # Add state file marking dir1 as canonical
        state_file = os.path.join(self.test_dir, ".zotero_folders.json")
        import json
        with open(state_file, 'w') as f:
            json.dump({"KEY1": "PS0018 - Psicologia"}, f)
            
        stats = {}
        preprocess_drive_duplicate_folders(self.test_dir, stats)
        
        # dir2 should be removed, test.pdf should still be in dir1
        self.assertTrue(os.path.exists(dir1))
        self.assertFalse(os.path.exists(dir2))
        self.assertTrue(os.path.exists(pdf1))
        self.assertEqual(stats.get('pruned_drive_duplicates', 0), 1)
        # the removed copy is recoverable from quarantine, not lost
        quarantined = [f for _, _, files in os.walk(os.path.join(self.cache_dir, "quarantine")) for f in files]
        self.assertEqual(len(quarantined), 1)
        self.assertTrue(quarantined[0].endswith("_test.pdf"))

if __name__ == '__main__':
    unittest.main()
