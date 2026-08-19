import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import shutil

from zotero_sync_webdav import preprocess_drive_duplicate_folders

class TestFolderDeduplication(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
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

if __name__ == '__main__':
    unittest.main()
