import unittest
import os
import tempfile
from pathlib import Path

import zotero_sync_webdav as zsync

class ComputeSha256QuarantineTests(unittest.TestCase):
    def test_compute_sha256_quarantine(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test.txt"
            file_path.write_text("dummy")

            cache = {}
            # Simulate a quarantine hit
            stat = file_path.stat()
            zsync.set_cached_hash(str(file_path), "QUARANTINE_TIMEOUT", cache, stat)

            # Ensure it returns None when hitting quarantine
            result = zsync.compute_sha256(str(file_path), cache=cache)
            self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
