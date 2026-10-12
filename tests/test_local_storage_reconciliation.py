import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zotero_sync_webdav as zsync


class LocalStorageReconciliationTests(unittest.TestCase):
    def test_indexes_only_storage_files_absent_from_api_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = Path(tmp)
            indexed = storage / "APIKNOWN1" / "indexed.pdf"
            pending = storage / "LOCALNEW1" / "pending.pdf"
            indexed.parent.mkdir()
            pending.parent.mkdir()
            indexed.write_bytes(b"already indexed")
            pending.write_bytes(b"awaiting API sync")

            with patch.object(zsync, "LOCAL_COPY_DIR", str(storage)):
                hashes = zsync.build_unindexed_local_storage_hashes({"APIKNOWN1": str(indexed)})

        self.assertEqual(hashes, {hashlib.sha256(b"awaiting API sync").hexdigest()})

    def test_returns_empty_set_when_storage_directory_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing_storage = str(Path(tmp) / "missing")
            with patch.object(zsync, "LOCAL_COPY_DIR", missing_storage):
                hashes = zsync.build_unindexed_local_storage_hashes({})

        self.assertEqual(hashes, set())


if __name__ == "__main__":
    unittest.main()
