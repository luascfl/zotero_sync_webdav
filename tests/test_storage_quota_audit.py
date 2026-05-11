import importlib
import os
import tempfile
import unittest
from pathlib import Path


_TEMP_DIR = tempfile.TemporaryDirectory()
_TARGET_DIR = Path(_TEMP_DIR.name) / "target"
_TARGET_DIR.mkdir()
_ENV_FILE = Path(_TEMP_DIR.name) / "zotero_sync.env"
_ENV_FILE.write_text(
    "ZOTERO_LIBRARY_ID=1\n"
    "ZOTERO_LIBRARY_TYPE=user\n"
    "ZOTERO_API_KEY=dummy\n"
    f"ZOTERO_SYNC_TARGET_FOLDER={_TARGET_DIR}\n",
    encoding="utf-8",
)
os.environ["ZOTERO_ENV_FILE"] = str(_ENV_FILE)

audit = importlib.import_module("zotero_storage_quota_audit")


class StorageQuotaAuditTests(unittest.TestCase):
    def test_human_size_formats_units(self):
        self.assertEqual(audit.human_size(512), "512 B")
        self.assertEqual(audit.human_size(2048), "2.0 KB")
        self.assertEqual(audit.human_size(1024 * 1024), "1.0 MB")
        self.assertEqual(audit.human_size(None), "desconhecido")

    def test_counts_toward_remote_storage(self):
        self.assertTrue(audit.counts_toward_remote_storage({"data": {"linkMode": "imported_file"}}))
        self.assertTrue(audit.counts_toward_remote_storage({"data": {"linkMode": "imported_url"}}))
        self.assertFalse(audit.counts_toward_remote_storage({"data": {"linkMode": "linked_file"}}))
        self.assertFalse(audit.counts_toward_remote_storage({"data": {"linkMode": "linked_url"}}))

    def test_resolve_attachment_local_path_uses_linked_file_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "arquivo.pdf"
            file_path.write_bytes(b"pdf")
            item = {
                "key": "ATT1",
                "data": {
                    "key": "ATT1",
                    "itemType": "attachment",
                    "linkMode": "linked_file",
                    "contentType": "application/pdf",
                    "path": str(file_path),
                    "title": "arquivo.pdf",
                },
            }
            self.assertEqual(audit.resolve_attachment_local_path(item), str(file_path))

    def test_build_attachment_audit_row_inherits_parent_metadata(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "arquivo.pdf"
            file_path.write_bytes(b"12345")
            item = {
                "key": "ATT1",
                "data": {
                    "key": "ATT1",
                    "itemType": "attachment",
                    "linkMode": "linked_file",
                    "contentType": "application/pdf",
                    "path": str(file_path),
                    "title": "arquivo.pdf",
                    "parentItem": "PARENT1",
                },
            }
            parents = {
                "PARENT1": {
                    "data": {
                        "title": "Artigo X",
                        "collections": ["COL1"],
                    }
                }
            }
            row = audit.build_attachment_audit_row(item, parents)
            self.assertEqual(row["parent_title"], "Artigo X")
            self.assertEqual(row["collections"], ["COL1"])
            self.assertTrue(row["local_exists"])
            self.assertEqual(row["size_bytes"], 5)

    def test_summarize_rows_accumulates_remote_sizes(self):
        rows = [
            {
                "link_mode": "imported_file",
                "size_bytes": 100,
                "counts_toward_remote_storage": True,
            },
            {
                "link_mode": "imported_file",
                "size_bytes": None,
                "counts_toward_remote_storage": True,
            },
            {
                "link_mode": "linked_file",
                "size_bytes": 500,
                "counts_toward_remote_storage": False,
            },
        ]
        summary = audit.summarize_rows(rows)
            
        self.assertEqual(summary["attachment_total"], 3)
        self.assertEqual(summary["remote_storage_total_bytes"], 100)
        self.assertEqual(summary["remote_storage_known_size_count"], 1)
        self.assertEqual(summary["remote_storage_missing_local_count"], 1)
        self.assertEqual(summary["mode_breakdown"]["imported_file"]["count"], 2)
        self.assertEqual(summary["mode_breakdown"]["linked_file"]["total_size_bytes"], 500)


if __name__ == "__main__":
    unittest.main()
