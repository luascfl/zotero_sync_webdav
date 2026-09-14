import tempfile
import unittest
from pathlib import Path

import zotero_sync_webdav as zsync


class WebCachePolicyTests(unittest.TestCase):
    def test_selects_most_recent_candidates_within_budget(self):
        candidates = [
            {"source_attachment_key": "new", "date_added": "2026-09-03T00:00:00Z", "size_bytes": 80},
            {"source_attachment_key": "middle", "date_added": "2026-09-02T00:00:00Z", "size_bytes": 50},
            {"source_attachment_key": "old", "date_added": "2026-09-01T00:00:00Z", "size_bytes": 40},
        ]

        selected, selected_bytes = zsync.select_recent_web_cache_candidates(
            candidates, 120
        )

        self.assertEqual([item["source_attachment_key"] for item in selected], ["new", "old"])
        self.assertEqual(selected_bytes, 120)

    def test_skips_candidate_larger_than_budget(self):
        candidates = [
            {"source_attachment_key": "oversized", "date_added": "2026-09-03T00:00:00Z", "size_bytes": 121},
            {"source_attachment_key": "fits", "date_added": "2026-09-02T00:00:00Z", "size_bytes": 120},
        ]

        selected, selected_bytes = zsync.select_recent_web_cache_candidates(
            candidates, 120
        )

        self.assertEqual([item["source_attachment_key"] for item in selected], ["fits"])
        self.assertEqual(selected_bytes, 120)

    def test_existing_group_storage_file_counts_as_cache_upload(self):
        self.assertTrue(zsync.web_cache_upload_succeeded({"success": [{}]}))
        self.assertTrue(zsync.web_cache_upload_succeeded({"unchanged": [{}]}))
        self.assertFalse(zsync.web_cache_upload_succeeded({"failure": [{}]}))

    def test_upload_uses_basename_with_source_parent_directory(self):
        calls = {}

        class FakeCache:
            @staticmethod
            def _attachment_template(item_type):
                calls["item_type"] = item_type
                return {}

        class FakeUpload:
            def __init__(self, cache_zot, payload, parentid, basedir):
                calls["cache_zot"] = cache_zot
                calls["payload"] = payload
                calls["parentid"] = parentid
                calls["basedir"] = basedir

            @staticmethod
            def upload():
                return {"success": [{}]}

        original_upload = zsync.zotero.Zupload
        zsync.zotero.Zupload = FakeUpload
        try:
            result = zsync.upload_web_cache_attachment(
                FakeCache(), "/source/nested/recent.pdf", "CACHEPARENT"
            )
        finally:
            zsync.zotero.Zupload = original_upload

        self.assertEqual(result, {"success": [{}]})
        self.assertEqual(calls["item_type"], "imported_file")
        self.assertEqual(calls["payload"][0]["title"], "recent.pdf")
        self.assertEqual(calls["payload"][0]["filename"], "recent.pdf")
        self.assertEqual(calls["parentid"], "CACHEPARENT")
        self.assertEqual(calls["basedir"], Path("/source/nested"))

    def test_candidates_require_existing_local_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "available.pdf"
            pdf_path.write_bytes(b"pdf")
            available = {
                "key": "available",
                "data": {
                    "key": "available",
                    "itemType": "attachment",
                    "contentType": "application/pdf",
                    "filename": pdf_path.name,
                    "path": str(pdf_path),
                    "dateAdded": "2026-09-02T00:00:00Z",
                },
            }
            unavailable = {
                "key": "missing",
                "data": {
                    "key": "missing",
                    "itemType": "attachment",
                    "contentType": "application/pdf",
                    "filename": "missing.pdf",
                    "path": "file:///does/not/exist/missing.pdf",
                    "dateAdded": "2026-09-03T00:00:00Z",
                },
            }

            candidates = zsync.build_web_cache_candidates([available, unavailable], {})

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["source_attachment_key"], "available")
        self.assertEqual(candidates[0]["size_bytes"], 3)

    def test_reconciliation_removes_only_marked_stale_cache_items(self):
        selected = [
            {
                "source_attachment_key": "current",
                "source_md5": "current-md5",
            }
        ]
        current = {
            "key": "cache-current",
            "data": {
                "extra": (
                    "Zotero Sync Web Cache source attachment: current\n"
                    "Zotero Sync Web Cache source MD5: current-md5"
                )
            },
        }
        stale = {
            "key": "cache-stale",
            "data": {
                "extra": (
                    "Zotero Sync Web Cache source attachment: old\n"
                    "Zotero Sync Web Cache source MD5: old-md5"
                )
            },
        }
        unmarked = {"key": "manual", "data": {"extra": "manual item"}}

        additions, removals = zsync.plan_web_cache_reconciliation(
            selected, [current, stale, unmarked]
        )

        self.assertEqual(additions, [])
        self.assertEqual([item["key"] for item in removals], ["cache-stale"])


if __name__ == "__main__":
    unittest.main()
