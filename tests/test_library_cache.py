"""Tests for US-013: incremental Zotero library snapshot."""
import copy
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import zotero_sync_webdav as zsync


def make_item(key, *, item_type="book", title="", parent=None, date_added="2025-01-01T00:00:00Z", version=1, deleted=None):
    data = {"key": key, "version": version, "itemType": item_type, "title": title, "dateAdded": date_added}
    if parent:
        data["parentItem"] = parent
    if deleted:
        data["deleted"] = 1
    return {"key": key, "version": version, "data": data}


class FakeLibrary:
    """Server-side library with versions; records which requests the cache makes."""

    def __init__(self, items=()):
        self.version = 10
        self.library_type = "users"
        self.library_id = "42"
        self.items_by_key = {}
        self.trash_keys = set()
        self.deleted_keys = []
        self.calls = []
        for item in items:
            self.items_by_key[item["key"]] = copy.deepcopy(item)
        self.fail_incremental = False

    # server-side mutations used by the tests
    def upsert(self, item, trashed=False):
        self.version += 1
        item = copy.deepcopy(item)
        item["version"] = item["data"]["version"] = self.version
        if trashed:
            item["data"]["deleted"] = 1
        self.items_by_key[item["key"]] = item

    def remove_permanently(self, key):
        self.version += 1
        self.items_by_key.pop(key, None)
        self.deleted_keys.append((self.version, key))

    # pyzotero surface
    def last_modified_version(self, **kwargs):
        self.calls.append("version")
        return self.version

    def items(self, since=None, includeTrashed=None, itemType=None, **kwargs):
        self.calls.append(("items", since, includeTrashed))
        if since is not None and self.fail_incremental:
            raise RuntimeError("boom")
        found = []
        for item in self.items_by_key.values():
            if item["data"]["itemType"] == "annotation":
                continue
            if since is not None and item["version"] <= since:
                continue
            if item["data"].get("deleted") and not includeTrashed:
                continue
            found.append(copy.deepcopy(item))
        return found

    def everything(self, results):
        return results

    def deleted(self, since=None, **kwargs):
        self.calls.append(("deleted", since))
        return {"items": [key for version, key in self.deleted_keys if version > since]}


class LibraryCacheTestCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "snapshot.json")

    def cache(self, library, **kwargs):
        return zsync.ZoteroLibraryCache(library, path=self.path, **kwargs)

    def item_fetches(self, library):
        return [call for call in library.calls if isinstance(call, tuple) and call[0] == "items"]


class RefreshTests(LibraryCacheTestCase):
    def test_first_refresh_is_full_and_a_repeat_without_changes_fetches_no_items(self):
        library = FakeLibrary([make_item("A", title="x" * 25)])
        cache = self.cache(library)

        self.assertEqual(cache.refresh(), "full")
        library.calls.clear()
        self.assertEqual(cache.refresh(), "unchanged")

        self.assertEqual(self.item_fetches(library), [])
        self.assertEqual(library.calls, ["version"])

    def test_incremental_applies_edits_trash_and_permanent_deletes(self):
        library = FakeLibrary([
            make_item("EDIT", title="old title " * 3),
            make_item("TRASH", title="to trash " * 4),
            make_item("GONE", title="to delete " * 4),
        ])
        cache = self.cache(library)
        cache.refresh()

        library.upsert(make_item("EDIT", title="new title " * 3))
        library.upsert(make_item("TRASH", title="to trash " * 4), trashed=True)
        library.upsert(make_item("ADDED", title="added later " * 3))
        library.remove_permanently("GONE")

        self.assertEqual(cache.refresh(), "incremental")
        self.assertEqual(set(cache.items), {"EDIT", "ADDED"})
        self.assertTrue(cache.items["EDIT"]["data"]["title"].startswith("new title"))

    def test_item_restored_from_trash_returns_to_the_snapshot(self):
        library = FakeLibrary([make_item("A", title="restore me " * 3)])
        cache = self.cache(library)
        cache.refresh()
        library.upsert(make_item("A", title="restore me " * 3), trashed=True)
        cache.refresh()
        self.assertNotIn("A", cache.items)

        library.upsert(make_item("A", title="restore me " * 3))
        cache.refresh()

        self.assertIn("A", cache.items)

    def test_plain_since_would_miss_trashed_items_so_the_request_asks_for_them(self):
        library = FakeLibrary([make_item("A", title="t" * 25)])
        cache = self.cache(library)
        cache.refresh()
        library.calls.clear()
        library.upsert(make_item("A", title="t" * 25), trashed=True)

        cache.refresh()

        self.assertEqual(self.item_fetches(library), [("items", 10, 1)])

    def test_failed_incremental_falls_back_to_a_full_reload_that_is_still_correct(self):
        library = FakeLibrary([make_item("A", title="a" * 25)])
        cache = self.cache(library)
        cache.refresh()
        library.upsert(make_item("B", title="b" * 25))
        library.fail_incremental = True

        self.assertEqual(cache.refresh(), "full")
        self.assertEqual(set(cache.items), {"A", "B"})

    def test_library_version_going_backwards_forces_a_full_reload(self):
        library = FakeLibrary([make_item("A", title="a" * 25)])
        cache = self.cache(library)
        cache.refresh()
        library.version = 3
        self.assertEqual(cache.refresh(), "full")


class PersistenceTests(LibraryCacheTestCase):
    def test_a_new_instance_resumes_incrementally_from_the_stored_version(self):
        library = FakeLibrary([make_item("A", title="a" * 25)])
        self.cache(library).refresh()
        library.upsert(make_item("B", title="b" * 25))
        library.calls.clear()

        second = self.cache(library)

        self.assertEqual(second.refresh(), "incremental")
        self.assertEqual(self.item_fetches(library), [("items", 10, 1)])
        self.assertEqual(set(second.items), {"A", "B"})

    def test_corrupt_snapshot_is_ignored_and_rebuilt(self):
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        library = FakeLibrary([make_item("A", title="a" * 25)])

        cache = self.cache(library)

        self.assertEqual(cache.refresh(), "full")
        self.assertEqual(set(cache.items), {"A"})
        with open(self.path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["version"], library.version)

    def test_snapshot_from_another_library_or_schema_is_not_trusted(self):
        library = FakeLibrary([make_item("A", title="a" * 25)])
        self.cache(library).refresh()
        with open(self.path, encoding="utf-8") as handle:
            payload = json.load(handle)
        payload["library"] = "users/999"
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)

        self.assertEqual(self.cache(library).refresh(), "full")

    def test_weekly_full_refresh_bounds_drift(self):
        library = FakeLibrary([make_item("A", title="a" * 25)])
        start = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.cache(library, full_refresh_days=7, now=lambda: start).refresh()
        library.upsert(make_item("B", title="b" * 25))

        soon = self.cache(library, full_refresh_days=7, now=lambda: start + timedelta(days=3))
        self.assertEqual(soon.refresh(), "incremental")

        due = self.cache(library, full_refresh_days=7, now=lambda: start + timedelta(days=8))
        self.assertEqual(due.refresh(), "full")


class DerivedListsTests(LibraryCacheTestCase):
    def build(self):
        library = FakeLibrary([
            make_item("OLD", title="older article title " * 2, date_added="2024-01-01T00:00:00Z"),
            make_item("NEW", title="newer article title " * 2, date_added="2026-01-01T00:00:00Z"),
            make_item("ATT_OLD", item_type="attachment", title="a.pdf", parent="OLD", date_added="2024-01-02T00:00:00Z"),
            make_item("ATT_NEW", item_type="attachment", title="b.pdf", parent="NEW", date_added="2026-01-02T00:00:00Z"),
            make_item("NOTE", item_type="note", title="", parent="NEW"),
            make_item("UNTITLED", title=""),
            make_item("ANNOT", item_type="annotation", parent="ATT_NEW"),
        ])
        cache = self.cache(library)
        cache.refresh()
        return cache

    def test_bibliographic_items_are_top_level_titled_non_attachments_newest_first(self):
        keys = [item["key"] for item in self.build().bibliographic_items()]
        self.assertEqual(keys, ["NEW", "OLD"])

    def test_attachments_are_newest_first_and_annotations_are_never_stored(self):
        cache = self.build()
        self.assertEqual([item["key"] for item in cache.attachments()], ["ATT_NEW", "ATT_OLD"])
        self.assertNotIn("ANNOT", cache.items)

    def test_callers_mutating_returned_items_do_not_change_the_snapshot(self):
        cache = self.build()
        returned = cache.attachments()
        returned[0]["data"]["title"] = "mutated by caller"
        returned[0]["_timestamp"] = 1.0

        again = cache.attachments()
        self.assertEqual(again[0]["data"]["title"], "b.pdf")
        self.assertNotIn("_timestamp", again[0])


class CollectorFallbackTests(unittest.TestCase):
    def test_attachment_collector_uses_the_legacy_listing_when_the_snapshot_fails(self):
        legacy = ([make_item("L", item_type="attachment", title="x.pdf")], {"x": 1}, {"x": 1})
        with patch.object(zsync, "get_library_cache", side_effect=RuntimeError("no snapshot")), \
                patch.object(zsync, "collect_all_attachments_full", return_value=legacy) as full:
            result = zsync.collect_all_attachments(object(), {})
        full.assert_called_once()
        self.assertIs(result, legacy)

    def test_bibliographic_collector_uses_the_legacy_listing_when_the_snapshot_fails(self):
        stats = {}
        with patch.object(zsync, "get_library_cache", side_effect=RuntimeError("no snapshot")), \
                patch.object(zsync, "collect_all_bibliographic_items_full", return_value=[make_item("B", title="t" * 25)]):
            items = zsync.collect_all_bibliographic_items(object(), stats)
        self.assertEqual([item["key"] for item in items], ["B"])
        self.assertEqual(stats["zotero_bibliographic_scanned"], 1)


if __name__ == "__main__":
    unittest.main()
