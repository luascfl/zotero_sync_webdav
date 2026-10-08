"""Zotero updates must never send read-only fields such as lastRead (pyzotero rejects them)."""
import unittest

import zotero_sync_webdav as zsync


class RecordingZotero:
    """Mimics pyzotero: update_item rejects read-only keys instead of ignoring them."""

    def __init__(self, item):
        self.stored = item
        self.sent = []

    def item(self, key):
        return self.stored

    def update_item(self, payload, last_modified=None):
        bad = set(payload) & zsync.ZOTERO_READONLY_UPDATE_FIELDS
        if bad:
            raise ValueError(f"Invalid keys present in item 1: {', '.join(sorted(bad))}")
        self.sent.append(payload)
        self.stored = {"key": payload.get("key"), "data": dict(payload)}
        return True


def attachment(**extra):
    data = {
        "key": "ATT1", "version": 3, "itemType": "attachment", "linkMode": "imported_file",
        "filename": "Cópia de Doc.pdf", "title": "Cópia de Doc.pdf", "collections": [],
        "lastRead": "2026-10-07T00:00:00Z", "dateAdded": "2025-01-01T00:00:00Z",
        "dateModified": "2026-10-01T00:00:00Z", **extra,
    }
    return {"key": "ATT1", "data": data}


class UpdatePayloadSanitizingTests(unittest.TestCase):
    def test_attachment_rename_succeeds_for_an_item_carrying_lastread(self):
        zot = RecordingZotero(attachment())

        renamed = zsync.update_zotero_attachment_filename(zot, "ATT1", "Doc.pdf")

        self.assertTrue(renamed)
        (sent,) = zot.sent
        self.assertEqual(sent["filename"], "Doc.pdf")
        self.assertFalse(set(sent) & zsync.ZOTERO_READONLY_UPDATE_FIELDS)

    def test_collection_membership_update_succeeds_for_an_item_carrying_lastread(self):
        zot = RecordingZotero(attachment())

        added = zsync.update_item_collection_membership(zot, "ATT1", "COL1")

        self.assertTrue(added)
        (sent,) = zot.sent
        self.assertEqual(sent["collections"], ["COL1"])
        self.assertFalse(set(sent) & zsync.ZOTERO_READONLY_UPDATE_FIELDS)


if __name__ == "__main__":
    unittest.main()
