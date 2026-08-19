import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import zotero_sync_webdav as zsync


def make_collection(key, name, parent=None, version=1):
    return {
        "key": key,
        "version": version,
        "data": {
            "name": name,
            "parentCollection": parent,
        },
    }


class FakeZotero:
    def __init__(self, nonempty_keys=None, delete_statuses=None):
        self.nonempty_keys = set(nonempty_keys or [])
        self.delete_statuses = dict(delete_statuses or {})
        self.collection_item_calls = []
        self.deleted_payloads = []

    def collection_items(self, key, limit=1):
        self.collection_item_calls.append((key, limit))
        if key in self.nonempty_keys:
            return [{"key": f"ITEM-{key}"}]
        return []

    def delete_collection(self, payload):
        self.deleted_payloads.append(payload)
        status_code = self.delete_statuses.get(payload["key"], 204)
        return SimpleNamespace(status_code=status_code)


class DuplicateCollectionCleanupTests(unittest.TestCase):
    def test_normalize_duplicate_collection_core_name_collapses_cosmetic_variants(self):
        normalized = {
            zsync.normalize_duplicate_collection_core_name(name)
            for name in [
                "AB1234 - Recibos／materiais de eventos",
                "Recibos／materiais de eventos [Lucas]",
                "Recibos／materiais de eventos",
            ]
        }

        self.assertEqual(normalized, {"recibosmateriais de eventos"})

    def test_cleanup_deletes_only_empty_bracketed_duplicate_when_single_sibling_has_items(self):
        zot = FakeZotero(nonempty_keys={"KEEP"})
        collections = [
            make_collection("KEEP", "Recibos／materiais de eventos", version=3),
            make_collection("DROP", "Recibos／materiais de eventos [Lucas]", version=7),
            make_collection("OTHER", "Outra coleção", version=2),
        ]
        stats = {}

        changed = zsync.cleanup_empty_duplicate_zotero_collections(zot, collections, stats)

        self.assertTrue(changed)
        self.assertEqual(zot.deleted_payloads, [{"key": "DROP", "version": 7}])
        self.assertCountEqual(zot.collection_item_calls, [("KEEP", 1), ("DROP", 1)])
        self.assertEqual(stats["deleted_empty_duplicate_collections"], 1)
        self.assertEqual(stats["skipped_empty_duplicate_collections"], 0)

    def test_cleanup_keeps_empty_duplicate_when_multiple_siblings_have_items(self):
        zot = FakeZotero(nonempty_keys={"KEEP1", "KEEP2"})
        collections = [
            make_collection("KEEP1", "Seminário de Pesquisa", version=1),
            make_collection("KEEP2", "AB1234 - Seminário de Pesquisa", version=2),
            make_collection("EMPTY", "Seminário de Pesquisa [Lucas]", version=3),
        ]
        stats = {}

        changed = zsync.cleanup_empty_duplicate_zotero_collections(zot, collections, stats)

        self.assertFalse(changed)
        self.assertEqual(zot.deleted_payloads, [])
        self.assertCountEqual(
            zot.collection_item_calls,
            [("KEEP1", 1), ("KEEP2", 1), ("EMPTY", 1)],
        )
        self.assertEqual(stats["deleted_empty_duplicate_collections"], 0)
        self.assertEqual(stats["skipped_empty_duplicate_collections"], 0)

    def test_cleanup_keeps_duplicate_that_has_child_collections(self):
        zot = FakeZotero(nonempty_keys={"KEEP"})
        collections = [
            make_collection("KEEP", "Projeto Integrador", version=1),
            make_collection("PARENT", "Projeto Integrador [Lucas]", version=2),
            make_collection("CHILD", "Subpasta", parent="PARENT", version=1),
        ]
        stats = {}

        changed = zsync.cleanup_empty_duplicate_zotero_collections(zot, collections, stats)

        self.assertFalse(changed)
        self.assertEqual(zot.deleted_payloads, [])
        self.assertEqual(zot.collection_item_calls, [("KEEP", 1)])
        self.assertEqual(stats["deleted_empty_duplicate_collections"], 0)
        self.assertEqual(stats["skipped_empty_duplicate_collections"], 0)


class DriveRenameMergeTests(unittest.TestCase):
    def test_merge_drive_renamed_collections_deletes_drained_old_sibling_and_empty_dir(self):
        collections = [
            make_collection("PARENT", "UNEB Psicologia 2026.1", version=1),
            make_collection("OLD", "Disciplina Antiga", parent="PARENT", version=7),
            make_collection("NEW", "Disciplina Renomeada", parent="PARENT", version=3),
        ]
        zot = FakeZotero()
        move_evidence = {("OLD", "NEW"): {"ITEM-1", "ITEM-2"}}
        stats = {}

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_dir = root / "UNEB Psicologia 2026.1" / "Disciplina Antiga"
            new_dir = root / "UNEB Psicologia 2026.1" / "Disciplina Renomeada"
            old_dir.mkdir(parents=True)
            new_dir.mkdir(parents=True)
            (new_dir / "artigo.pdf").write_bytes(b"x")

            changed = zsync.merge_drive_renamed_collections(
                zot,
                collections,
                temp_dir,
                move_evidence,
                stats,
            )

            self.assertTrue(changed)
            self.assertEqual(zot.deleted_payloads, [{"key": "OLD", "version": 7}])
            self.assertEqual(zot.collection_item_calls, [("OLD", 1)])
            self.assertFalse(old_dir.exists())
            self.assertTrue(new_dir.exists())
            self.assertEqual(stats["merged_drive_renamed_collections"], 1)
            self.assertEqual(stats["skipped_drive_renamed_collections"], 0)

    def test_merge_drive_renamed_collections_skips_ambiguous_fanout(self):
        collections = [
            make_collection("PARENT", "UNEB Psicologia 2026.1", version=1),
            make_collection("OLD", "Disciplina Antiga", parent="PARENT", version=7),
            make_collection("NEW1", "Disciplina Renomeada", parent="PARENT", version=3),
            make_collection("NEW2", "Disciplina Final", parent="PARENT", version=4),
        ]
        zot = FakeZotero()
        stats = {}

        changed = zsync.merge_drive_renamed_collections(
            zot,
            collections,
            "/tmp/unused",
            {
                ("OLD", "NEW1"): {"ITEM-1"},
                ("OLD", "NEW2"): {"ITEM-2"},
            },
            stats,
        )

        self.assertFalse(changed)
        self.assertEqual(zot.deleted_payloads, [])
        self.assertEqual(zot.collection_item_calls, [])
        self.assertEqual(stats["merged_drive_renamed_collections"], 0)
        self.assertEqual(stats["skipped_drive_renamed_collections"], 1)


class RegisteredFoldersStateTests(unittest.TestCase):
    def test_sync_registered_folders_state_writes_current_collection_paths(self):
        collection_by_key = {
            "ROOT": {"relative_path": "UNEB Psicologia 2026.1"},
            "CHILD": {"relative_path": "UNEB Psicologia 2026.1/Disciplina Renomeada"},
            "IGNORED": {"relative_path": ""},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            zsync.sync_registered_folders_state(temp_dir, collection_by_key)
            state_file = Path(temp_dir) / ".zotero_folders.json"

            self.assertEqual(
                json.loads(state_file.read_text(encoding="utf-8")),
                {
                    "CHILD": "UNEB Psicologia 2026.1/Disciplina Renomeada",
                    "ROOT": "UNEB Psicologia 2026.1",
                },
            )


if __name__ == "__main__":
    unittest.main()
