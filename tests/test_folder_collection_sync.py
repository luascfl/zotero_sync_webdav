"""Sincronização bidirecional pasta do drive <> coleção Zotero, com Zotero falso e pastas temporárias."""

import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_TEMP = tempfile.TemporaryDirectory()
_TARGET = Path(_TEMP.name) / "target"
_TARGET.mkdir()
_ENV = Path(_TEMP.name) / "zotero_sync.env"
_ENV.write_text(
    "ZOTERO_LIBRARY_ID=1\nZOTERO_LIBRARY_TYPE=user\nZOTERO_API_KEY=dummy\n"
    f"ZOTERO_SYNC_TARGET_FOLDER={_TARGET}\n",
    encoding="utf-8",
)
os.environ["ZOTERO_ENV_FILE"] = str(_ENV)
zsync = importlib.import_module("zotero_sync_webdav")


def make_collection(key, name, parent=None, version=1):
    return {"key": key, "version": version, "data": {
        "key": key, "version": version, "name": name, "parentCollection": parent or False,
    }}


class FakeZotero:
    def __init__(self, nonempty=(), update_status=204, delete_status=204):
        self.nonempty = set(nonempty)
        self.update_status = update_status
        self.delete_status = delete_status
        self.updated = []
        self.deleted = []

    def collection_items(self, key, limit=1):
        return [{"key": "ITEM"}] if key in self.nonempty else []

    def update_collection(self, payload):
        self.updated.append(payload)
        return SimpleNamespace(status_code=self.update_status)

    def delete_collection(self, payload):
        self.deleted.append(payload)
        return SimpleNamespace(status_code=self.delete_status)


def new_stats():
    return {name: 0 for name in (
        "folder_sync_drive_renames", "folder_sync_collection_renames",
        "folder_sync_collection_deletes", "folder_sync_conflicts", "folder_sync_errors",
    )}


class FolderSyncCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "vault"
        self.root.mkdir()
        audit = Path(self.tmp.name) / "audit.jsonl"
        patcher = mock.patch.object(zsync, "DUPLICATE_ACTIONS_LOG", str(audit))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.audit = audit
        patcher = mock.patch.dict(zsync.HASH_CACHE, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(zsync, "fetch_zotero_collections")
        self.fetch = patcher.start()
        self.addCleanup(patcher.stop)

    def pdf(self, rel, content=b"x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def ledger(self, mapping):
        (self.root / ".zotero_folders.json").write_text(json.dumps(mapping), encoding="utf-8")

    def plan(self, collections, ledger, names=None):
        by_key, _children, path_to_key = zsync.build_collection_path_model(collections)
        return zsync.plan_collection_folder_actions(by_key, ledger, self.root, names or {}, path_to_key)

    def audit_actions(self):
        if not self.audit.exists():
            return []
        return [json.loads(line)["action"] for line in self.audit.read_text().splitlines()]


class ZoteroSideRenameTests(FolderSyncCase):
    def test_collection_renamed_in_zotero_renames_the_directory_and_keeps_the_hash_cache(self):
        pdf = self.pdf("Antiga/a.pdf", b"conteudo")
        old_key = zsync._normalize_cache_path(str(pdf))
        zsync.HASH_CACHE[old_key] = {"hash": "h"}
        collections = [make_collection("K1", "Nova")]
        actions = self.plan(collections, {"K1": "Antiga"})
        self.assertEqual([a["type"] for a in actions], ["rename_drive_dir"])

        stats = new_stats()
        drive_changed, collections_changed = zsync.apply_collection_folder_actions(
            FakeZotero(), actions, collections, self.root, stats)

        self.assertTrue(drive_changed)
        self.assertFalse(collections_changed)
        self.assertFalse((self.root / "Antiga").exists())
        self.assertEqual((self.root / "Nova" / "a.pdf").read_bytes(), b"conteudo")
        new_key = zsync._normalize_cache_path(str(self.root / "Nova" / "a.pdf"))
        self.assertEqual(zsync.HASH_CACHE.get(new_key), {"hash": "h"})
        self.assertNotIn(old_key, zsync.HASH_CACHE)
        self.assertEqual(stats["folder_sync_drive_renames"], 1)
        self.assertEqual(self.audit_actions(), ["folder_rename"])

    def test_renaming_a_parent_is_one_operation_and_children_follow(self):
        self.pdf("Pai/Filho/a.pdf")
        collections = [make_collection("P", "Pai Novo"), make_collection("C", "Filho", parent="P")]
        actions = self.plan(collections, {"P": "Pai", "C": "Pai/Filho"})
        self.assertEqual([(a["type"], a["old"], a["new"]) for a in actions],
                         [("rename_drive_dir", "Pai", "Pai Novo")])

        zsync.apply_collection_folder_actions(FakeZotero(), actions, collections, self.root, new_stats())
        self.assertTrue((self.root / "Pai Novo" / "Filho" / "a.pdf").exists())

    def test_existing_destination_with_files_is_a_conflict_and_nothing_moves(self):
        self.pdf("Antiga/a.pdf")
        self.pdf("Nova/b.pdf")
        collections = [make_collection("K1", "Nova")]
        stats = new_stats()
        zsync.apply_collection_folder_actions(
            FakeZotero(), self.plan(collections, {"K1": "Antiga"}), collections, self.root, stats)

        self.assertTrue((self.root / "Antiga" / "a.pdf").exists())
        self.assertTrue((self.root / "Nova" / "b.pdf").exists())
        self.assertEqual(stats["folder_sync_conflicts"], 1)

    def test_empty_destination_created_earlier_does_not_block_the_rename(self):
        self.pdf("Antiga/a.pdf")
        (self.root / "Nova").mkdir()
        collections = [make_collection("K1", "Nova")]
        zsync.apply_collection_folder_actions(
            FakeZotero(), self.plan(collections, {"K1": "Antiga"}), collections, self.root, new_stats())
        self.assertTrue((self.root / "Nova" / "a.pdf").exists())
        self.assertFalse((self.root / "Antiga").exists())

    def test_collection_deleted_in_zotero_removes_only_an_empty_directory(self):
        (self.root / "Vazia").mkdir()
        self.pdf("Cheia/a.pdf")
        actions = self.plan([], {"V": "Vazia", "C": "Cheia"})
        self.assertEqual([(a["type"], a["path"]) for a in actions], [("remove_empty_drive_dir", "Vazia")])

        zsync.apply_collection_folder_actions(FakeZotero(), actions, [], self.root, new_stats())
        self.assertFalse((self.root / "Vazia").exists())
        self.assertTrue((self.root / "Cheia" / "a.pdf").exists())


class DriveSideRenameTests(FolderSyncCase):
    def names(self, key, *files):
        return {key: {zsync.normalize_aggressive(name) for name in files}}

    def test_folder_renamed_on_drive_renames_the_collection_in_place(self):
        self.pdf("Nova/a.pdf")
        self.pdf("Nova/b.pdf")
        (self.root / "Antiga").mkdir(exist_ok=True)
        os.rmdir(self.root / "Antiga")
        collections = [make_collection("K1", "Antiga", version=7)]
        names = self.names("K1", "a.pdf", "b.pdf")
        actions = self.plan(collections, {"K1": "Antiga"}, names)
        self.assertEqual([(a["type"], a["new_name"]) for a in actions], [("rename_collection", "Nova")])

        zot = FakeZotero()
        stats = new_stats()
        _drive, collections_changed = zsync.apply_collection_folder_actions(
            zot, actions, collections, self.root, stats)

        self.assertTrue(collections_changed)
        self.assertEqual(len(zot.updated), 1)
        self.assertEqual((zot.updated[0]["key"], zot.updated[0]["name"], zot.updated[0]["version"]), ("K1", "Nova", 7))
        self.assertEqual(zot.deleted, [])
        self.assertEqual(self.audit_actions(), ["collection_rename"])

    def test_unrelated_new_folder_is_not_mistaken_for_a_rename(self):
        self.pdf("Outra/zzz.pdf")
        collections = [make_collection("K1", "Antiga")]
        actions = self.plan(collections, {"K1": "Antiga"}, self.names("K1", "a.pdf", "b.pdf"))
        self.assertEqual([a["type"] for a in actions if a["type"] == "rename_collection"], [])

    def test_folder_sharing_only_a_small_part_of_the_pdfs_is_not_a_rename(self):
        for name in ("a.pdf", "novo1.pdf", "novo2.pdf", "novo3.pdf"):
            self.pdf(f"Nova/{name}")
        collections = [make_collection("K1", "Antiga")]
        actions = self.plan(collections, {"K1": "Antiga"}, self.names("K1", "a.pdf", "b.pdf"))
        self.assertNotIn("rename_collection", [a["type"] for a in actions])

    def test_two_collections_matching_one_folder_are_a_conflict_not_a_rename(self):
        self.pdf("Nova/a.pdf")
        collections = [make_collection("K1", "Um"), make_collection("K2", "Dois")]
        names = {**self.names("K1", "a.pdf"), **self.names("K2", "a.pdf")}
        actions = self.plan(collections, {"K1": "Um", "K2": "Dois"}, names)
        self.assertEqual({a["type"] for a in actions}, {"conflict"})
        zot = FakeZotero()
        zsync.apply_collection_folder_actions(zot, actions, collections, self.root, new_stats())
        self.assertEqual(zot.updated, [])

    def test_renamed_parent_folder_renames_only_the_parent_collection(self):
        self.pdf("Novo/a.pdf")
        self.pdf("Novo/Filho/b.pdf")
        collections = [make_collection("P", "Antigo"), make_collection("C", "Filho", parent="P")]
        names = {**self.names("P", "a.pdf"), **self.names("C", "b.pdf")}
        actions = self.plan(collections, {"P": "Antigo", "C": "Antigo/Filho"}, names)
        self.assertEqual([(a["type"], a["key"]) for a in actions], [("rename_collection", "P")])

    def test_failed_api_rename_is_an_error_and_not_counted(self):
        self.pdf("Nova/a.pdf")
        collections = [make_collection("K1", "Antiga")]
        actions = self.plan(collections, {"K1": "Antiga"}, self.names("K1", "a.pdf"))
        stats = new_stats()
        zsync.apply_collection_folder_actions(
            FakeZotero(update_status=412), actions, collections, self.root, stats)
        self.assertEqual(stats["folder_sync_collection_renames"], 0)
        self.assertEqual(stats["folder_sync_errors"], 1)
        self.assertEqual(self.audit_actions(), [])


class DeletionTests(FolderSyncCase):
    def delete_actions(self, collections, ledger, names=None):
        return [a for a in self.plan(collections, ledger, names) if a["type"] == "delete_empty_collection"]

    def test_vanished_folder_deletes_an_empty_childless_collection(self):
        collections = [make_collection("K1", "Sumiu", version=4)]
        actions = self.delete_actions(collections, {"K1": "Sumiu"})
        self.assertEqual([a["key"] for a in actions], ["K1"])
        zot = FakeZotero()
        stats = new_stats()
        zsync.apply_collection_folder_actions(zot, actions, collections, self.root, stats)
        self.assertEqual(zot.deleted, [{"key": "K1", "version": 4}])
        self.assertEqual(self.audit_actions(), ["collection_delete"])

    def test_collection_with_items_is_never_deleted_when_its_folder_vanishes(self):
        collections = [make_collection("K1", "Sumiu")]
        self.assertEqual(self.delete_actions(collections, {"K1": "Sumiu"}, {"K1": {"a.pdf"}}), [])
        # itens que não são PDF só aparecem na checagem da API
        actions = self.delete_actions(collections, {"K1": "Sumiu"})
        zot = FakeZotero(nonempty={"K1"})
        zsync.apply_collection_folder_actions(zot, actions, collections, self.root, new_stats())
        self.assertEqual(zot.deleted, [])

    def test_collection_with_children_is_kept(self):
        collections = [make_collection("P", "Pai"), make_collection("C", "Filho", parent="P")]
        (self.root / "Pai" / "Filho").mkdir(parents=True)
        os.rmdir(self.root / "Pai" / "Filho")
        os.rmdir(self.root / "Pai")
        self.assertEqual(self.delete_actions(collections, {"P": "Pai", "C": "Pai/Filho"}), [])

    def test_deletions_are_capped_per_run(self):
        collections = [make_collection(f"K{i}", f"C{i}") for i in range(zsync.MAX_COLLECTION_DELETES_PER_RUN + 3)]
        ledger = {c["key"]: c["data"]["name"] for c in collections}
        actions = self.delete_actions(collections, ledger)
        zot = FakeZotero()
        stats = new_stats()
        zsync.apply_collection_folder_actions(zot, actions, collections, self.root, stats)
        self.assertEqual(len(zot.deleted), zsync.MAX_COLLECTION_DELETES_PER_RUN)

    def test_dry_run_changes_nothing(self):
        self.pdf("Antiga/a.pdf")
        (self.root / "Vazia").mkdir()
        collections = [make_collection("K1", "Nova"), make_collection("K2", "Sumiu")]
        actions = self.plan(collections, {"K1": "Antiga", "K2": "Sumiu"})
        zot = FakeZotero()
        with mock.patch.dict(os.environ, {"ZOTERO_FOLDER_SYNC_DRY_RUN": "1"}):
            zsync.apply_collection_folder_actions(zot, actions, collections, self.root, new_stats(), dry_run=True)
        self.assertTrue((self.root / "Antiga" / "a.pdf").exists())
        self.assertEqual(zot.deleted, [])
        self.assertEqual(zot.updated, [])
        self.assertEqual(self.audit_actions(), [])


class OrchestrationTests(FolderSyncCase):
    def test_unmounted_drive_blocks_every_structural_action(self):
        collections = [make_collection("K1", "Sumiu")]
        self.ledger({"K1": "Sumiu"})  # razão lembra de uma pasta que não existe: mount vazio
        zot = FakeZotero()
        stats = new_stats()
        changed = zsync.reconcile_collection_folder_renames(zot, collections, [], {}, self.root, stats)

        self.assertFalse(changed)
        self.assertTrue(stats["folder_sync_blocked"])
        self.assertEqual(zot.deleted, [])
        self.assertFalse(zsync.write_folder_ledger_if_clean(self.root, {"K1": {"relative_path": "x"}}, stats))
        self.assertEqual(json.loads((self.root / ".zotero_folders.json").read_text()), {"K1": "Sumiu"})

    def test_first_run_without_ledger_changes_nothing_and_writes_it_at_the_end(self):
        self.pdf("Algo/a.pdf")
        collections = [make_collection("K1", "Algo")]
        zot = FakeZotero()
        stats = new_stats()
        self.assertFalse(zsync.reconcile_collection_folder_renames(zot, collections, [], {}, self.root, stats))
        by_key, _c, _p = zsync.build_collection_path_model(collections)
        self.assertTrue(zsync.write_folder_ledger_if_clean(self.root, by_key, stats))
        self.assertEqual(json.loads((self.root / ".zotero_folders.json").read_text()), {"K1": "Algo"})

    def _rename_scenario(self):
        self.pdf("Nova/a.pdf")
        collections = [make_collection("K1", "Antiga")]
        attachment = {"key": "A1", "data": {
            "key": "A1", "itemType": "attachment", "filename": "a.pdf",
            "contentType": "application/pdf", "collections": ["K1"],
        }}
        return collections, [attachment]

    def test_ledger_older_than_the_limit_is_only_renewed_never_acted_on(self):
        self.ledger({"K1": "Antiga", "K2": "Fica"})
        self.pdf("Fica/z.pdf")
        collections, attachments = self._rename_scenario()
        old = zsync.time.time() - 30 * 86400
        os.utime(self.root / ".zotero_folders.json", (old, old))
        zot = FakeZotero()
        self.assertFalse(zsync.reconcile_collection_folder_renames(
            zot, collections, attachments, {}, self.root, new_stats()))
        self.assertEqual(zot.updated, [])

    def test_ledger_within_the_limit_still_drives_the_rename(self):
        self.ledger({"K1": "Antiga", "K2": "Fica"})
        self.pdf("Fica/z.pdf")
        collections, attachments = self._rename_scenario()
        zot = FakeZotero()
        self.assertTrue(zsync.reconcile_collection_folder_renames(
            zot, collections, attachments, {}, self.root, new_stats()))
        self.assertEqual([p["name"] for p in zot.updated], ["Nova"])

    def test_age_limit_can_be_tuned_by_environment(self):
        with mock.patch.dict(os.environ, {"ZOTERO_FOLDER_LEDGER_MAX_AGE_DAYS": "3"}):
            self.assertEqual(zsync.folder_ledger_max_age_days(), 3)
        with mock.patch.dict(os.environ, {"ZOTERO_FOLDER_LEDGER_MAX_AGE_DAYS": "lixo"}):
            self.assertEqual(zsync.folder_ledger_max_age_days(), 14)

    def test_ledger_is_not_rewritten_after_a_structural_error(self):
        self.ledger({"K1": "Velho"})
        stats = new_stats()
        stats["folder_sync_errors"] = 1
        self.assertFalse(zsync.write_folder_ledger_if_clean(self.root, {"K1": {"relative_path": "Novo"}}, stats))
        self.assertEqual(json.loads((self.root / ".zotero_folders.json").read_text()), {"K1": "Velho"})

    def test_full_step_renames_a_drive_folder_and_asks_for_a_refetch(self):
        self.pdf("Nova/a.pdf")
        self.ledger({"K1": "Antiga", "K2": "Fica"})
        self.pdf("Fica/z.pdf")
        collections = [make_collection("K1", "Antiga"), make_collection("K2", "Fica")]
        attachment = {"key": "A1", "data": {
            "key": "A1", "itemType": "attachment", "filename": "a.pdf",
            "contentType": "application/pdf", "collections": ["K1"],
        }}
        zot = FakeZotero()
        stats = new_stats()
        changed = zsync.reconcile_collection_folder_renames(zot, collections, [attachment], {}, self.root, stats)
        self.assertTrue(changed)
        self.assertEqual([p["name"] for p in zot.updated], ["Nova"])

    def test_corrupt_ledger_is_treated_as_absent(self):
        (self.root / ".zotero_folders.json").write_text("{nao e json", encoding="utf-8")
        self.assertEqual(zsync.load_folder_ledger(self.root), {})


class TrashedItemTests(FolderSyncCase):
    def test_item_in_the_zotero_trash_is_not_realigned_to_a_collection(self):
        class Zot(FakeZotero):
            def __init__(self):
                super().__init__()
                self.items_updated = []

            def item(self, key):
                return {"data": {"key": key, "version": 9, "deleted": 1, "collections": ["OLD"]}}

            def update_item(self, payload):
                self.items_updated.append(payload)

        zot = Zot()
        changed = zsync.sync_item_collections_to_drive_collection(
            zot, "ITEM", "NEW", {"OLD": {}, "NEW": {}})
        self.assertFalse(changed)
        self.assertEqual(zot.items_updated, [])


class MoveEvidenceTests(FolderSyncCase):
    def test_reconcile_records_old_to_new_evidence_and_merge_then_drains_the_old_collection(self):
        class Zot(FakeZotero):
            def item(self, key):
                return {"data": {"key": key, "version": 3, "collections": ["OLD"]}}

            def update_item(self, item):
                pass

        self.pdf("Nova/Doc - Silva 2024.pdf", b"same")
        (self.root / "Antiga").mkdir()
        local = Path(self.tmp.name) / "local.pdf"
        local.write_bytes(b"same")
        parent = {"key": "P1", "data": {
            "key": "P1", "itemType": "journalArticle", "title": "Doc", "date": "2024",
            "creators": [{"creatorType": "author", "lastName": "Silva"}], "collections": ["OLD"],
        }}
        attachment = {"key": "A1", "data": {
            "key": "A1", "itemType": "attachment", "parentItem": "P1",
            "filename": "Doc - Silva 2024.pdf", "contentType": "application/pdf",
        }}
        collections = [make_collection("OLD", "Antiga", version=5), make_collection("NEW", "Nova", version=2)]
        by_key, _c, path_to_key = zsync.build_collection_path_model(collections)
        name = zsync.normalize_filename("Doc - Silva 2024.pdf")
        aggressive = zsync.normalize_aggressive("Doc - Silva 2024.pdf")
        pdf = str(self.root / "Nova" / "Doc - Silva 2024.pdf")
        evidence, stats = {}, {}
        zot = Zot()

        with mock.patch.object(zsync, "TARGET_FOLDER", str(self.root)):
            zsync.reconcile_drive_collection_paths(
                zot, [attachment], {"P1": parent}, by_key, path_to_key,
                {name: pdf}, {aggressive: pdf}, {"A1": str(local)}, stats, set(), evidence)
        self.assertEqual(evidence, {("OLD", "NEW"): {"P1"}})

        stats.update({"folder_sync_collection_deletes": 0})
        self.assertTrue(zsync.prune_superseded_collections(zot, collections, self.root, evidence, stats))
        self.assertEqual(zot.deleted, [{"key": "OLD", "version": 5}])
        self.assertFalse((self.root / "Antiga").exists())
        self.assertTrue((self.root / "Nova" / "Doc - Silva 2024.pdf").exists())

    def test_prune_does_nothing_while_the_run_is_blocked(self):
        zot = FakeZotero()
        stats = {"folder_sync_blocked": True}
        self.assertFalse(zsync.prune_superseded_collections(
            zot, [make_collection("OLD", "A")], self.root, {("OLD", "NEW"): {"X"}}, stats))
        self.assertEqual(zot.deleted, [])


if __name__ == "__main__":
    unittest.main()
