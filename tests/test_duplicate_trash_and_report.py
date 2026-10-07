"""Tests for US-011: Zotero trash for duplicate removal and the read-only duplicates report."""
import json
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import zotero_sync_webdav as zsync


class IsolatedAuditTestCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.actions_log = os.path.join(self.work, "actions.jsonl")
        for name, value in (
            ("QUARANTINE_DIR", os.path.join(self.work, "quarantine")),
            ("DUPLICATE_ACTIONS_LOG", self.actions_log),
        ):
            patcher = patch.object(zsync, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def audit_lines(self):
        if not os.path.exists(self.actions_log):
            return []
        with open(self.actions_log, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]


class PatchItemDeletedFlagTests(unittest.TestCase):
    def make_zot(self):
        response = MagicMock()
        client = MagicMock()
        client.patch.return_value = response
        zot = SimpleNamespace(
            endpoint="https://api.zotero.org",
            library_type="users",
            library_id="42",
            client=client,
            default_headers=lambda: {"Authorization": "Bearer secret"},
        )
        return zot, client, response

    def test_sends_versioned_deleted_patch_to_the_item_endpoint(self):
        zot, client, response = self.make_zot()

        zsync.patch_item_deleted_flag(zot, "ABCD1234", 17)

        (url,), kwargs = client.patch.call_args
        self.assertEqual(url, "https://api.zotero.org/users/42/items/ABCD1234")
        self.assertEqual(kwargs["json"], {"deleted": 1})
        self.assertEqual(kwargs["headers"]["If-Unmodified-Since-Version"], "17")
        response.raise_for_status.assert_called_once()

    def test_missing_version_is_refused_before_any_request(self):
        zot, client, _ = self.make_zot()

        with self.assertRaises(ValueError):
            zsync.patch_item_deleted_flag(zot, "ABCD1234", None)

        client.patch.assert_not_called()


class MoveItemToZoteroTrashTests(IsolatedAuditTestCase):
    def make_zot(self, children, item_version=9):
        return SimpleNamespace(
            children=lambda key: children,
            item=lambda key: {"key": key, "version": item_version, "data": {"key": key}},
        )

    def test_children_are_trashed_before_the_parent_and_already_trashed_are_skipped(self):
        children = [
            {"key": "CHILD1", "version": 5, "data": {}},
            {"key": "CHILD2", "version": 6, "data": {"deleted": 1}},
        ]
        calls = []
        with patch.object(zsync, "patch_item_deleted_flag", side_effect=lambda z, k, v: calls.append((k, v))):
            result = zsync.move_item_to_zotero_trash(
                self.make_zot(children), "PARENT", action="dup", reason="r", kept_key="KEEP", title="T",
            )

        self.assertEqual(calls, [("CHILD1", 5), ("PARENT", 9)])
        self.assertEqual(result, ["CHILD1"])
        (line,) = self.audit_lines()
        self.assertEqual(line["action"], "dup")
        self.assertEqual(line["item_key"], "PARENT")
        self.assertEqual(line["kept_key"], "KEEP")
        self.assertEqual(line["children_trashed"], ["CHILD1"])

    def test_parent_failure_after_children_is_recorded_as_partial_and_propagates(self):
        children = [{"key": "CHILD1", "version": 5, "data": {}}]

        def fail_on_parent(zot, key, version):
            if key == "PARENT":
                raise RuntimeError("412 Precondition Failed")

        with patch.object(zsync, "patch_item_deleted_flag", side_effect=fail_on_parent):
            with self.assertRaises(RuntimeError):
                zsync.move_item_to_zotero_trash(
                    self.make_zot(children), "PARENT", action="dup", reason="r",
                )

        (line,) = self.audit_lines()
        self.assertEqual(line["action"], "dup_partial")
        self.assertEqual(line["children_trashed"], ["CHILD1"])


class ManualDuplicateRemovalTests(IsolatedAuditTestCase):
    def test_remove_duplicatas_never_permanently_deletes(self):
        class NoPermanentDeleteZotero:
            def delete_item(self, *args, **kwargs):
                raise AssertionError("exclusão permanente não é permitida")

        with patch.object(zsync, "move_item_to_zotero_trash") as trash, patch.object(zsync.time, "sleep"):
            ok, err = zsync.delete_attachment_keys(NoPermanentDeleteZotero(), ["K1", "K2"], dry_run=False)
            dry_ok, dry_err = zsync.delete_attachment_keys(NoPermanentDeleteZotero(), ["K3"], dry_run=True)

        self.assertEqual((ok, err), (2, 0))
        self.assertEqual([call.args[1] for call in trash.call_args_list], ["K1", "K2"])
        self.assertEqual((dry_ok, dry_err), (1, 0))


def make_bibliographic_item(key, title, *, doi="", date_added="2025-01-01T00:00:00Z"):
    return {
        "key": key,
        "version": 1,
        "data": {
            "key": key,
            "itemType": "journalArticle",
            "title": title,
            "DOI": doi,
            "dateAdded": date_added,
            "collections": [],
            "tags": [],
            "relations": {},
        },
    }


class AutomaticBibliographicCleanupTests(IsolatedAuditTestCase):
    LONG_TITLE = "Um titulo suficientemente longo para identificar duplicata bibliografica"

    def run_cleanup(self, items, summaries):
        zot = SimpleNamespace(children=lambda key: [{"_for": key}])
        stats = {"errors": 0}
        with patch.object(zsync, "collect_all_bibliographic_items", return_value=items), \
                patch.object(zsync, "summarize_duplicate_children", side_effect=lambda children, _: summaries[children[0]["_for"]]), \
                patch.object(zsync, "move_item_to_zotero_trash") as trash, \
                patch.object(zsync, "add_review_tag_to_item", return_value=True) as tag, \
                patch.object(zsync, "merge_duplicate_metadata_into_keeper"), \
                patch.object(zsync.time, "sleep"):
            zsync.run_safe_bibliographic_duplicate_cleanup(zot, stats, {})
        return trash, tag, stats

    def test_doi_duplicate_goes_to_trash_and_title_only_duplicate_is_only_flagged(self):
        items = [
            make_bibliographic_item("DOIKEEP", "Artigo com doi " + self.LONG_TITLE, doi="10.1000/abc", date_added="2024-01-01T00:00:00Z"),
            make_bibliographic_item("DOIDUP", "Artigo com doi " + self.LONG_TITLE, doi="10.1000/abc", date_added="2025-01-01T00:00:00Z"),
            make_bibliographic_item("TITKEEP", "Sem doi " + self.LONG_TITLE, date_added="2024-01-01T00:00:00Z"),
            make_bibliographic_item("TITDUP", "Sem doi " + self.LONG_TITLE, date_added="2025-01-01T00:00:00Z"),
        ]
        keeper_with_pdf = {"pdf_hashes": {"h1"}, "pdf_filenames": ["a.pdf"]}
        summaries = {"DOIKEEP": {}, "DOIDUP": {}, "TITKEEP": keeper_with_pdf, "TITDUP": {}}

        trash, tag, stats = self.run_cleanup(items, summaries)

        self.assertEqual([call.args[1] for call in trash.call_args_list], ["DOIDUP"])
        self.assertEqual(trash.call_args.kwargs["kept_key"], "DOIKEEP")
        self.assertEqual(tag.call_count, 1)
        self.assertEqual(tag.call_args.args[1], "TITDUP")
        self.assertEqual(stats["auto_removed_bibliographic_duplicates"], 1)

    def test_group_auto_delete_block_reason_depends_only_on_identity_kind(self):
        self.assertIsNone(zsync.bibliographic_group_auto_delete_block_reason(("doi", "10.1/x")))
        self.assertIsNotNone(zsync.bibliographic_group_auto_delete_block_reason(("title+type", "x")))
        self.assertIsNotNone(zsync.bibliographic_group_auto_delete_block_reason(("title", "x")))
        self.assertIsNotNone(zsync.bibliographic_group_auto_delete_block_reason(None))


class ClassifyDuplicateCopiesTests(unittest.TestCase):
    def test_single_owner_with_one_copy_in_its_collection_marks_the_others_as_strays(self):
        verdict = zsync.classify_duplicate_copies(
            ["Doc.pdf", "NEJ Salvador/Assessor/Doc.pdf"],
            [{"key": "I1", "title": "Doc", "collections": ["NEJ Salvador/Assessor"]}],
        )
        self.assertEqual(verdict["verdict"], "stray")
        self.assertEqual(verdict["roles"], {"Doc.pdf": "stray", "NEJ Salvador/Assessor/Doc.pdf": "keep"})

    def test_distinct_zotero_items_sharing_content_is_a_conflict(self):
        verdict = zsync.classify_duplicate_copies(
            ["A/x.pdf", "B/y.pdf"],
            [
                {"key": "I1", "title": "", "collections": ["A"]},
                {"key": "I2", "title": "", "collections": ["B"]},
            ],
        )
        self.assertEqual(verdict["verdict"], "conflict")
        self.assertEqual(set(verdict["roles"].values()), {"review"})

    def test_copies_in_two_collections_of_the_same_item_are_a_conflict(self):
        verdict = zsync.classify_duplicate_copies(
            ["A/x.pdf", "B/x.pdf"],
            [{"key": "I1", "title": "", "collections": ["A", "B"]}],
        )
        self.assertEqual(verdict["verdict"], "conflict")

    def test_no_copy_inside_an_item_collection_is_a_conflict_not_a_stray(self):
        verdict = zsync.classify_duplicate_copies(
            ["A/x.pdf", "B/x.pdf"],
            [{"key": "I1", "title": "", "collections": ["C"]}],
        )
        self.assertEqual(verdict["verdict"], "conflict")

    def test_copies_without_any_zotero_item_are_unowned(self):
        verdict = zsync.classify_duplicate_copies(["A/x.pdf", "B/x.pdf"], [])
        self.assertEqual(verdict["verdict"], "unowned")

    def test_collection_matching_ignores_case_and_normalization_differences(self):
        verdict = zsync.classify_duplicate_copies(
            ["Avaliação/x.pdf", "Outra/x.pdf"],
            [{"key": "I1", "title": "", "collections": ["avaliação"]}],
        )
        self.assertEqual(verdict["verdict"], "stray")


class BuildDuplicatesReportTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def write(self, relative, content):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def attachment(self, key, filename, parent):
        return {"key": key, "data": {
            "key": key, "itemType": "attachment", "filename": filename,
            "contentType": "application/pdf", "parentItem": parent, "linkMode": "imported_file",
        }}

    def test_same_content_in_two_folders_reports_the_copy_outside_the_item_collection(self):
        a = self.write("A/Doc.pdf", b"same content")
        b = self.write("B/Doc.pdf", b"same content")
        parent = make_bibliographic_item("PARENT1", "Doc title")
        parent["data"]["collections"] = ["COLA"]
        groups = zsync.build_duplicates_report(
            [a, b], self.root,
            [self.attachment("ATT1", "Doc.pdf", "PARENT1")],
            {"PARENT1": parent},
            {"COLA": {"relative_path": "A"}, "COLB": {"relative_path": "B"}},
        )

        (group,) = groups
        self.assertEqual(group["verdict"], "stray")
        self.assertEqual({c["path"]: c["role"] for c in group["copies"]}, {"A/Doc.pdf": "keep", "B/Doc.pdf": "stray"})
        self.assertTrue(os.path.exists(a) and os.path.exists(b))

    def test_same_name_with_different_content_is_a_conflict_and_unique_files_are_ignored(self):
        a = self.write("A/Doc.pdf", b"version one")
        b = self.write("B/Doc.pdf", b"version two!")
        only = self.write("A/Only.pdf", b"different")
        groups = zsync.build_duplicates_report([a, b, only], self.root, [], {}, {})

        (group,) = groups
        self.assertEqual(group["kind"], "name_collision")
        self.assertEqual(group["verdict"], "conflict")
        self.assertEqual({c["path"] for c in group["copies"]}, {"A/Doc.pdf", "B/Doc.pdf"})

    def test_same_content_with_different_names_is_found_and_reported_per_owner(self):
        a = self.write("UNEB/Plagio - Dutra.pdf", b"identical")
        b = self.write("ABNT/PLAGIO consideracoes.pdf", b"identical")
        p1 = make_bibliographic_item("P1", "T1"); p1["data"]["collections"] = ["C1"]
        p2 = make_bibliographic_item("P2", "T2"); p2["data"]["collections"] = ["C2"]
        groups = zsync.build_duplicates_report(
            [a, b], self.root,
            [self.attachment("A1", "Plagio - Dutra.pdf", "P1"), self.attachment("A2", "PLAGIO consideracoes.pdf", "P2")],
            {"P1": p1, "P2": p2},
            {"C1": {"relative_path": "UNEB"}, "C2": {"relative_path": "ABNT"}},
        )

        (group,) = groups
        self.assertEqual(group["verdict"], "conflict")
        self.assertEqual({owner["key"] for owner in group["owners"]}, {"P1", "P2"})


if __name__ == "__main__":
    unittest.main()
