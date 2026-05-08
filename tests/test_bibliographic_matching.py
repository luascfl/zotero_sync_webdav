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

zsync = importlib.import_module("zotero_sync_webdav")


def make_item(key, title, *, doi="", date_added="2025-01-01T00:00:00Z"):
    return {
        "key": key,
        "data": {
            "key": key,
            "itemType": "journalArticle",
            "title": title,
            "DOI": doi,
            "dateAdded": date_added,
        },
    }


class BibliographicMatchingTests(unittest.TestCase):
    def test_truncated_zotero_filename_selects_existing_parent(self):
        index = zsync.build_bibliographic_parent_index([
            make_item(
                "8W8XDT6E",
                "A situação atual dos cursos de licenciatura no Brasil frente à hegemonia da educação mercantil e empresarial",
                doi="10.14244/198271991355",
            )
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "A situação atual dos cursos de licenciatura no Brasil frente à hegemonia da - Diniz-Pereira 2015 (1).pdf",
            index,
        )

        self.assertEqual(parent["key"], "8W8XDT6E")
        self.assertEqual(len(candidates), 1)

    def test_truncated_oficinas_filename_selects_existing_parent_without_attachment(self):
        index = zsync.build_bibliographic_parent_index([
            make_item(
                "AWKA6AM8",
                "Oficinas de identidade com adolescentes: relato de experiência de um projeto de extensão",
                doi="10.35700/ca.2021.ano8n14.p117-121.3050",
            )
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "Oficinas de identidade com adolescentes relato de experiência de um projeto de -  2021 1.pdf",
            index,
        )

        self.assertEqual(parent["key"], "AWKA6AM8")
        self.assertEqual(len(candidates), 1)

    def test_duplicate_bibliographic_candidates_block_automatic_parent_selection(self):
        title = "Oficinas de identidade com adolescentes: relato de experiência de um projeto de extensão"
        index = zsync.build_bibliographic_parent_index([
            make_item("AWKA6AM8", title, date_added="2025-11-02T20:12:21Z"),
            make_item("YUV3E6U5", title, date_added="2026-05-08T18:21:40Z"),
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "Oficinas de identidade com adolescentes relato de experiência de um projeto de -  2021 1.pdf",
            index,
        )

        self.assertIsNone(parent)
        self.assertEqual({candidate["key"] for candidate in candidates}, {"AWKA6AM8", "YUV3E6U5"})

    def test_leading_author_year_filename_can_match_book_title(self):
        index = zsync.build_bibliographic_parent_index([
            make_item("BOOK1234", "Compreender o Behaviorismo Comportamento, Cultura e Evolução")
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "Baum (2019) Compreender o Behaviorismo Comportamento, Cultura e Evolução - 3ª ed.-30-41.pdf",
            index,
        )

        self.assertEqual(parent["key"], "BOOK1234")
        self.assertEqual(len(candidates), 1)

    def test_copy_prefix_is_removed_before_parent_matching(self):
        index = zsync.build_bibliographic_parent_index([
            make_item("PARENT1", "Arquivo X e sua teoria principal")
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "Cópia de Arquivo X e sua teoria principal.pdf",
            index,
        )

        self.assertEqual(parent["key"], "PARENT1")
        self.assertEqual(len(candidates), 1)

    def test_copy_variant_never_beats_clean_name(self):
        preferred = zsync.choose_non_copy_canonical_name(
            "Cópia de Arquivo X.pdf",
            "Arquivo X - Autor 2020.pdf",
        )

        self.assertEqual(preferred, "Arquivo X - Autor 2020.pdf")

    def test_numbered_copy_variant_does_not_become_canonical(self):
        preferred = zsync.choose_non_copy_canonical_name(
            "Arquivo X (1).pdf",
            "Arquivo X.pdf",
        )

        self.assertEqual(preferred, "Arquivo X.pdf")

    def test_enforce_drive_canonical_name_deletes_same_hash_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            canonical = folder / "Arquivo X.pdf"
            duplicate = folder / "Cópia de Arquivo X.pdf"
            content = b"same pdf content"
            canonical.write_bytes(content)
            duplicate.write_bytes(content)
            stats = {"pruned_drive_duplicates": 0, "renamed_webdav": 0}
            duplicate_hash = zsync.compute_sha256(str(duplicate), cache={})

            result = zsync.enforce_drive_canonical_name(
                str(duplicate),
                canonical.name,
                duplicate_hash,
                stats,
            )

            self.assertEqual(Path(result), canonical)
            self.assertTrue(canonical.exists())
            self.assertFalse(duplicate.exists())
            self.assertEqual(stats["pruned_drive_duplicates"], 1)

    def test_enforce_drive_canonical_name_renames_copy_when_destination_absent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            duplicate = folder / "Cópia de Arquivo X.pdf"
            duplicate.write_bytes(b"same pdf content")
            stats = {"pruned_drive_duplicates": 0, "renamed_webdav": 0}
            duplicate_hash = zsync.compute_sha256(str(duplicate), cache={})

            result = zsync.enforce_drive_canonical_name(
                str(duplicate),
                "Arquivo X.pdf",
                duplicate_hash,
                stats,
            )

            self.assertEqual(Path(result), folder / "Arquivo X.pdf")
            self.assertTrue((folder / "Arquivo X.pdf").exists())
            self.assertFalse(duplicate.exists())
            self.assertEqual(stats["renamed_webdav"], 1)

    def test_bibliographic_duplicate_groups_use_doi_before_title(self):
        index = zsync.build_bibliographic_parent_index([
            make_item("OLDITEM1", "Título antigo grafia A", doi="https://doi.org/10.123/ABC"),
            make_item("NEWITEM2", "Título novo grafia B", doi="10.123/abc"),
        ])

        groups = zsync.build_bibliographic_duplicate_groups(index)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["identity"], ("doi", "10.123/abc"))
        self.assertEqual({item["key"] for item in groups[0]["items"]}, {"OLDITEM1", "NEWITEM2"})

    def test_duplicate_cleanup_keeper_prefers_pdf_over_empty_older_item(self):
        older = {"key": "OLD", "dateAdded": "2024-01-01T00:00:00Z"}
        newer_with_pdf = {"key": "NEW", "dateAdded": "2026-01-01T00:00:00Z"}

        keeper = zsync.choose_bibliographic_duplicate_keeper(
            [older, newer_with_pdf],
            {
                "OLD": {"pdf_hashes": set(), "pdf_filenames": []},
                "NEW": {"pdf_hashes": {"abc"}, "pdf_filenames": ["Arquivo X.pdf"]},
            },
        )

        self.assertEqual(keeper["key"], "NEW")

    def test_duplicate_cleanup_allows_redundant_pdf_hash_deletion(self):
        duplicate = {"key": "DUP", "doi": "10.123/x", "relations": {}}
        keeper = {"key": "KEEP", "doi": "10.123/x", "relations": {}}

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            {"pdf_hashes": {"same"}, "unsafe_children": [], "missing_hash_attachments": []},
            {"pdf_hashes": {"same"}, "unsafe_children": [], "missing_hash_attachments": []},
        )

        self.assertTrue(can_delete, reason)

    def test_duplicate_cleanup_blocks_nonredundant_pdf_hash(self):
        duplicate = {"key": "DUP", "doi": "10.123/x", "relations": {}}
        keeper = {"key": "KEEP", "doi": "10.123/x", "relations": {}}

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            {"pdf_hashes": {"different"}, "unsafe_children": [], "missing_hash_attachments": []},
            {"pdf_hashes": {"same"}, "unsafe_children": [], "missing_hash_attachments": []},
        )

        self.assertFalse(can_delete)
        self.assertIn("não redundante", reason)

    def test_duplicate_cleanup_blocks_title_only_metadata_without_pdf(self):
        duplicate = {"key": "DUP", "doi": "", "relations": {}}
        keeper = {"key": "KEEP", "doi": "", "relations": {}}

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            {"pdf_hashes": set(), "unsafe_children": [], "missing_hash_attachments": []},
            {"pdf_hashes": set(), "unsafe_children": [], "missing_hash_attachments": []},
        )

        self.assertFalse(can_delete)
        self.assertIn("sem DOI", reason)

    def test_unsafe_duplicate_child_classifies_highlight_annotation(self):
        detail = zsync.classify_unsafe_duplicate_child({
            "key": "ANN1",
            "data": {
                "itemType": "annotation",
                "annotationType": "highlight",
            },
        })

        self.assertEqual(detail["reason"], "highlight")
        self.assertEqual(detail["label"], "highlight")

    def test_duplicate_cleanup_reports_highlight_block_reason(self):
        duplicate = {"key": "DUP", "doi": "10.123/x", "relations": {}}
        keeper = {"key": "KEEP", "doi": "10.123/x", "relations": {}}
        summary = {
            "pdf_hashes": {"same"},
            "unsafe_children": ["ANN1"],
            "unsafe_child_details": [{"key": "ANN1", "reason": "highlight", "label": "highlight"}],
            "missing_hash_attachments": [],
        }
        keeper_summary = {
            "pdf_hashes": {"same"},
            "unsafe_children": [],
            "unsafe_child_details": [],
            "missing_hash_attachments": [],
        }

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            summary,
            keeper_summary,
        )

        self.assertFalse(can_delete)
        self.assertIn("highlight", reason)

    def test_duplicate_cleanup_reports_snapshot_block_reason(self):
        duplicate = {"key": "DUP", "doi": "10.123/x", "relations": {}}
        keeper = {"key": "KEEP", "doi": "10.123/x", "relations": {}}
        summary = {
            "pdf_hashes": {"same"},
            "unsafe_children": ["SNAP1"],
            "unsafe_child_details": [{"key": "SNAP1", "reason": "snapshot", "label": "snapshot HTML"}],
            "missing_hash_attachments": [],
        }
        keeper_summary = {
            "pdf_hashes": {"same"},
            "unsafe_children": [],
            "unsafe_child_details": [],
            "missing_hash_attachments": [],
        }

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            summary,
            keeper_summary,
        )

        self.assertFalse(can_delete)
        self.assertIn("snapshot HTML", reason)



if __name__ == "__main__":
    unittest.main()
