import importlib
import json
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


def make_item(
    key,
    title,
    *,
    doi="",
    date="",
    creators=None,
    date_added="2025-01-01T00:00:00Z",
    item_type="journalArticle",
):
    return {
        "key": key,
        "data": {
            "key": key,
            "itemType": item_type,
            "title": title,
            "DOI": doi,
            "date": date,
            "creators": list(creators or []),
            "dateAdded": date_added,
        },
    }



def make_attachment(
    key,
    filename,
    *,
    parent_key="",
    link_mode="imported_file",
    content_type="application/pdf",
    title=None,
    path=None,
):
    data = {
        "key": key,
        "itemType": "attachment",
        "title": title if title is not None else filename,
        "linkMode": link_mode,
        "contentType": content_type,
    }
    if filename is not None:
        data["filename"] = filename
    if parent_key:
        data["parentItem"] = parent_key
    if path is not None:
        data["path"] = path
    return {"key": key, "data": data}

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

    def test_roman_numeral_series_titles_do_not_match_other_parts(self):
        title_i = "O processo de ensinagem no grau superior I"
        title_ii = "O processo de ensinagem no grau superior II"
        index = zsync.build_bibliographic_parent_index([
            make_item("PART1", title_i),
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "O processo de ensinagem no grau superior II.pdf",
            index,
        )

        self.assertIsNone(parent)
        self.assertEqual(candidates, [])
        self.assertEqual(zsync.title_match_score(title_ii, title_i), 0.0)

    def test_same_title_with_different_item_types_is_not_duplicate_risk(self):
        title = "O que é a Psicologia"
        index = zsync.build_bibliographic_parent_index([
            make_item("BOOK0001", title, item_type="book", date_added="2025-11-02T20:12:21Z"),
            make_item("SLIDE001", title, item_type="presentation", date_added="2026-05-08T18:21:40Z"),
        ])

        parent, candidates = zsync.select_parent_for_new_attachment(
            "O que é a Psicologia.pdf",
            index,
        )

        self.assertIsNone(parent)
        self.assertEqual(candidates, [])

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

    def test_plain_trailing_number_is_not_treated_as_copy_variant(self):
        self.assertFalse(zsync.is_copy_variant_filename("Slides 1.pdf"))
        self.assertEqual(zsync.canonical_duplicate_filename("Slides 1.pdf"), "Slides 1.pdf")


    def test_canonical_parent_pdf_filename_uses_title_author_year(self):
        item = make_item(
            "PARENT1",
            "A situação atual dos cursos de licenciatura no Brasil frente à hegemonia da educação mercantil e empresarial",
            date="2015-12",
            creators=[{"creatorType": "author", "lastName": "Diniz-Pereira"}],
        )

        filename = zsync.canonical_parent_pdf_filename(item)

        self.assertEqual(
            filename,
            "A situação atual dos cursos de licenciatura no Brasil frente à hegemonia da educação mercantil e empresarial - Diniz-Pereira 2015.pdf",
        )

    def test_canonical_parent_pdf_filename_removes_copy_markers(self):
        item = make_item(
            "PARENT1",
            "Cópia de Arquivo X (1)",
            date="2024",
            creators=[{"creatorType": "author", "name": "Maria Silva"}],
        )

        filename = zsync.canonical_parent_pdf_filename(item)

        self.assertEqual(filename, "Arquivo X - Silva 2024.pdf")

    def test_canonical_standalone_attachment_filename_strips_copy_markers(self):
        attachment = make_attachment(
            "ATT1",
            "Cópia de Campo da especularidade Clínica pulsional do bebê - Marie Couvert 2020 (1).pdf",
        )

        filename = zsync.canonical_standalone_attachment_filename(attachment)

        self.assertEqual(
            filename,
            "Campo da especularidade Clínica pulsional do bebê - Marie Couvert 2020.pdf",
        )

    def test_canonical_standalone_attachment_filename_ignores_child_attachments(self):
        attachment = make_attachment(
            "ATT1",
            "Cópia de Arquivo X.pdf",
            parent_key="PARENT1",
        )

        self.assertIsNone(zsync.canonical_standalone_attachment_filename(attachment))

    def test_parse_path_map_entries_parses_pairs(self):
        pairs = zsync.parse_path_map_entries([
            "/mnt/old=/mnt/new",
            "/vault a=/vault b",
        ])

        self.assertEqual(
            pairs,
            [("/mnt/old", "/mnt/new"), ("/vault a", "/vault b")],
        )

    def test_replace_path_prefix_rewrites_vault_root(self):
        mapped = zsync.replace_path_prefix(
            "/mnt/old/vaults/a",
            [("/mnt/old", "/srv/obsidian")],
        )

        self.assertEqual(mapped, "/srv/obsidian/vaults/a")

    def test_sanitize_obsidian_folder_name_replaces_invalid_chars(self):
        clean = zsync.sanitize_obsidian_folder_name('Pasta: "A/B"?', 'fallback')
        self.assertEqual(clean, "Pasta_ _A_B__")

    def test_parse_path_map_entries_rejects_invalid_rule(self):
        with self.assertRaises(SystemExit):
            zsync.parse_path_map_entries(["sem-separador"])

    def test_build_collection_path_model_creates_hierarchy(self):
        collections = [
            {"key": "ROOT", "data": {"name": "UNEB Psicologia 2025.2"}},
            {"key": "CHILD", "data": {"name": "Psicologia Social", "parentCollection": "ROOT"}},
        ]
        by_key, children, path_to_key = zsync.build_collection_path_model(collections)
        self.assertEqual(by_key["ROOT"]["relative_path"], "UNEB Psicologia 2025.2")
        self.assertEqual(by_key["CHILD"]["relative_path"], "UNEB Psicologia 2025.2/Psicologia Social")
        self.assertEqual(children[None], ["ROOT"])
        self.assertEqual(children["ROOT"], ["CHILD"])
        self.assertEqual(path_to_key["uneb psicologia 2025.2/psicologia social"], "CHILD")

    def test_attachment_target_location_uses_parent_collection(self):
        parent = make_item("PARENT1", "Título", creators=[{"creatorType": "author", "lastName": "Autor"}])
        parent["data"]["collections"] = ["COL1"]
        attachment = make_attachment("ATT1", "Arquivo.pdf", parent_key="PARENT1")
        collection_by_key = {
            "COL1": {"relative_path": "UNEB Psicologia 2025.2", "relative_parts": ["UNEB Psicologia 2025.2"]}
        }
        location = zsync.attachment_target_location(
            attachment,
            "Arquivo.pdf",
            {"PARENT1": parent},
            collection_by_key,
        )
        self.assertEqual(location["collection_key"], "COL1")
        self.assertEqual(location["relative_path"], "UNEB Psicologia 2025.2/Arquivo.pdf")

    def test_infer_collection_key_from_relative_path_uses_deepest_match(self):
        path_to_key = {
            "uneb psicologia 2025.2": "ROOT",
            "uneb psicologia 2025.2/psicologia social": "CHILD",
        }
        key = zsync.infer_collection_key_from_relative_path(
            "UNEB Psicologia 2025.2/Psicologia Social/Artigo.pdf",
            path_to_key,
        )
        self.assertEqual(key, "CHILD")


    def test_hash_match_selection_prefers_metadata_name_matching_drive(self):
        parent_a = make_item(
            "PARENTA",
            "O conceito de biopoder no pensamento de michel foucault",
            date="2017",
            creators=[{"creatorType": "author", "lastName": "Nogueira Furtado"}],
        )
        parent_b = make_item(
            "PARENTB",
            "O conceito de biopoder no pensamento de Michel Foucault",
            date="2016",
            creators=[{"creatorType": "author", "lastName": "Furtado"}],
        )
        attachments = {
            "ATTA": {"key": "ATTA", "data": {"key": "ATTA", "parentItem": "PARENTA"}},
            "ATTB": {"key": "ATTB", "data": {"key": "ATTB", "parentItem": "PARENTB"}},
        }
        parents = {
            "PARENTA": parent_a,
            "PARENTB": parent_b,
        }
        drive_name = "O conceito de biopoder no pensamento de Michel Foucault - Furtado 2016.pdf"

        entry = zsync.choose_hash_match_entry(
            [
                {"key": "ATTA", "filename": "O conceito de biopoder no pensamento de michel foucault - Nogueira Furtado 2017.pdf", "info": {}},
                {"key": "ATTB", "filename": drive_name, "info": {}},
            ],
            drive_name,
            attachments,
            parents,
        )

        self.assertEqual(entry["key"], "ATTB")

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

    def test_preprocess_drive_copy_variants_renames_copy_before_sync(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            duplicate = folder / "Cópia de Arquivo X.pdf"
            duplicate.write_bytes(b"same pdf content")
            stats = {
                "renamed_webdav": 0,
                "pruned_drive_duplicates": 0,
                "preprocessed_drive_copy_variants": 0,
                "blocked_drive_copy_variants": 0,
            }
            result = zsync.preprocess_drive_copy_variants([str(duplicate)], stats)

            self.assertEqual(result, [str(folder / "Arquivo X.pdf")])
            self.assertTrue((folder / "Arquivo X.pdf").exists())
            self.assertFalse(duplicate.exists())
            self.assertEqual(stats["preprocessed_drive_copy_variants"], 1)

    def test_preprocess_drive_copy_variants_blocks_when_collision_differs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir)
            canonical = folder / "Arquivo X.pdf"
            duplicate = folder / "Cópia de Arquivo X.pdf"
            canonical.write_bytes(b"a")
            duplicate.write_bytes(b"b")
            stats = {
                "renamed_webdav": 0,
                "pruned_drive_duplicates": 0,
                "preprocessed_drive_copy_variants": 0,
                "blocked_drive_copy_variants": 0,
            }
            result = zsync.preprocess_drive_copy_variants([str(duplicate)], stats)

            self.assertEqual(result, [str(duplicate)])
            self.assertTrue(duplicate.exists())
            self.assertEqual(stats["blocked_drive_copy_variants"], 1)

    def test_bibliographic_duplicate_groups_use_doi_before_title(self):
        index = zsync.build_bibliographic_parent_index([
            make_item("OLDITEM1", "Título antigo grafia A", doi="https://doi.org/10.123/ABC"),
            make_item("NEWITEM2", "Título novo grafia B", doi="10.123/abc"),
        ])

        groups = zsync.build_bibliographic_duplicate_groups(index)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["identity"], ("doi", "10.123/abc"))
        self.assertEqual({item["key"] for item in groups[0]["items"]}, {"OLDITEM1", "NEWITEM2"})

    def test_title_only_duplicate_groups_are_separated_by_item_type(self):
        title = "O que é a Psicologia"
        index = zsync.build_bibliographic_parent_index([
            make_item("BOOK0001", title, item_type="book"),
            make_item("SLIDE001", title, item_type="presentation"),
        ])

        groups = zsync.build_bibliographic_duplicate_groups(index)

        self.assertEqual(groups, [])

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

    def test_duplicate_cleanup_blocks_title_only_metadata_when_all_items_are_empty(self):
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

    def test_duplicate_cleanup_allows_empty_duplicate_when_keeper_has_attachment(self):
        duplicate = {"key": "DUP", "doi": "", "relations": {}}
        keeper = {"key": "KEEP", "doi": "", "relations": {}}

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            {
                "pdf_hashes": set(),
                "pdf_filenames": [],
                "unsafe_children": [],
                "missing_hash_attachments": [],
            },
            {
                "pdf_hashes": {"same"},
                "pdf_filenames": ["Arquivo.pdf"],
                "unsafe_children": [],
                "missing_hash_attachments": [],
            },
        )

        self.assertTrue(can_delete, reason)
        self.assertIn("sem anexos", reason)

    def test_duplicate_cleanup_allows_empty_duplicate_with_relations(self):
        duplicate = {
            "key": "DUP",
            "doi": "",
            "relations": {"dc:replaces": "http://zotero.org/users/1/items/OLD"},
        }
        keeper = {"key": "KEEP", "doi": "", "relations": {}}

        can_delete, reason = zsync.duplicate_item_can_be_deleted(
            duplicate,
            keeper,
            {
                "pdf_hashes": set(),
                "pdf_filenames": [],
                "unsafe_children": [],
                "missing_hash_attachments": [],
            },
            {
                "pdf_hashes": {"same"},
                "pdf_filenames": ["Arquivo.pdf"],
                "unsafe_children": [],
                "missing_hash_attachments": [],
            },
        )

        self.assertTrue(can_delete, reason)
        self.assertIn("sem anexos", reason)

    def test_duplicate_cleanup_merges_relations_before_deletion(self):
        class FakeZotero:
            def __init__(self):
                self.updated = []

            def update_item(self, item):
                self.updated.append(item)

        zot = FakeZotero()
        keeper_item = {
            "data": {
                "collections": [],
                "tags": [],
                "relations": {"dc:relation": "existing"},
            }
        }
        keeper = {"item": keeper_item}
        duplicate = {
            "collections": [],
            "tags": [],
            "relations": {
                "dc:relation": "new",
                "dc:replaces": "old",
            },
        }

        self.assertTrue(zsync.merge_duplicate_metadata_into_keeper(zot, keeper, duplicate))
        self.assertEqual(zot.updated, [keeper_item["data"]])
        self.assertEqual(keeper_item["data"]["relations"]["dc:relation"], ["existing", "new"])
        self.assertEqual(keeper_item["data"]["relations"]["dc:replaces"], "old")

    def test_stale_review_duplicate_tag_is_removed_when_item_no_longer_matches(self):
        class FakeZotero:
            def __init__(self):
                self.updated = []

            def update_item(self, item):
                self.updated.append(item)

        item = make_item("BOOK0001", "O que é a Psicologia", item_type="book")
        item["data"]["tags"] = [
            {"tag": zsync.REVIEW_DUPLICATE_TAG},
            {"tag": "preservar"},
        ]
        stats = {
            "current_review_duplicate_keys": set(),
            "review_tags_removed": 0,
        }

        zsync.clear_stale_review_duplicate_tags(
            FakeZotero(),
            zsync.build_bibliographic_parent_index([item]),
            stats,
        )

        self.assertEqual(item["data"]["tags"], [{"tag": "preservar"}])
        self.assertEqual(stats["review_tags_removed"], 1)

    def test_current_review_duplicate_tag_is_preserved(self):
        class FakeZotero:
            def __init__(self):
                self.updated = []

            def update_item(self, item):
                self.updated.append(item)

        item = make_item("BOOK0001", "O que é a Psicologia", item_type="book")
        item["data"]["tags"] = [{"tag": zsync.REVIEW_DUPLICATE_TAG}]
        stats = {
            "current_review_duplicate_keys": {"BOOK0001"},
            "review_tags_removed": 0,
        }

        zsync.clear_stale_review_duplicate_tags(
            FakeZotero(),
            zsync.build_bibliographic_parent_index([item]),
            stats,
        )

        self.assertEqual(item["data"]["tags"], [{"tag": zsync.REVIEW_DUPLICATE_TAG}])
        self.assertEqual(stats["review_tags_removed"], 0)

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

    def test_desktop_recognizer_manifest_declares_update_url(self):
        manifest = json.loads(Path("zotero_sync_recognizer/manifest.json").read_text(encoding="utf-8"))
        zotero_app = manifest["applications"]["zotero"]
        self.assertEqual(zotero_app["id"], "zotero-sync-recognizer@example.com")
        self.assertTrue(zotero_app["update_url"].startswith("https://"))
        self.assertEqual(zotero_app["strict_max_version"], "9.*")

    def test_desktop_recognizer_bootstrap_has_fallback_parent_flow(self):
        bootstrap = Path("zotero_sync_recognizer/bootstrap.js").read_text(encoding="utf-8")
        self.assertIn("createFallbackParent", bootstrap)
        self.assertIn("fallbackParents", bootstrap)

    def test_desktop_recognizer_can_create_fallback_without_metadata_recognition(self):
        bootstrap = Path("zotero_sync_recognizer/bootstrap.js").read_text(encoding="utf-8")
        self.assertIn("payload.autoRecognize !== false", bootstrap)
        self.assertIn("if (autoRecognize && items.length)", bootstrap)
        self.assertIn("let items = [];", bootstrap)
        self.assertIn("return Zotero.Items.getAsync(item.id);", bootstrap)
        self.assertIn("fallbackPending: false", bootstrap)
        self.assertIn("result.fallbackPending = true;", bootstrap)
        self.assertIn("discardStandaloneAttachment", bootstrap)


    def test_sync_item_collections_to_drive_collection_replaces_managed_subset(self):
        class FakeZotero:
            def __init__(self):
                self.updated = []

            def update_item(self, item):
                self.updated.append(item)

        zot = FakeZotero()
        item = {"data": {"collections": ["OLDCOL", "FREEFORM"]}}
        changed = zsync.sync_item_collections_to_drive_collection(
            zot,
            "ITEM1",
            "NEWCOL",
            {"OLDCOL": {}, "NEWCOL": {}},
            item=item,
        )
        self.assertTrue(changed)
        self.assertEqual(item["data"]["collections"], ["FREEFORM", "NEWCOL"])
        self.assertEqual(zot.updated[0]["collections"], ["FREEFORM", "NEWCOL"])

    def test_remove_empty_directories_preserves_obsidian(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            empty = root / "A"
            empty.mkdir()
            protected = root / ".obsidian"
            protected.mkdir()
            stats = {}
            removed = zsync.remove_empty_directories(root, stats, "removed")
            self.assertEqual(removed, 1)
            self.assertFalse(empty.exists())
            self.assertTrue(protected.exists())
            self.assertEqual(stats["removed"], 1)

    def test_collect_nonempty_directory_paths_ignores_empty_dirs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "UNEB Psicologia 2026.1" / "Disciplina").mkdir(parents=True)
            (root / "UNEB Psicologia 2026.1" / "Disciplina" / "texto.pdf").write_bytes(b"x")
            (root / "UNEB Psicologia 2026.1" / "Vazia").mkdir(parents=True)
            discovered = zsync.collect_nonempty_directory_paths(root)
            self.assertEqual(discovered, ["UNEB Psicologia 2026.1/Disciplina"])

    def test_ensure_drive_content_collections_creates_missing_chain(self):
        class FakeZotero:
            def __init__(self):
                self.calls = []
                self.next_id = 0

            def create_collection(self, payload):
                self.next_id += 1
                key = f"COL{self.next_id}"
                entry = payload[0]
                self.calls.append((entry["name"], entry.get("parentCollection") or None))
                return {"successful": {"0": {"key": key}}}
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "UNEB Psicologia 2026.1" / "Nova Disciplina").mkdir(parents=True)
            (root / "UNEB Psicologia 2026.1" / "Nova Disciplina" / "texto.pdf").write_bytes(b"x")
            zot = FakeZotero()
            collection_by_key = {}
            collection_path_to_key = {}
            stats = {}
            changed = zsync.ensure_drive_content_collections(
                zot,
                str(root),
                collection_by_key,
                collection_path_to_key,
                stats,
            )
            self.assertTrue(changed)
            self.assertEqual(
                zot.calls,
                [("UNEB Psicologia 2026.1", None), ("Nova Disciplina", "COL1")],
            )
            self.assertEqual(
                collection_path_to_key["uneb psicologia 2026.1/nova disciplina"],
                "COL2",
            )
            self.assertEqual(stats["created_zotero_collections_from_drive"], 2)



if __name__ == "__main__":
    unittest.main()
