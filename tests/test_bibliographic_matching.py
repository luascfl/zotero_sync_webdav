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


if __name__ == "__main__":
    unittest.main()
