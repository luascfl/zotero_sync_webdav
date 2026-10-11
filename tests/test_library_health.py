"""Relatório de saúde da biblioteca: somente leitura, só pela API e sem títulos."""

import importlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
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

SECRET_TITLE = "ZZTITULOSECRETO de um artigo que ninguem pode ver"
SECRET_FILE = "ZZARQUIVOSECRETO.pdf"
SECRET_COLLECTION = "ZZCOLECAOSECRETA"
LONG_TITLE = "Um titulo suficientemente longo para identificar duplicata bibliografica"


def article(key, title=LONG_TITLE, doi="", collections=(), tags=()):
    return {"key": key, "data": {
        "key": key, "itemType": "journalArticle", "title": title, "DOI": doi, "date": "2024",
        "creators": [{"creatorType": "author", "lastName": "Silva"}],
        "collections": list(collections), "tags": [{"tag": tag} for tag in tags],
        "dateAdded": "2025-01-01T00:00:00Z",
    }}


def pdf(key, parent=None, filename=SECRET_FILE):
    data = {"key": key, "itemType": "attachment", "filename": filename,
            "contentType": "application/pdf", "dateAdded": "2025-01-01T00:00:00Z"}
    if parent:
        data["parentItem"] = parent
    return {"key": key, "data": data}


def collection(key, name, parent=None):
    return {"key": key, "version": 1, "data": {
        "key": key, "name": name, "parentCollection": parent or False}}


class ReportContentTests(unittest.TestCase):
    def test_counts_and_standalone_pdfs(self):
        items = [
            article("A1", collections=["C1"]),
            article("A2", title="Outro titulo completamente diferente do primeiro"),
            pdf("P1", parent="A1"),
            pdf("P2"),
        ]
        report = zsync.build_library_health_report(items, [collection("C1", "Pasta")])
        self.assertEqual(report["counts"]["items"], 4)
        self.assertEqual(report["counts"]["bibliographic"], 2)
        self.assertEqual(report["counts"]["pdf_attachments"], 2)
        self.assertEqual(report["counts"]["unfiled_bibliographic"], 1)
        self.assertEqual(report["standalone_pdf_attachments"], ["P2"])

    def test_duplicate_groups_by_doi_and_by_title(self):
        items = [
            article("D1", title="Primeiro artigo com doi igual e titulo sem relacao alguma", doi="10.1000/abc"),
            article("D2", title="Segundo artigo com doi igual e titulo sem relacao nenhuma", doi="10.1000/abc"),
            article("T1"),
            article("T2"),
            article("U1", title="Artigo unico que nao tem nenhum duplicado na biblioteca"),
        ]
        groups = zsync.build_library_health_report(items, [])["bibliographic_duplicate_groups"]
        self.assertEqual(sorted(sorted(g["keys"]) for g in groups), [["D1", "D2"], ["T1", "T2"]])
        by_kind = {g["kind"]: g for g in groups}
        self.assertTrue(by_kind["doi"]["auto_removable"])
        self.assertFalse(by_kind["title+type"]["auto_removable"])

    def test_empty_collections_ignore_used_ones_and_parents(self):
        items = [article("A1", collections=["USED"])]
        collections = [
            collection("USED", "Usada"),
            collection("EMPTY", "Vazia"),
            collection("PARENT", "Pai"),
            collection("CHILD", "Filha", parent="PARENT"),
        ]
        report = zsync.build_library_health_report(items, collections)
        self.assertEqual(sorted(report["empty_collections"]), ["CHILD", "EMPTY"])

    def test_sibling_collections_with_the_same_core_name(self):
        collections = [
            collection("K1", "Seminario de Pesquisa"),
            collection("K2", "Seminario de Pesquisa [Lucas]"),
            collection("K3", "Outra"),
            collection("K4", "Seminario de Pesquisa", parent="K3"),
        ]
        report = zsync.build_library_health_report([], collections)
        self.assertEqual(report["sibling_duplicate_collections"], [["K1", "K2"]])

    def test_items_with_the_review_tag(self):
        items = [article("R1", tags=[zsync.REVIEW_DUPLICATE_TAG]), article("R2", tags=["outra"])]
        self.assertEqual(zsync.build_library_health_report(items, [])["review_tagged_items"], ["R1"])


class PrivacyTests(unittest.TestCase):
    """O repositório é público: nada que identifique conteúdo pode sair no relatório."""

    def setUp(self):
        self.items = [
            article("A1", title=SECRET_TITLE, collections=["C1"]),
            article("A2", title=SECRET_TITLE),
            pdf("P1", filename=SECRET_FILE),
        ]
        self.collections = [collection("C1", SECRET_COLLECTION), collection("C2", SECRET_COLLECTION + " [Lucas]")]

    def test_report_and_markdown_never_carry_titles_filenames_or_collection_names(self):
        report = zsync.build_library_health_report(self.items, self.collections)
        markdown = zsync.render_library_health_markdown(report, fetch_mode="full")
        for secret in (SECRET_TITLE, SECRET_FILE, SECRET_COLLECTION, "ZZ"):
            self.assertNotIn(secret, json.dumps(report, ensure_ascii=False))
            self.assertNotIn(secret, markdown)
        self.assertIn("`A1+A2`", markdown)
        self.assertIn("`P1`", markdown)


class RenderTests(unittest.TestCase):
    def test_clean_library_says_nothing_needs_attention(self):
        report = zsync.build_library_health_report([article("A1", collections=["C1"])], [collection("C1", "x")])
        markdown = zsync.render_library_health_markdown(report)
        self.assertIn("Nenhum.", markdown)
        self.assertNotIn("Verificação", markdown)

    def test_long_key_lists_are_truncated(self):
        items = [pdf(f"S{i:03d}") for i in range(40)]
        markdown = zsync.render_library_health_markdown(
            zsync.build_library_health_report(items, []), max_keys=5)
        self.assertIn("e mais 35", markdown)
        self.assertNotIn("S006", markdown)


class ModeTests(unittest.TestCase):
    def test_only_api_credentials_are_required_when_there_is_no_target_folder(self):
        with mock.patch.object(zsync, "load_config"), \
                mock.patch.object(zsync, "LIBRARY_ID", "1"), \
                mock.patch.object(zsync, "API_KEY", "key"), \
                mock.patch.object(zsync, "TARGET_FOLDER_RAW", ""):
            zsync.check_environment_requirements(require_target=False)
            with self.assertRaises(RuntimeError) as raised:
                zsync.check_environment_requirements()
        self.assertIn("ZOTERO_SYNC_TARGET_FOLDER", str(raised.exception))
        self.assertNotIn("ZOTERO_API_KEY", str(raised.exception))

    def test_mode_prints_the_report_without_touching_the_drive_or_the_lock(self):
        fake_cache = SimpleNamespace(
            refresh=lambda: "full", all_items=lambda: [article("A1", title=SECRET_TITLE)], last_mode="full")
        output = io.StringIO()
        with mock.patch.object(zsync, "connect_zotero_client", return_value=object()) as connect, \
                mock.patch.object(zsync, "get_library_cache", return_value=fake_cache), \
                mock.patch.object(zsync, "fetch_zotero_collections", return_value=[]), \
                mock.patch.object(zsync, "ensure_single_instance") as lock, \
                redirect_stdout(output):
            zsync.run_library_health_mode()
        connect.assert_called_once_with(require_target=False)
        lock.assert_not_called()
        self.assertIn("Saúde da biblioteca Zotero", output.getvalue())
        self.assertNotIn(SECRET_TITLE, output.getvalue())

    def test_api_failure_exits_nonzero_and_reports_only_the_error_type(self):
        output = io.StringIO()
        with mock.patch.object(
                zsync, "connect_zotero_client", side_effect=ValueError("https://api.zotero.org/users/1?key=SEGREDO")), \
                redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                zsync.run_library_health_mode()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("ValueError", output.getvalue())
        self.assertNotIn("SEGREDO", output.getvalue())

    def test_cli_exposes_the_subcommand(self):
        args = zsync.build_cli_parser().parse_args(["biblioteca-relatorio"])
        self.assertEqual(args.command, "biblioteca-relatorio")


if __name__ == "__main__":
    unittest.main()
