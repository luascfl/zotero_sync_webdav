"""Regression tests for diagnostic reporting around missing target folders."""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import zotero_sync_webdav as zsync


class DiagnosticReportTests(unittest.TestCase):
    """Verify diagnostic output stays truthful when folder scanning fails."""

    def test_missing_target_folder_is_reported_as_failure(self):
        """A missing folder must surface a scan failure instead of a false success."""
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_folder = os.path.join(temp_dir, "missing-target-folder")

            missing_result = zsync.find_missing_drive_pdfs_in_zotero([], missing_folder)

            self.assertFalse(missing_result["scan_ok"])
            self.assertEqual(missing_result["missing"], [])
            self.assertEqual(missing_result["errors"], [f"Pasta não encontrada: {missing_folder}"])

            report_output = io.StringIO()
            with redirect_stdout(report_output):
                zsync.print_diagnostic_report([], missing_result)

            report = report_output.getvalue()
            self.assertIn(f"Pasta não encontrada: {missing_folder}", report)
            self.assertIn(
                "❌ Não foi possível verificar a pasta do drive. O relatório acima não confirma reconciliação com o Zotero.",
                report,
            )
            self.assertNotIn("✅ Todos os PDFs da pasta já estão no Zotero.", report)


if __name__ == "__main__":
    unittest.main()
