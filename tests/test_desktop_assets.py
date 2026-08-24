import tempfile
import unittest
from pathlib import Path

import zotero_sync_webdav as zsync


class DesktopRecognizerAssetsTests(unittest.TestCase):
    def test_prefers_plugin_bundled_with_source_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            shared = root / "shared"
            (source / "zotero_sync_recognizer").mkdir(parents=True)
            (shared / "zotero_sync_recognizer").mkdir(parents=True)

            resolved = zsync.resolve_desktop_recognizer_plugin_dir(source, shared)

        self.assertEqual(resolved, source / "zotero_sync_recognizer")

    def test_uses_shared_assets_when_script_is_installed_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "installed-bin"
            shared = root / "shared"
            source.mkdir()
            (shared / "zotero_sync_recognizer").mkdir(parents=True)

            resolved = zsync.resolve_desktop_recognizer_plugin_dir(source, shared)

        self.assertEqual(resolved, shared / "zotero_sync_recognizer")


if __name__ == "__main__":
    unittest.main()
