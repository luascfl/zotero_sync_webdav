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

    def test_resolves_local_binary_when_systemd_path_omits_zotero(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            local_binary = home / ".local" / "bin" / "zotero"
            local_binary.parent.mkdir(parents=True)
            local_binary.touch()

            resolved = zsync.resolve_zotero_desktop_binary(
                configured_binary=None,
                path_binary=None,
                home_dir=home,
            )

        self.assertEqual(resolved, str(local_binary))

    def test_prefers_explicit_desktop_binary(self):
        self.assertEqual(
            zsync.resolve_zotero_desktop_binary(
                configured_binary="/opt/zotero/zotero",
                path_binary="/usr/bin/zotero",
            ),
            "/opt/zotero/zotero",
        )

    def test_profile_root_is_available_to_plugin_installer(self):
        self.assertEqual(
            zsync.ZOTERO_PROFILE_ROOT,
            Path.home() / ".zotero" / "zotero",
        )

    def test_stages_import_file_on_local_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "mounted" / "source.pdf"
            source.parent.mkdir()
            source.write_bytes(b"pdf-content")

            staged = zsync.stage_file_for_desktop_import(
                str(source),
                staging_dir=root / "staging",
            )

            self.assertNotEqual(staged, source)
            self.assertEqual(staged.name, source.name)
            self.assertEqual(staged.read_bytes(), b"pdf-content")


if __name__ == "__main__":
    unittest.main()
