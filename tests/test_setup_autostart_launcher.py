import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import zotero_sync_webdav as zsync


class SetupAutostartLauncherTests(unittest.TestCase):
    """Verify the no-copy autostart launcher contract."""

    def test_run_setup_autostart_mode_passes_absolute_source_script_to_bash(self):
        extra_args = ["--dry-run", "--user"]
        expected_source = str(Path(zsync.__file__).resolve())

        with patch.object(
            zsync.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=23),
        ) as mock_run:
            with self.assertRaises(SystemExit) as raised:
                zsync.run_setup_autostart_mode(extra_args)

        self.assertEqual(raised.exception.code, 23)
        mock_run.assert_called_once()

        command = mock_run.call_args.args[0]
        self.assertEqual(command[0], "bash")
        self.assertEqual(command[2], expected_source)
        self.assertNotEqual(command[2], Path(expected_source).name)
        self.assertTrue(Path(command[2]).is_absolute())
        self.assertEqual(command[3:], extra_args)
        self.assertFalse(mock_run.call_args.kwargs["check"])

    def test_setup_autostart_shell_uses_launcher_without_copying_main_script(self):
        shell_script = zsync.SETUP_AUTOSTART_SHELL

        for snippet in [
            "ZSW_SOURCE_SCRIPT",
            "ZSW_PYTHON_BIN",
            "run_zotero_sync.sh",
            "ExecStart=$launcher_path",
        ]:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, shell_script)

        self.assertNotIn(
            'install -m 755 "$python_src" "$python_target"',
            shell_script,
        )


if __name__ == "__main__":
    unittest.main()
