import unittest
from unittest.mock import call, patch

import zotero_sync_webdav as zsync


class ZoteroWatchModeTests(unittest.TestCase):
    """Regression coverage for the immediate Zotero-open watcher mode."""

    def test_first_open_sync_progress_notification_mentions_detected_open_zotero(self):
        progress_body = zsync.build_first_open_sync_notification_body()

        self.assertEqual(zsync.SYNC_PROGRESS_NOTIFICATION_SUMMARY, "Sync em andamento")
        self.assertEqual(
            progress_body,
            "Zotero aberto detectado. Primeira sync iniciada.",
        )

        with patch.object(zsync, "send_desktop_notification") as mock_notify:
            zsync.send_sync_progress_notification(progress_body)

        mock_notify.assert_called_once_with(
            "Sync em andamento",
            "Zotero aberto detectado. Primeira sync iniciada.",
            icon="zotero",
        )

    def test_run_open_zotero_sync_loop_only_notifies_on_first_iteration_and_stops_when_zotero_closes(self):
        with patch.object(
            zsync,
            "is_zotero_running",
            side_effect=[True, False],
        ) as mock_is_running:
            with patch.object(zsync, "run_sync_mode") as mock_run_sync_mode:
                with patch("time.sleep") as mock_sleep:
                    zsync.run_open_zotero_sync_loop(11)

        mock_run_sync_mode.assert_has_calls(
            [
                call(
                    notification_policy={
                        "announce_start": True,
                        "progress": True,
                        "completion": True,
                    }
                ),
                call(
                    notification_policy={
                        "announce_start": False,
                        "progress": False,
                        "completion": False,
                    }
                ),
            ]
        )
        self.assertEqual(mock_run_sync_mode.call_count, 2)
        self.assertEqual(mock_is_running.call_count, 2)
        mock_sleep.assert_called_once_with(11)

    def test_run_zotero_open_watch_waits_for_open_then_starts_sync_loop_with_configured_interval(self):
        with patch.object(
            zsync,
            "is_zotero_running",
            side_effect=[False, False, True],
        ) as mock_is_running:
            with patch.object(
                zsync,
                "run_open_zotero_sync_loop",
                side_effect=SystemExit(0),
            ) as mock_run_loop:
                with patch("time.sleep") as mock_sleep:
                    with patch.dict(
                        "os.environ",
                        {
                            "ZOTERO_OPEN_WATCH_POLL_SECONDS": "4",
                            "ZOTERO_SYNC_INTERVAL_SECONDS": "19",
                        },
                        clear=False,
                    ):
                        with self.assertRaises(SystemExit) as raised:
                            zsync.run_zotero_open_watch()

        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(mock_is_running.call_count, 3)
        mock_sleep.assert_has_calls([call(4), call(4)])
        mock_run_loop.assert_called_once_with(19)

    def test_setup_autostart_shell_includes_watch_service_unit_and_enablement(self):
        shell_script = zsync.SETUP_AUTOSTART_SHELL

        for snippet in [
            "zotero-sync-watch.service",
            "ExecStart=$launcher_path watch-zotero",
            "systemctl --user enable zotero-sync-watch.service",
        ]:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, shell_script)


if __name__ == "__main__":
    unittest.main()
