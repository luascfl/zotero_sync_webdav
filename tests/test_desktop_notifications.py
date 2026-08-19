import unittest
from types import SimpleNamespace
from unittest.mock import call, mock_open, patch

import zotero_sync_webdav as zsync


class DesktopNotificationTests(unittest.TestCase):
    """Verify desktop notifications choose the correct backend."""

    def test_falls_back_to_gdbus_when_notify_send_is_unavailable(self):
        summary = "Sync complete"
        body = "2 new PDFs ready"

        with patch.object(zsync.shutil, "which", side_effect=[None, "/usr/bin/gdbus"]) as mock_which:
            with patch.object(
                zsync.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as mock_run:
                sent = zsync.send_desktop_notification(summary, body, icon="zotero")

        self.assertTrue(sent)
        mock_which.assert_any_call("notify-send")
        mock_which.assert_any_call("gdbus")
        self.assertEqual(mock_which.call_count, 2)
        mock_run.assert_called_once_with(
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.Notify",
                "Zotero Sync",
                "0",
                "zotero",
                summary,
                body,
                "[]",
                "{}",
                "5000",
            ],
            check=False,
        )

    def test_successful_notify_send_does_not_fall_back_to_gdbus(self):
        summary = "Sync complete"
        body = "2 new PDFs ready"

        with patch.object(zsync.shutil, "which", side_effect=["/usr/bin/notify-send"]) as mock_which:
            with patch.object(
                zsync.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=0),
            ) as mock_run:
                sent = zsync.send_desktop_notification(summary, body, icon="zotero")

        self.assertTrue(sent)
        mock_which.assert_called_once_with("notify-send")
        mock_run.assert_called_once_with(
            ["notify-send", "-a", "Zotero Sync", "-i", "zotero", summary, body],
            check=False,
        )

    def test_pending_queue_body_uses_singular_and_plural_wording(self):
        cases = [
            (
                "singular",
                1,
                "1 PDF novo está na fila. Abra o Zotero para sincronizá-lo.",
            ),
            (
                "plural",
                2,
                "2 PDFs novos estão na fila. Abra o Zotero para sincronizá-los.",
            ),
        ]

        for name, pending_count, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    zsync.build_pending_queue_notification_body(pending_count),
                    expected,
                )

    def test_first_open_sync_progress_notification_wording(self):
        progress_body = zsync.build_first_open_sync_notification_body()
        stage_body = zsync.build_sync_stage_notification_body(
            "Coletando anexos do Zotero"
        )

        self.assertEqual(zsync.SYNC_PROGRESS_NOTIFICATION_SUMMARY, "Sync em andamento")
        self.assertEqual(
            progress_body,
            "Zotero aberto detectado. Primeira sync iniciada.",
        )
        self.assertEqual(
            stage_body,
            "Etapa: Coletando anexos do Zotero.",
        )
        self.assertNotEqual(
            zsync.SYNC_PROGRESS_NOTIFICATION_SUMMARY,
            zsync.PENDING_QUEUE_NOTIFICATION_SUMMARY,
        )
        self.assertNotEqual(
            zsync.SYNC_PROGRESS_NOTIFICATION_SUMMARY,
            zsync.COMPLETION_NOTIFICATION_SUMMARY,
        )

        with patch.object(zsync, "send_desktop_notification") as mock_notify:
            zsync.send_sync_progress_notification(stage_body)

        mock_notify.assert_called_once_with(
            "Sync em andamento",
            "Etapa: Coletando anexos do Zotero.",
            icon="zotero",
        )

    def test_finalize_execution_skips_completion_alert_when_notifications_are_disabled(self):
        stats = {
            "pending_desktop_imports": ["alpha.pdf"],
            "added": 1,
            "skipped": 2,
            "errors": 0,
        }
        mocked_open = mock_open()

        with patch.object(zsync, "update_pending_import_queue_files") as mock_update_queue:
            with patch.object(zsync, "send_completion_notification") as mock_completion:
                with patch.object(zsync, "LOG_FILE_PATH", "/tmp/zotero-sync.log"):
                    with patch("builtins.open", mocked_open) as mock_file:
                        with patch.object(zsync, "datetime") as mock_datetime:
                            mock_datetime.now.return_value.isoformat.return_value = (
                                "2026-07-09T14:30:00"
                            )

                            zsync.finalize_execution(
                                stats,
                                "Resumo da sync",
                                notify_completion=False,
                            )

        mock_update_queue.assert_called_once_with(["alpha.pdf"])
        mock_file.assert_called_once_with(
            "/tmp/zotero-sync.log",
            "a",
            encoding="utf-8",
        )
        self.assertEqual(
            mocked_open().write.mock_calls,
            [
                call("\n"),
                call("Resumo da sync"),
                call("\n"),
                call("--- Execução finalizada: 2026-07-09T14:30:00 ---\n"),
            ],
        )
        mock_completion.assert_not_called()

    def test_run_adaptive_sync_only_notifies_on_first_loop_when_zotero_starts_open(self):
        with patch.object(
            zsync,
            "is_zotero_running",
            side_effect=[True, True, False],
        ) as mock_is_running:
            with patch.object(zsync, "run_sync_mode") as mock_run_sync_mode:
                with patch("time.sleep") as mock_sleep:
                    with patch.dict(
                        "os.environ",
                        {"ZOTERO_SYNC_INTERVAL_SECONDS": "7"},
                        clear=False,
                    ):
                        zsync.run_adaptive_sync()

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
        self.assertEqual(mock_is_running.call_count, 3)
        mock_sleep.assert_called_once_with(7)

    def test_send_completion_notification_uses_sync_concluido_summary(self):
        stats = {"added": 3, "skipped": 1, "errors": 2}

        self.assertEqual(zsync.COMPLETION_NOTIFICATION_SUMMARY, "Sync concluído")
        self.assertNotEqual(
            zsync.COMPLETION_NOTIFICATION_SUMMARY,
            zsync.PENDING_QUEUE_NOTIFICATION_SUMMARY,
        )

        with patch.object(zsync, "send_desktop_notification") as mock_notify:
            zsync.send_completion_notification(stats, None)

        mock_notify.assert_called_once_with(
            "Sync concluído",
            "Adicionados: 3 • Existentes: 1 • Erros: 2",
            icon="text-x-log",
            desktop_hint=None,
        )

if __name__ == "__main__":
    unittest.main()
