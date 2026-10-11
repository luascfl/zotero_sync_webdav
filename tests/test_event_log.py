"""Log unificado com códigos de erro: catálogo, run_id, eventos estruturados, retenção e relatório."""

import hashlib
import io
import json
import os
import re
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import zotero_sync_webdav as zsync

CODE_RE = re.compile(r"ZSW-[A-Z]+-\d{3}")


class EventCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log_dir = Path(self.tmp.name)
        patcher = mock.patch.object(zsync, "LOG_DIR", str(self.log_dir))
        patcher.start()
        self.addCleanup(patcher.stop)
        zsync.RUN.reset()
        self.addCleanup(zsync.RUN.reset)

    def rows(self):
        path = Path(zsync.events_file_path())
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class CatalogTests(unittest.TestCase):
    def test_every_code_is_well_formed_and_explains_cause_and_action(self):
        self.assertGreaterEqual(len(zsync.ERROR_CATALOG), 8)
        for code, entry in zsync.ERROR_CATALOG.items():
            with self.subTest(code=code):
                self.assertRegex(code, CODE_RE)
                self.assertIn(entry["severity"], ("error", "pending", "warning"))
                for field in ("title", "cause", "action"):
                    self.assertTrue(entry[field].strip(), field)

    def test_every_code_used_in_the_source_is_in_the_catalog(self):
        source = Path(zsync.__file__).read_text(encoding="utf-8")
        used = set(re.findall(r'log_event\(\s*"(ZSW-[A-Z]+-\d{3})"', source))
        self.assertTrue(used)
        self.assertEqual(used - set(zsync.ERROR_CATALOG), set())

    def test_explain_prints_cause_and_action_and_rejects_unknown_codes(self):
        out = io.StringIO()
        with redirect_stdout(out):
            zsync.run_explain_mode("zsw-hash-001")
        self.assertIn("Causa:", out.getvalue())
        self.assertIn("Ação:", out.getvalue())
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            zsync.run_explain_mode("ZSW-NADA-999")
        listing = io.StringIO()
        with redirect_stdout(listing):
            zsync.run_explain_mode(None)
        self.assertIn("ZSW-HASH-001", listing.getvalue())


class LogEventTests(EventCase):
    def test_event_goes_to_the_readable_log_and_the_structured_file_with_the_run_id(self):
        with self.assertLogs(level="WARNING") as captured:
            zsync.log_event("ZSW-HASH-003", "falha em '%s'", "/x/a.pdf", subject="/x/a.pdf")
        self.assertIn("[ZSW-HASH-003] falha em '/x/a.pdf'", captured.output[0])
        (row,) = self.rows()
        self.assertEqual(row["code"], "ZSW-HASH-003")
        self.assertEqual(row["run_id"], zsync.RUN.run_id)
        self.assertEqual((row["severity"], row["area"]), ("pending", "hash"))

    def test_unknown_code_is_a_programming_error(self):
        with self.assertRaises(KeyError):
            zsync.log_event("ZSW-XXX-000", "nunca")

    def test_same_subject_counts_once_per_run_but_a_new_run_counts_again(self):
        with self.assertLogs(level="WARNING"):
            for _ in range(5):
                zsync.log_event("ZSW-HASH-002", "pulado '%s'", "/x/a.pdf", subject="/x/a.pdf")
        self.assertEqual(zsync.RUN.counts["ZSW-HASH-002"], 1)
        self.assertEqual(len(self.rows()), 1)
        first_run = zsync.RUN.run_id
        zsync.RUN.reset()
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-HASH-002", "pulado '%s'", "/x/a.pdf", subject="/x/a.pdf")
        self.assertNotEqual(zsync.RUN.run_id, first_run)
        self.assertEqual(zsync.RUN.counts["ZSW-HASH-002"], 1)

    def test_every_log_line_carries_the_run_id(self):
        record = __import__("logging").LogRecord("x", 20, __file__, 1, "msg", (), None)
        zsync._RunIdFilter().filter(record)
        self.assertEqual(record.run_id, zsync.RUN.run_id)
        self.assertRegex(zsync.RUN.run_id, r"^[0-9a-f]{8}$")


class OutcomeTests(EventCase):
    def test_errors_and_pending_reach_the_stats_once(self):
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-HASH-001", "timeout", subject="a")
            zsync.log_event("ZSW-HASH-001", "timeout", subject="b")
            zsync.log_event("ZSW-HASH-002", "pulado", subject="c")
            zsync.log_event("ZSW-SYS-001", "lock")
        stats = {"errors": 1}
        zsync.apply_run_events_to_stats(stats)
        zsync.apply_run_events_to_stats(stats)  # idempotente
        self.assertEqual(stats["errors"], 3)
        self.assertEqual(stats["coded_errors"], 2)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["run_id"], zsync.RUN.run_id)

    def test_event_already_counted_by_the_caller_is_not_counted_twice(self):
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-DESK-001", "falha", subject="a.pdf", in_stats=True)
        stats = {"errors": 1}
        zsync.apply_run_events_to_stats(stats)
        self.assertEqual(stats["errors"], 1)
        self.assertEqual(zsync.RUN.counts["ZSW-DESK-001"], 1)

    def test_clean_run_stays_clean(self):
        stats = {"errors": 0}
        zsync.apply_run_events_to_stats(stats)
        self.assertEqual((stats["errors"], stats["pending"]), (0, 0))
        self.assertEqual(zsync.render_run_events_summary(), "")

    def test_summary_lists_codes_errors_first_and_points_to_explain(self):
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-HASH-002", "pulado", subject="c")
            zsync.log_event("ZSW-HASH-001", "timeout", subject="a")
        summary = zsync.render_run_events_summary()
        self.assertLess(summary.index("ZSW-HASH-001"), summary.index("ZSW-HASH-002"))
        self.assertIn(zsync.RUN.run_id, summary)
        self.assertIn("explicar", summary)

    def test_completion_notification_and_status_show_pending(self):
        body = zsync.build_completion_notification_body({"added": 0, "skipped": 5, "pending": 3, "errors": 0}, None)
        self.assertIn("Pendências: 3", body)
        clean = zsync.build_completion_notification_body({"added": 0, "skipped": 5}, None)
        self.assertNotIn("Pendências", clean)
        snapshot = zsync.build_sync_status_snapshot({"pending": 3}, "running", "x")
        self.assertEqual(snapshot["counts"]["pending"], 3)


class HashEventsTests(EventCase):
    def setUp(self):
        super().setUp()
        self.file = self.log_dir / "a.pdf"
        self.file.write_bytes(b"dummy")
        zsync._HASH_RUN_STATE["timeouts"] = 0
        self.addCleanup(zsync._HASH_RUN_STATE.__setitem__, "timeouts", 0)

    def timeout_once(self, cache):
        zsync.RUN.reset()
        with mock.patch("signal.alarm"), mock.patch.object(zsync.hashlib, "sha256", side_effect=TimeoutError), \
                self.assertLogs(level="WARNING"):
            self.assertIsNone(zsync.compute_sha256(str(self.file), cache=cache))

    def expire_quarantine(self, cache):
        cache[zsync._normalize_cache_path(str(self.file))]["quarantined_at"] -= (
            zsync.HASH_QUARANTINE_TTL_HOURS + 1) * 3600

    def severities(self):
        return {sev: n for (code, sev), n in zsync.RUN.by_severity.items() if code == "ZSW-HASH-001"}

    def test_the_first_timeout_of_a_file_is_a_pending_not_an_error(self):
        cache = {}
        self.timeout_once(cache)
        self.assertEqual(self.severities(), {"pending": 1})
        stats = {"errors": 0}
        zsync.apply_run_events_to_stats(stats)
        self.assertEqual((stats["errors"], stats["pending"]), (0, 1))
        self.assertEqual(self.rows()[0]["severity"], "pending")
        self.assertEqual(self.rows()[0]["attempts"], 1)

    def test_the_same_file_timing_out_again_after_the_quarantine_becomes_an_error(self):
        cache = {}
        self.timeout_once(cache)
        self.expire_quarantine(cache)
        self.timeout_once(cache)
        self.assertEqual(self.severities(), {"error": 1})
        stats = {"errors": 0}
        zsync.apply_run_events_to_stats(stats)
        self.assertEqual((stats["errors"], stats["pending"]), (1, 0))
        self.assertEqual(cache[zsync._normalize_cache_path(str(self.file))]["timeout_count"], 2)

    def test_a_changed_file_starts_over_as_a_first_failure(self):
        cache = {}
        self.timeout_once(cache)
        self.expire_quarantine(cache)
        self.file.write_bytes(b"outro conteudo, tamanho diferente")
        self.timeout_once(cache)
        self.assertEqual(self.severities(), {"pending": 1})

    def test_a_successful_read_forgets_the_failure_history(self):
        cache = {}
        self.timeout_once(cache)
        self.expire_quarantine(cache)
        zsync.RUN.reset()
        self.assertEqual(zsync.compute_sha256(str(self.file), cache=cache), hashlib.sha256(b"dummy").hexdigest())
        entry = cache[zsync._normalize_cache_path(str(self.file))]
        self.assertEqual(entry["hash"], hashlib.sha256(b"dummy").hexdigest())
        self.assertNotIn("timeout_count", entry)
        self.assertNotIn("quarantined_at", entry)
        self.assertEqual(zsync.RUN.counts, {})

    def test_skips_inside_the_quarantine_window_are_pending_and_counted_once(self):
        cache = {}
        self.timeout_once(cache)
        zsync.RUN.reset()
        with self.assertLogs(level="WARNING"):
            self.assertIsNone(zsync.compute_sha256(str(self.file), cache=cache))
            self.assertIsNone(zsync.compute_sha256(str(self.file), cache=cache))
        self.assertEqual(zsync.RUN.counts, {"ZSW-HASH-002": 1})
        stats = {"errors": 0}
        zsync.apply_run_events_to_stats(stats)
        self.assertEqual((stats["errors"], stats["pending"]), (0, 1))


    def test_a_file_that_hashes_fine_emits_nothing(self):
        self.assertEqual(zsync.compute_sha256(str(self.file), cache={}), hashlib.sha256(b"dummy").hexdigest())
        self.assertEqual(zsync.RUN.counts, {})


class QueryTests(EventCase):
    def seed(self):
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-HASH-001", "timeout em a", subject="a")
            zsync.log_event("ZSW-FOLD-001", "conflito x", subject="x")
        first = zsync.RUN.run_id
        zsync.RUN.reset()
        with self.assertLogs(level="WARNING"):
            zsync.log_event("ZSW-HASH-001", "timeout em b", subject="b")
        return first

    def query(self, **kwargs):
        out = io.StringIO()
        with redirect_stdout(out):
            zsync.run_events_mode(kwargs.get("code"), kwargs.get("run"), kwargs.get("days", 1), kwargs.get("limit", 50))
        return out.getvalue()

    def test_filters_by_code_and_by_run(self):
        first = self.seed()
        by_code = self.query(code="zsw-hash-001")
        self.assertIn("timeout em a", by_code)
        self.assertIn("timeout em b", by_code)
        self.assertNotIn("conflito x", by_code)
        self.assertIn("2 evento(s)", by_code)
        by_run = self.query(run=first)
        self.assertIn("conflito x", by_run)
        self.assertNotIn("timeout em b", by_run)

    def test_last_run_and_limit(self):
        self.seed()
        last = self.query(run="ultimo")
        self.assertIn("timeout em b", last)
        self.assertNotIn("timeout em a", last)
        limited = self.query(limit=1)
        self.assertEqual(limited.count("ZSW-HASH-001"), 1)
        self.assertIn("-- 3 evento(s) (mostrando os últimos 1)", limited)
        self.assertEqual(self.query(code="ZSW-COLL-001").strip(), "-- 0 evento(s)")


class RetentionTests(EventCase):
    def touch(self, name):
        (self.log_dir / name).write_text("x", encoding="utf-8")

    def test_purge_removes_only_expired_dated_logs_and_events(self):
        today = datetime(2026, 10, 11)
        old = (today - timedelta(days=zsync.LOG_RETENTION_DAYS + 1)).strftime("%Y-%m-%d")
        edge = (today - timedelta(days=zsync.LOG_RETENTION_DAYS)).strftime("%Y-%m-%d")
        recent = (today - timedelta(days=1)).strftime("%Y-%m-%d")
        for name in (
            f"zotero_sync_{old}.log", f"events-{old}.jsonl", f"zotero_sync_{edge}.log",
            f"zotero_sync_{recent}.log", f"events-{recent}.jsonl",
            "zotero_sync_today.log", "zotero_sync_duplicates_report.log", "outro.txt",
        ):
            self.touch(name)
        self.assertEqual(zsync.purge_old_logs(today=today), 2)
        left = sorted(os.listdir(self.log_dir))
        self.assertNotIn(f"zotero_sync_{old}.log", left)
        self.assertNotIn(f"events-{old}.jsonl", left)
        for kept in (f"zotero_sync_{edge}.log", f"zotero_sync_{recent}.log", "zotero_sync_today.log",
                     "zotero_sync_duplicates_report.log", "outro.txt"):
            self.assertIn(kept, left)

    def test_yesterdays_log_is_archived_instead_of_overwritten(self):
        date_file = self.log_dir / ".last_log_date"
        (self.log_dir / "zotero_sync_today.log").write_text("falha da madrugada\n", encoding="utf-8")
        date_file.write_text("2026-10-10", encoding="utf-8")
        with mock.patch.object(zsync, "LOG_DATE_FILE", str(date_file)), \
                mock.patch.object(zsync, "LOG_FILE_NAME", "zotero_sync_today.log"):
            path = zsync.prepare_daily_log_file()
        self.assertEqual((self.log_dir / "zotero_sync_2026-10-10.log").read_text(encoding="utf-8"),
                         "falha da madrugada\n")
        self.assertIn("Log diário", Path(path).read_text(encoding="utf-8"))
        self.assertNotIn("madrugada", Path(path).read_text(encoding="utf-8"))

    def test_same_day_log_is_appended_not_archived(self):
        date_file = self.log_dir / ".last_log_date"
        (self.log_dir / "zotero_sync_today.log").write_text("linha antiga\n", encoding="utf-8")
        date_file.write_text(datetime.now().strftime("%Y-%m-%d"), encoding="utf-8")
        with mock.patch.object(zsync, "LOG_DATE_FILE", str(date_file)):
            path = zsync.prepare_daily_log_file()
        self.assertIn("linha antiga", Path(path).read_text(encoding="utf-8"))
        self.assertEqual([n for n in os.listdir(self.log_dir) if re.fullmatch(r"zotero_sync_\d{4}.*\.log", n)], [])


class WatcherTests(unittest.TestCase):
    def test_a_sync_that_exits_with_errors_does_not_kill_the_watcher_loop(self):
        zsync.RUN.reset()
        with mock.patch.object(zsync, "LOG_DIR", tempfile.mkdtemp()), \
                mock.patch.object(zsync, "is_zotero_running", side_effect=[True, True, True, False]), \
                mock.patch.object(zsync, "run_sync_mode", side_effect=[SystemExit(1), None]) as run_sync, \
                mock.patch("time.sleep"), self.assertLogs(level="WARNING") as captured:
            zsync.run_open_zotero_sync_loop(5)
        self.assertEqual(run_sync.call_count, 2)
        self.assertTrue(any("ZSW-SYS-003" in line for line in captured.output))


if __name__ == "__main__":
    unittest.main()
