import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import zotero_sync_webdav as zsync

HOUR = 3600


class ComputeSha256QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "test.pdf"
        self.path.write_bytes(b"dummy")
        self.expected = hashlib.sha256(b"dummy").hexdigest()
        zsync._HASH_RUN_STATE["timeouts"] = 0
        self.addCleanup(zsync._HASH_RUN_STATE.__setitem__, "timeouts", 0)

    def quarantine(self, cache, age_seconds):
        zsync.set_cached_hash(
            str(self.path), zsync.HASH_TIMEOUT_QUARANTINE_MARK, cache, self.path.stat(),
            quarantined_at=time.time() - age_seconds,
        )

    def test_recent_quarantine_still_skips_the_file(self):
        cache = {}
        self.quarantine(cache, age_seconds=HOUR)
        self.assertIsNone(zsync.compute_sha256(str(self.path), cache=cache))

    def test_expired_quarantine_retries_and_stores_the_real_hash(self):
        cache = {}
        self.quarantine(cache, age_seconds=(zsync.HASH_QUARANTINE_TTL_HOURS + 1) * HOUR)
        self.assertEqual(zsync.compute_sha256(str(self.path), cache=cache), self.expected)
        entry = cache[zsync._normalize_cache_path(str(self.path))]
        self.assertEqual(entry["hash"], self.expected)
        self.assertNotIn("quarantined_at", entry)

    def test_quarantine_written_by_the_old_code_without_a_timestamp_is_retried(self):
        # Era o estado real de 32 PDFs grandes: quarentena para sempre, sem carimbo.
        cache = {}
        zsync.set_cached_hash(str(self.path), zsync.HASH_TIMEOUT_QUARANTINE_MARK, cache, self.path.stat())
        self.assertEqual(zsync.compute_sha256(str(self.path), cache=cache), self.expected)

    def test_a_changed_file_ignores_its_quarantine(self):
        cache = {}
        self.quarantine(cache, age_seconds=0)
        self.path.write_bytes(b"conteudo novo")
        self.assertEqual(
            zsync.compute_sha256(str(self.path), cache=cache), hashlib.sha256(b"conteudo novo").hexdigest())

    def test_a_timeout_stamps_the_quarantine(self):
        cache = {}
        with mock.patch("signal.alarm"), mock.patch.object(zsync.hashlib, "sha256", side_effect=TimeoutError):
            self.assertIsNone(zsync.compute_sha256(str(self.path), cache=cache))
        entry = cache[zsync._normalize_cache_path(str(self.path))]
        self.assertEqual(entry["hash"], zsync.HASH_TIMEOUT_QUARANTINE_MARK)
        self.assertAlmostEqual(entry["quarantined_at"], time.time(), delta=5)
        self.assertEqual(zsync._HASH_RUN_STATE["timeouts"], 1)


class HashTimeoutScalingTests(unittest.TestCase):
    def setUp(self):
        zsync._HASH_RUN_STATE["timeouts"] = 0
        self.addCleanup(zsync._HASH_RUN_STATE.__setitem__, "timeouts", 0)
        patcher = mock.patch.multiple(zsync, HASH_READ_TIMEOUT_SECONDS=30, HASH_TIMEOUT_MAX_SECONDS=300)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_small_files_keep_the_base_timeout(self):
        self.assertEqual(zsync.hash_timeout_for_size(5 * 1024 * 1024), 30)

    def test_large_files_get_more_time_up_to_the_cap(self):
        mib = 1024 * 1024
        self.assertEqual(zsync.hash_timeout_for_size(93 * mib), 124)  # 93 MiB a 0,75 MiB/s
        self.assertEqual(zsync.hash_timeout_for_size(334 * mib), 300)
        self.assertEqual(zsync.hash_timeout_for_size(10 * 1024 * mib), 300)

    def test_circuit_breaker_falls_back_to_the_base_timeout(self):
        zsync._HASH_RUN_STATE["timeouts"] = zsync.HASH_TIMEOUT_BREAKER
        self.assertEqual(zsync.hash_timeout_for_size(334 * 1024 * 1024), 30)

    def test_disabled_timeout_stays_disabled(self):
        with mock.patch.object(zsync, "HASH_READ_TIMEOUT_SECONDS", 0):
            self.assertEqual(zsync.hash_timeout_for_size(334 * 1024 * 1024), 0)

    def test_compute_sha256_uses_the_scaled_timeout_unless_one_is_given(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "a.pdf"
            path.write_bytes(b"x")
            with mock.patch.object(zsync, "hash_timeout_for_size", return_value=77), \
                    mock.patch("signal.alarm") as alarm:
                zsync.compute_sha256(str(path), cache={})
                self.assertEqual(alarm.call_args_list[0].args, (77,))
                alarm.reset_mock()
                zsync.compute_sha256(str(path), cache={}, timeout_seconds=9)
                self.assertEqual(alarm.call_args_list[0].args, (9,))


if __name__ == "__main__":
    unittest.main()
