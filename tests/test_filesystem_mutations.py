"""Tests for US-002: filesystem mutation helpers."""
import os
import shutil
import tempfile
import time
import unittest

import zotero_sync_webdav as zsync


class RenameWebdavFileTests(unittest.TestCase):
    """Test rename_webdav_file helper."""

    def test_rename_to_unused_name(self):
        """Successful rename updates path."""
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "Cópia de Artigo.pdf")
            with open(src, "w") as f:
                f.write("content")
            result = zsync.rename_webdav_file(src, "Artigo.pdf")
            expected = os.path.join(td, "Artigo.pdf")
            self.assertEqual(result, expected)
            self.assertTrue(os.path.exists(expected))
            self.assertFalse(os.path.exists(src))

    def test_rename_destination_exists(self):
        """When destination exists, original path is returned unchanged."""
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "Cópia de Artigo.pdf")
            dst = os.path.join(td, "Artigo.pdf")
            with open(src, "w") as f:
                f.write("copy content")
            with open(dst, "w") as f:
                f.write("original content")
            result = zsync.rename_webdav_file(src, "Artigo.pdf")
            # Should not overwrite
            self.assertEqual(result, src)
            self.assertTrue(os.path.exists(src))
            self.assertTrue(os.path.exists(dst))
            with open(dst) as f:
                self.assertEqual(f.read(), "original content")


class CopyToLocalStorageTests(unittest.TestCase):
    """Test copy_to_local_storage helper."""

    def test_copy_creates_key_directory(self):
        """Copies file into LOCAL_COPY_DIR/<key>/ structure and returns 'copied'."""
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "test.pdf")
            with open(src, "wb") as f:
                f.write(b"pdf content")
            orig_dir = zsync.LOCAL_COPY_DIR
            try:
                zsync.LOCAL_COPY_DIR = os.path.join(td, "storage")
                result = zsync.copy_to_local_storage(src, "TESTKEY1")
                self.assertEqual(result, "copied")
                dest = os.path.join(td, "storage", "TESTKEY1", "test.pdf")
                self.assertTrue(os.path.exists(dest))
            finally:
                zsync.LOCAL_COPY_DIR = orig_dir

    def test_copy_existing_file_returns_exists(self):
        """When destination already exists, returns 'exists'."""
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "test.pdf")
            with open(src, "wb") as f:
                f.write(b"pdf content")
            orig_dir = zsync.LOCAL_COPY_DIR
            try:
                zsync.LOCAL_COPY_DIR = os.path.join(td, "storage")
                key_dir = os.path.join(zsync.LOCAL_COPY_DIR, "TESTKEY2")
                os.makedirs(key_dir, exist_ok=True)
                existing = os.path.join(key_dir, "test.pdf")
                with open(existing, "wb") as f:
                    f.write(b"already here")
                result = zsync.copy_to_local_storage(src, "TESTKEY2")
                self.assertEqual(result, "exists")
            finally:
                zsync.LOCAL_COPY_DIR = orig_dir

    def test_copy_no_local_dir_returns_none(self):
        """When LOCAL_COPY_DIR is empty, returns None."""
        orig_dir = zsync.LOCAL_COPY_DIR
        try:
            zsync.LOCAL_COPY_DIR = ""
            with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
                result = zsync.copy_to_local_storage(f.name, "KEY")
                self.assertIsNone(result)
        finally:
            zsync.LOCAL_COPY_DIR = orig_dir


class HashCacheTests(unittest.TestCase):
    """Test hash cache lookup and entry rename."""

    def test_set_and_get_cached_hash(self):
        """Set a hash, retrieve it."""
        cache = {}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            path = f.name
        try:
            stat = os.stat(path)
            zsync.set_cached_hash(path, "abc123", cache, stat)
            result = zsync.get_cached_hash(path, cache, stat)
            self.assertEqual(result, "abc123")
        finally:
            os.unlink(path)

    def test_rename_cache_entry(self):
        """Renaming moves the cache entry."""
        cache = {}
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "old.pdf")
            new = os.path.join(td, "new.pdf")
            with open(old, "w") as f:
                f.write("data")
            stat = os.stat(old)
            zsync.set_cached_hash(old, "hash1", cache, stat)
            os.rename(old, new)
            zsync.rename_cache_entry(cache, old, new)
            norm_old = zsync._normalize_cache_path(old)
            norm_new = zsync._normalize_cache_path(new)
            self.assertNotIn(norm_old, cache)
            self.assertIn(norm_new, cache)
            self.assertEqual(cache[norm_new]["hash"], "hash1")

    def test_remove_cache_entry(self):
        """Removing drops the entry."""
        cache = {}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            path = f.name
        try:
            stat = os.stat(path)
            zsync.set_cached_hash(path, "xyz", cache, stat)
            norm = zsync._normalize_cache_path(path)
            self.assertIn(norm, cache)
            zsync.remove_cache_entry(cache, path)
            self.assertNotIn(norm, cache)
        finally:
            os.unlink(path)

    def test_cache_invalidated_on_mtime_change(self):
        """Stale mtime returns None."""
        cache = {}
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"v1")
            path = f.name
        try:
            stat1 = os.stat(path)
            zsync.set_cached_hash(path, "hash_v1", cache, stat1)
            time.sleep(0.05)
            with open(path, "wb") as f:
                f.write(b"v2 with different size")
            stat2 = os.stat(path)
            result = zsync.get_cached_hash(path, cache, stat2)
            self.assertIsNone(result)
        finally:
            os.unlink(path)


class RelocateDriveFileTests(unittest.TestCase):
    """Test relocate_drive_file helper."""

    def test_relocate_creates_subdirectories(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "file.pdf")
            with open(src, "w") as f:
                f.write("data")
            desired = os.path.join(td, "sub", "dir", "file.pdf")
            stats = {'renamed_webdav': 0}
            result = zsync.relocate_drive_file(src, desired, None, stats)
            self.assertEqual(result, desired)
            self.assertTrue(os.path.exists(desired))
            self.assertFalse(os.path.exists(src))

    def test_relocate_collision_returns_original(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "file.pdf")
            dst = os.path.join(td, "dest.pdf")
            with open(src, "w") as f:
                f.write("src data")
            with open(dst, "w") as f:
                f.write("dst data")
            stats = {'renamed_webdav': 0}
            result = zsync.relocate_drive_file(src, dst, None, stats)
            # Collision: should return original path
            self.assertEqual(result, src)


if __name__ == "__main__":
    unittest.main()
