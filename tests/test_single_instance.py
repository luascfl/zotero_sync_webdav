import unittest
from unittest.mock import patch, MagicMock
import tempfile
import os
import sys

from zotero_sync_webdav import ensure_single_instance

class TestSingleInstanceLock(unittest.TestCase):
    def setUp(self):
        import zotero_sync_webdav
        if '_SINGLE_INSTANCE_LOCK_FD' in zotero_sync_webdav.__dict__:
            del zotero_sync_webdav.__dict__['_SINGLE_INSTANCE_LOCK_FD']

    @patch('fcntl.flock')
    @patch('os.open')
    @patch('tempfile.gettempdir', return_value='/tmp')
    def test_ensure_single_instance_success(self, mock_gettempdir, mock_open, mock_flock):
        # Simulate successful file opening and locking
        mock_open.return_value = 99
        mock_flock.return_value = None
        
        # Ensure it does not raise SystemExit
        try:
            ensure_single_instance()
        except SystemExit:
            self.fail("ensure_single_instance() raised SystemExit unexpectedly!")
            
        mock_open.assert_called_once()
        mock_flock.assert_called_once()
        
    @patch('fcntl.flock')
    @patch('os.open')
    @patch('tempfile.gettempdir', return_value='/tmp')
    def test_ensure_single_instance_collision(self, mock_gettempdir, mock_open, mock_flock):
        # Simulate lock collision
        mock_open.return_value = 99
        mock_flock.side_effect = BlockingIOError("Resource temporarily unavailable")
        
        with self.assertRaises(SystemExit) as cm:
            ensure_single_instance()
            
        self.assertEqual(cm.exception.code, 1)

if __name__ == '__main__':
    unittest.main()
