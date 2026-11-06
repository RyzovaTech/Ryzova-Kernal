# SPDX-License-Identifier: GPL-3.0-only
"""Offline, fail-closed regression tests for pinned CI source handling."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pinned_source import fetch_pinned


class PinnedSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "artifact.tar.gz"
        self.data = b"safe-pinned-source\n"
        self.digest = hashlib.sha256(self.data).hexdigest()

    def test_cached_valid_source_requires_no_network(self):
        self.path.write_bytes(self.data)
        with patch("pinned_source.urllib.request.urlopen", side_effect=AssertionError("network used")):
            self.assertEqual(fetch_pinned(self.path, ["https://example.test/source"], self.digest, max_bytes=128), self.path)

    def test_corrupt_cache_is_rejected_without_redownload(self):
        self.path.write_bytes(b"tampered")
        with patch("pinned_source.urllib.request.urlopen", side_effect=AssertionError("network used")):
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                fetch_pinned(self.path, ["https://example.test/source"], self.digest, max_bytes=128)
        self.assertEqual(self.path.read_bytes(), b"tampered")

    def test_bad_mirror_falls_back_only_when_digest_matches(self):
        with patch("pinned_source.urllib.request.urlopen", side_effect=[
                io.BytesIO(b"wrong"), io.BytesIO(self.data)]) as mock:
            fetch_pinned(self.path, ["https://one.example/fixture", "https://two.example/fixture"], self.digest, max_bytes=128)
        self.assertEqual(mock.call_count, 2)
        self.assertEqual(self.path.read_bytes(), self.data)
        self.assertFalse(any(p.name.startswith(".artifact.tar.gz.") for p in self.path.parent.iterdir()))

    def test_offline_failure_leaves_no_archive(self):
        with patch("pinned_source.urllib.request.urlopen", side_effect=OSError("network unavailable")):
            with self.assertRaisesRegex(RuntimeError, "all pinned source mirrors failed"):
                fetch_pinned(self.path, ["https://one.example/fixture"], self.digest, max_bytes=128)
        self.assertFalse(self.path.exists())

    def test_oversized_archive_is_not_cached(self):
        with patch("pinned_source.urllib.request.urlopen", return_value=io.BytesIO(self.data)):
            with self.assertRaisesRegex(RuntimeError, "maximum size"):
                fetch_pinned(self.path, ["https://one.example/fixture"], self.digest, max_bytes=3)
        self.assertFalse(self.path.exists())

    def test_https_only(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            fetch_pinned(self.path, ["http://example.test/fixture"], self.digest, max_bytes=128)

    def test_invalid_hash_rejected_before_network(self):
        with self.assertRaisesRegex(ValueError, "64-character"):
            fetch_pinned(self.path, ["https://example.test/fixture"], "not-a-digest", max_bytes=128)


if __name__ == "__main__":
    unittest.main()
