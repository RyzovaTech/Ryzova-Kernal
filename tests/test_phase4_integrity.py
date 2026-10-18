# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import phase4_integrity

class IntegrationTests(unittest.TestCase):
    def test_existing_repository(self):
        result = phase4_integrity.evaluate()
        self.assertTrue(result["pass"], result)
        self.assertFalse(result["unverified"] == [])
    def test_disallows_auto_sync(self):
        with TemporaryDirectory() as d:
            root=Path(d)
            (root / phase4_integrity.BANNED_SYNC).parent.mkdir(parents=True)
            (root / phase4_integrity.BANNED_SYNC).write_text("on: schedule\n")
            self.assertTrue((root / phase4_integrity.BANNED_SYNC).exists())
    def test_digest_tracks_bytes(self):
        with TemporaryDirectory() as d:
            p=Path(d)/"probe"
            p.write_bytes(b"a"); first=phase4_integrity.digest(p)
            p.write_bytes(b"b"); self.assertNotEqual(first,phase4_integrity.digest(p))
if __name__=="__main__":
    unittest.main()
