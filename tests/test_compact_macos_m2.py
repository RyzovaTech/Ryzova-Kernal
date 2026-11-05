# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/macos_m1_reference.macho"


class ReferenceExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.runner = Path(cls.work.name) / "runner"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                        "-fsanitize=undefined", "-fno-sanitize-recover=all",
                        str(ROOT / "ryzova/compat/macos/m2.c"), "-lcrypto",
                        "-o", str(cls.runner)], check=True)

    def test_reference_matches_macos(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
                         "478499eefd5228f56ffaed4dafc07436b01ae1319f1cc95998aecb92e46afc1f")
        result = subprocess.run([self.runner, FIXTURE], capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (37, b"FLEX_MACOS_M1_REFERENCE\n", b""))

    def test_changes_to_code_imports_and_length_are_rejected(self):
        original = FIXTURE.read_bytes()
        for offset in (1136, 4096, 8277, len(original)):
            image = bytearray(original)
            if offset == len(original):
                image.append(0)
            else:
                image[offset] ^= 1
            path = Path(self.work.name) / "invalid"
            path.write_bytes(image)
            result = subprocess.run([self.runner, path], capture_output=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout), (125, b""), offset)
