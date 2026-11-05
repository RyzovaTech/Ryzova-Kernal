# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from compact_macos_m3_fixture import build

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
                        str(ROOT / "ryzova/compat/macos/grant.c"), "-o", str(cls.runner)], check=True)

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

    def test_m3_guest_reads_argv_and_writes_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            fixture.write_bytes(build())
            granted = root / "entry.txt"
            granted.write_bytes(b"IN!\n")
            result = subprocess.run([self.runner, fixture, root, "entry.txt", "demo"],
                                    capture_output=True, timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (37, b"IN!\n", b""))
            self.assertEqual(granted.read_bytes(), b"IN!\nFLEX_NOTE=demo")

    def test_m3_rejects_paths_outside_the_grant_and_missing_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            root = outer / "grant"
            root.mkdir()
            fixture = outer / "fixture"
            fixture.write_bytes(build())
            outside = outer / "outside.txt"
            outside.write_bytes(b"SAFE")
            (root / "alias").symlink_to(outside)
            (root / "hard").hardlink_to(outside)
            local = root / "entry.txt"
            local.write_bytes(b"IN!\n")
            for grant, name in ((root, "../outside.txt"), (root, str(outside)),
                                (root, "alias"), (root, "hard"), ("-", "entry.txt")):
                with self.subTest(grant=grant, name=name):
                    result = subprocess.run([self.runner, fixture, grant, name, "demo"],
                                            capture_output=True, timeout=5)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (13, b"", b""))
            self.assertEqual(outside.read_bytes(), b"SAFE")
            self.assertEqual(local.read_bytes(), b"IN!\n")
