# SPDX-License-Identifier: AGPL-3.0-only
"""Host reference tests for the real, MIT sbase wc source, NOT guest support."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
from compact_windows_w8_sbase_wc import (
    CASES, FIXTURE, GIT_BLOBS, git_blob_sha, verify_case,
    verify_upstream_sources,
)


class SbaseW8SourceTests(unittest.TestCase):
    def test_upstream_exact_git_blobs_and_mit_license(self):
        original = verify_upstream_sources()
        self.assertEqual(set(original), set(GIT_BLOBS)|{"bridge.c","util.h"})
        self.assertIn("wc.c", original)
        self.assertIn(b"Permission is hereby granted",
                      (FIXTURE/"upstream/LICENSE").read_bytes())

    def test_mutated_original_source_rejected_before_compiler(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(FIXTURE, root/"fixture")
            wc = root/"fixture/upstream/wc.c"
            wc.write_bytes(wc.read_bytes()+b"\n/* unreviewed drift */\n")
            with self.assertRaisesRegex(ValueError, "drift"):
                verify_upstream_sources(root/"fixture")

    def test_blob_input_must_be_actual_source_bytes(self):
        with self.assertRaises(TypeError):
            git_blob_sha("not source bytes")
        for name, digest in GIT_BLOBS.items():
            source=(FIXTURE/"upstream"/name).read_bytes()
            self.assertEqual(git_blob_sha(source),digest)


class SbaseW8ReferenceTests(unittest.TestCase):
    def test_outputs_and_windows_crlf_normalization(self):
        for name, args, data, expected in CASES:
            with self.subTest(name=name):
                self.assertEqual(verify_case(name,SimpleNamespace(
                    returncode=0,stdout=expected,stderr=b""))["stdout_text_lf"],
                    expected.decode("ascii"))
                self.assertEqual(verify_case(name,SimpleNamespace(
                    returncode=0,stdout=expected.replace(b"\n",b"\r\n"),
                    stderr=b""))["case"],name)

    def test_wrong_case_exit_output_stderr_or_oversized_output_fail_closed(self):
        examples=(
            ("unknown",0,b"2 3 18\n",b""),
            ("default",1,b"2 3 18\n",b""),
            ("default",0,b"0 0 0\n",b""),
            ("default",0,b"2 3 18\n",b"nonempty"),
            ("default",0,b"x"*5000,b""),
        )
        for name, code, stdout, stderr in examples:
            with self.subTest(name=name,code=code):
                with self.assertRaises(ValueError):
                    verify_case(name,SimpleNamespace(
                        returncode=code,stdout=stdout,stderr=stderr))

    @unittest.skipIf(sys.platform=="win32","Linux compiler check only")
    def test_actual_unmodified_upstream_wc_runs_in_linux_host(self):
        # This tests the independently sourced program with our limited
        # bridge, not a fabricated Python-level output and not QEMU.
        with tempfile.TemporaryDirectory() as temp:
            binary=Path(temp)/"sbase-wc"
            subprocess.run([
                "cc","-std=c11","-Wall","-Wextra","-Werror","-O2",
                "-I",str(FIXTURE),"-I",str(FIXTURE/"upstream"),
                str(FIXTURE/"upstream/wc.c"),str(FIXTURE/"bridge.c"),
                "-o",str(binary),
            ],capture_output=True,timeout=60,check=True)
            for name, args, data, _ in CASES:
                with self.subTest(name=name):
                    proc=subprocess.run([str(binary),*args],input=data,
                                        capture_output=True,timeout=5)
                    self.assertTrue(verify_case(name,proc)["host_passed"])
            negative=subprocess.run([str(binary),"-m"],input=b"\xc3\xa9\n",
                                    capture_output=True,timeout=5)
            self.assertNotEqual(negative.returncode,0)
            self.assertIn(b"non-ASCII",negative.stderr)


if __name__=="__main__":
    unittest.main()
