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
        self.assertEqual(set(original), set(GIT_BLOBS)|{"bridge.c","util.h","win32_mincrt.c"})
        self.assertIn("wc.c", original)
        self.assertIn(b"Permission is hereby granted",
                      (FIXTURE/"upstream/LICENSE").read_bytes())

    def test_crtless_candidate_is_explicitly_import_limited_and_not_claimed_guest(self):
        source = (FIXTURE/"win32_mincrt.c").read_text()
        self.assertIn("GetStdHandle(STD_INPUT_HANDLE)", source)
        self.assertIn("ReadFile(", source)
        self.assertIn("WriteFile(", source)
        self.assertIn("ExitProcess(", source)
        self.assertIn("unsupported", source)
        self.assertNotIn("LoadLibrary(", source)
        self.assertNotIn("GetProcAddress(", source)

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



class SbaseW8PeOpcodeWindowTests(unittest.TestCase):
    def fixture(self):
        # Minimal PE32+ with one verified executable section, no runtime.
        image=bytearray(1024)
        image[:2]=b"MZ"
        image[0x3c:0x40]=(0x80).to_bytes(4,"little")
        image[0x80:0x84]=b"PE\0\0"
        image[0x84:0x86]=(0x8664).to_bytes(2,"little")
        image[0x86:0x88]=(1).to_bytes(2,"little")
        image[0x94:0x96]=(0xf0).to_bytes(2,"little")
        image[0x98:0x9a]=(0x20b).to_bytes(2,"little")
        image[0xb0:0xb8]=(0x140000000).to_bytes(8,"little")
        sh=0x80+24+0xf0
        image[sh+12:sh+16]=(0x1000).to_bytes(4,"little")
        image[sh+16:sh+20]=(0x100).to_bytes(4,"little")
        image[sh+20:sh+24]=(0x200).to_bytes(4,"little")
        image[sh+36:sh+40]=(0x20000020).to_bytes(4,"little")
        image[0x249:0x249+8]=bytes.fromhex("488b4424080f1f00")
        return bytes(image)

    def test_exact_ip_executable_section_maps_to_original_bytes(self):
        from compact_windows_w8_sbase_wc import pe_instruction_window
        image=self.fixture()
        receipt=pe_instruction_window(image,0x140001049)
        self.assertEqual(receipt["rva_hex"],"0x1049")
        self.assertEqual(receipt["image_base_hex"],"0x140000000")
        self.assertTrue(receipt["at_ip_bytes_hex"].startswith("488b4424080f1f00"))
        self.assertEqual(receipt["pe_sha256"],hashlib.sha256(image).hexdigest())
        self.assertFalse(receipt["supported_instruction_claim"])

    def test_unmapped_nonexecutable_and_invalid_pe_fail_closed(self):
        from compact_windows_w8_sbase_wc import pe_instruction_window
        original=self.fixture()
        with self.assertRaises(ValueError):
            pe_instruction_window(original,0x140010000)
        with self.assertRaises(ValueError):
            pe_instruction_window(original,0x141001049)
        with self.assertRaises(ValueError):
            pe_instruction_window(b"not a PE",0x140001049)
        nonexec=bytearray(original)
        sh=0x80+24+0xf0
        nonexec[sh+36:sh+40]=(0x40000040).to_bytes(4,"little")
        with self.assertRaises(ValueError):
            pe_instruction_window(bytes(nonexec),0x140001049)


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
