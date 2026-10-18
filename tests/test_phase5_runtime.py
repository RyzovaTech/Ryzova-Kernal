#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compile portable phase 5 runtime against GCC/Clang. No Linux app executes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
COMMON=ROOT/"ryzova/compat/linux"
TEST=ROOT/"tests/phase5_runtime_test.c"
class TestVirtualLinuxRuntime(unittest.TestCase):
    def test_bounded_process_and_namespace(self):
        cc=os.environ.get("PHASE5_CC","cc")
        with tempfile.TemporaryDirectory() as d:
            exe=str(Path(d)/"phase5-runtime")
            flags=["-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
            if os.environ.get("PHASE5_SANITIZE")=="1":
                flags+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
            subprocess.run([cc,*flags,str(COMMON/"namespace.c"),
                            str(COMMON/"syscall.c"),str(TEST),"-o",exe],
                           check=True,capture_output=True,text=True)
            r=subprocess.run([exe],check=True,capture_output=True,text=True,timeout=10)
            self.assertIn("PHASE5_2_3_VIRTUAL_RUNTIME_ALL_TESTS_PASS",r.stdout)
if __name__=="__main__":
    unittest.main()
