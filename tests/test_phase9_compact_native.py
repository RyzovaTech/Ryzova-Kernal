# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from phase9_compact_native import commands, fixtures, inspect

COMMIT = "a" * 40


class CompactNativeTests(unittest.TestCase):
    def serial(self):
        lines = [f"RYZOVA_RUNTIME_STAGE_{i}" for i in range(26, 37)]
        for name, values in {"hello": (0, 1, 0, 8, 2), "loop": (4, 0, 0, 2048, 0),
                             "opcode": (3, 0, 0, 1, 0), "syscall": (5, 0, 0, 2, 0),
                             "exit7": (0, 1, 7, 3, 1)}.items():
            status, exited, code, steps, calls = values
            lines.append(f"COMPACT_{name}_BEGIN")
            if name == "hello":
                lines.append(f"FLEX_COMPACT_{COMMIT}")
            lines.extend([f"COMPACT_LINUX_RESULT status={status} exited={exited} "
                          f"exit={code} steps={steps} syscalls={calls}", "COMPACT_RC_OK", f"COMPACT_{name}_END"])
        lines.extend([hashlib.sha256(fixtures(COMMIT)["hello"]).hexdigest() + " /tmp/c-hello",
                      "RYZOVA_COMPACT_DONE"])
        return ("\n".join(lines) + "\n").encode()

    def test_evidence_requires_all_positive_and_negative_cases(self):
        serial = self.serial()
        self.assertTrue(inspect(b"COMPACT_NATIVE_BUILD_OK\nCOMPACT_FS_SYNC_OK\n", serial, COMMIT)["passed"])
        for old, new in ((b"steps=2048", b"steps=1"), (b"status=5", b"status=0"),
                         (b"exit=7", b"exit=0"), (b"COMPACT_RC_OK", b"wrong_status"), (b"FLEX_COMPACT_", b"WRONG_"),
                         (b"RYZOVA_RUNTIME_STAGE_29", b"missing")):
            self.assertFalse(inspect(b"COMPACT_NATIVE_BUILD_OK\nCOMPACT_FS_SYNC_OK\n", serial.replace(old, new), COMMIT)["passed"])
        self.assertFalse(inspect(b"COMPACT_NATIVE_BUILD_OK\n", serial, COMMIT)["passed"])
        self.assertFalse(inspect(b"echo COMPACT_NATIVE_BUILD_OK\n", serial, COMMIT)["passed"])
        echoed = b"term% echo COMPACT_hello_BEGIN; compact-linux /tmp/c-hello; echo COMPACT_hello_END\n"
        self.assertFalse(inspect(b"COMPACT_NATIVE_BUILD_OK\nCOMPACT_FS_SYNC_OK\n", echoed, COMMIT)["passed"])
        self.assertFalse(inspect(b"COMPACT_NATIVE_BUILD_OK\nCOMPACT_FS_SYNC_OK\n", serial + b"panic: fault\n", COMMIT)["passed"])

    def test_commands_fit_serial_and_do_not_echo_proof(self):
        for command in commands():
            self.assertLess(len(command), 190)
            self.assertNotIn("COMPACT_LINUX_RESULT", command)
            self.assertNotIn("FLEX_COMPACT_", command)

    def test_real_elf_native_reference_and_interpreter(self):
        c = ROOT / "ryzova/compat/linux"
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            runner = tmp / "runner"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            *[str(c / name) for name in ("elf64.c", "namespace.c", "syscall.c",
                                                       "subset_vm.c", "subset_vm_probe.c")],
                            "-o", str(runner)], check=True, capture_output=True)
            for name, data in fixtures(COMMIT).items():
                path = tmp / name
                path.write_bytes(data)
                path.chmod(0o700)
                result = subprocess.run([str(runner), str(path)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0 if name == "hello" else 2)
                if name in ("hello", "exit7"):
                    native = subprocess.run([str(path)], capture_output=True, timeout=5)
                    self.assertEqual(native.stdout, result.stdout)
                    self.assertEqual(native.returncode, 0 if name == "hello" else 7)
                if name == "hello":
                    self.assertEqual(result.stdout, f"FLEX_COMPACT_{COMMIT}\n".encode())
                if name == "loop":
                    self.assertIn(b"status=4", result.stderr)


if __name__ == "__main__":
    unittest.main()
