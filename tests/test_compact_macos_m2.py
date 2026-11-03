# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-2A: selected Darwin BSD syscall simulation, no host syscall forwarding.

All executions use synthetic bounded MH_EXECUTE fixture code. These tests
prove neither native Ryzova guest integration nor genuine macOS app support.
"""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_compact_macos_m1 import sample

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"
STDOUT=b"Hello from Ryzova\n"


def darwin_syscall_fixture(message=STDOUT):
    """Mach-O text: BSD write(1,text,len), exit(0) via original restricted VM."""
    header=(b"\xb8"+struct.pack("<I",0x02000004)
            +b"\xbf"+struct.pack("<I",1))
    # REX.W LEA RSI,[RIP+disp32] points to inline file-backed message.
    lea=b"\x48\x8d\x35"
    rest=(b"\xba"+struct.pack("<I",len(message))
          +b"\x0f\x05"
          +b"\xb8"+struct.pack("<I",0x02000001)
          +b"\x31\xff"
          +b"\x0f\x05")
    disp=len(rest)
    code=header+lea+struct.pack("<i",disp)+rest+message
    if len(code)>256:
        raise ValueError("bounded MAC2 fixture limit")
    return sample(code)


class BoundedDarwinServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.probe=cls.root/"mac2-probe"
        cc=os.environ.get("PHASE5_CC","cc")
        cmd=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            cmd+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        cmd += [str(C/"macho64.c"),str(C/"macho_vm.c"),
                str(C/"macho_darwin_probe.c"),"-o",str(cls.probe)]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
        if r.returncode:
            raise AssertionError(r.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_guest(self,image,budget=None):
        fixture=self.root/"darwin-research.macho"
        fixture.write_bytes(image)
        command=[str(self.probe),str(fixture)]
        if budget is not None:
            command.append(str(budget))
        return subprocess.run(command,text=True,capture_output=True,timeout=8)

    def check(self,image,status,*,message=None,exited=False):
        out=self.run_guest(image)
        self.assertEqual(out.returncode,0 if status==0 else 2,out.stdout+out.stderr)
        self.assertIn("MAC2_VM status="+str(status),out.stdout)
        self.assertIn("native_guest=0 host_syscall_forwarding=0",out.stdout)
        if exited:
            self.assertIn("exited=1 exit_code=0",out.stdout)
        if message is not None:
            self.assertIn("capture_bytes="+str(len(message)),out.stdout)
            self.assertIn("MAC2_CAPTURE_HEX "+message.hex(),out.stdout)
        return out

    def test_hello_world_is_captured_not_forwarded_to_host(self):
        out=self.check(darwin_syscall_fixture(),0,message=STDOUT,exited=True)
        self.assertNotIn("Hello from Ryzova",out.stdout)
        self.assertIn("steps=8",out.stdout)

    def test_default_mac1_mode_still_denies_identical_syscalls(self):
        # Exercise original MAC-1 probe as a separate process, not a mode
        # flag hidden in the code. Default ABI never forwards syscalls.
        runner=self.root/"default-mac1-probe"
        cc=os.environ.get("PHASE5_CC","cc")
        build=subprocess.run([cc,"-std=c11","-O1","-Wall","-Wextra",
                              "-Werror","-pedantic",str(C/"macho64.c"),
                              str(C/"macho_vm.c"),str(C/"macho_vm_probe.c"),
                              "-o",str(runner)],text=True,capture_output=True)
        self.assertEqual(build.returncode,0,build.stderr)
        file=self.root/"default-deny.macho"
        file.write_bytes(darwin_syscall_fixture())
        result=subprocess.run([str(runner),str(file)],text=True,capture_output=True)
        self.assertEqual(result.returncode,2)
        self.assertIn("MAC1_VM status=5",result.stdout)

    def test_unknown_darwin_class_and_bsd_syscalls_are_denied(self):
        for syscall in (0x0100001f,0x02000005,0x02000014,0,0x2000000):
            with self.subTest(nr=syscall):
                x=darwin_syscall_fixture()
                struct.pack_into("<I",x,0x200+1,syscall)
                self.check(x,5)

    def test_wrong_fd_invalid_pointer_and_write_cap_fail_closed(self):
        x=darwin_syscall_fixture()
        struct.pack_into("<I",x,0x200+6,2)  # mov edi,2
        self.check(x,5)
        x=darwin_syscall_fixture()
        struct.pack_into("<i",x,0x200+13,0x7fffffff)
        self.check(x,7)
        x=darwin_syscall_fixture()
        struct.pack_into("<I",x,0x200+18,257)  # mov edx,257
        self.check(x,2)

    def test_root_ret_not_a_darwin_process_exit(self):
        self.check(sample(b"\xc3"),5)

    def test_guest_write_rejected_if_text_segment_not_readable(self):
        x=darwin_syscall_fixture()
        struct.pack_into("<I",x,32+60,4)  # RX->X-only initial protection
        self.check(x,7)

    def test_unsupported_exit_status_is_captured_not_host_exit(self):
        x=darwin_syscall_fixture()
        # XOR EDI,EDI is replaced by MOV EDI,42, shifts trailing SYS.
        code=bytearray(x)
        begin=0x200
        sequence=(b"\xb8"+struct.pack("<I",0x02000001)
                  +b"\xbf"+struct.pack("<I",42)
                  +b"\x0f\x05")
        code[begin:begin+len(sequence)]=sequence
        out=self.run_guest(code)
        self.assertEqual(out.returncode,0,out.stdout)
        self.assertIn("exited=1 exit_code=42",out.stdout)
        self.assertIn("capture_bytes=0",out.stdout)


if __name__=="__main__":
    unittest.main()
