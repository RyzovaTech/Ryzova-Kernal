# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-2A: selected Darwin BSD syscall simulation, no host syscall forwarding.

All executions use synthetic bounded MH_EXECUTE fixture code. These tests
prove neither native Ryzova guest integration nor genuine macOS app support.
"""
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from test_compact_macos_m1 import sample, extract_freestanding_text_object

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

    def test_exact_opt_in_simulation_contract_is_not_native_runtime(self):
        contract=json.loads((C/"mac2-contract.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["schema"],"ryzova-compact-macos-m2a/v1")
        self.assertEqual(contract["phase"],"MAC-2A")
        self.assertTrue(contract["default_mac1_syscalls_denied"])
        self.assertEqual(contract["enabled_only_with_explicit_api"],"ryz_mac2_run")
        self.assertEqual([row["number_hex"] for row in contract["simulated_syscalls"]],
                         ["0x02000001","0x02000004"])
        self.assertEqual(contract["captured_output_max_bytes"],256)
        self.assertEqual(contract["maximum_guest_steps"],4096)
        for key in (
            "native_ryzova_guest_verified","real_macos_application_executed",
            "dyld_libsystem_implemented","full_mach_ipc_implemented",
            "host_syscall_forwarding","host_filesystem_network_access",
            "mac2_phase_complete","production_release_allowed"
        ):
            with self.subTest(capability=key):
                self.assertIs(contract[key],False)

    def test_hello_world_is_captured_not_forwarded_to_host(self):
        out=self.check(darwin_syscall_fixture(),0,message=STDOUT,exited=True)
        self.assertNotIn("Hello from Ryzova",out.stdout)
        self.assertIn("steps=8",out.stdout)

    def test_real_clang_darwin_macho_object_hello_capture(self):
        # Independently assemble a real Darwin-target MH_OBJECT using Clang.
        # All local RIP-relative references are resolved at object build
        # time; its __text has no relocations and is extracted fail closed.
        source=self.root/"darwin-mac2-hello.s"
        obj=self.root/"darwin-mac2-hello.o"
        assembly=(
            ".text\n"
            ".globl _ryz_entry\n"
            "_ryz_entry:\n"
            " movl $0x02000004, %eax\n"
            " movl $1, %edi\n"
            " leaq Lmessage(%rip), %rsi\n"
            " movl $18, %edx\n"
            " syscall\n"
            " movl $0x02000001, %eax\n"
            " xorl %edi, %edi\n"
            " syscall\n"
            "Lmessage:\n"
            ' .ascii "Hello from Ryzova\\n"\n'
        )
        source.write_text(assembly)
        build=subprocess.run(
            ["clang","-target","x86_64-apple-macosx13.0","-c",
             str(source),"-o",str(obj)],
            text=True,capture_output=True,timeout=30
        )
        self.assertEqual(build.returncode,0,build.stderr)
        data=obj.read_bytes()
        self.assertEqual(struct.unpack_from("<I",data,12)[0],1) # MH_OBJECT
        code=extract_freestanding_text_object(data)
        self.assertLessEqual(len(code),256)
        result=self.check(sample(code),0,message=STDOUT,exited=True)
        self.assertIn("host_syscall_forwarding=0",result.stdout)

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

    def test_exact_256_byte_capture_budget_and_repeated_write_limit(self):
        payload=b"A"*128
        start=(b"\xb8"+struct.pack("<I",0x02000004)
               +b"\xbf"+struct.pack("<I",1))
        lea=b"\x48\\x8d\\x35"
        first=b"\xba"+struct.pack("<I",len(payload))+b"\x0f\\x05"
        second=b"\xb8"+struct.pack("<I",0x02000004)+b"\x0f\\x05"
        exitcode=b"\xb8"+struct.pack("<I",0x02000001)+b"\x31\\xff"+b"\x0f\\x05"
        tail=first+second+exitcode
        instruction=start+lea+struct.pack("<i",len(tail))+tail+payload
        self.assertLessEqual(len(instruction),256)
        out=self.check(sample(instruction),0,message=payload*2,exited=True)
        self.assertIn("capture_bytes=256",out.stdout)
        # A third identical write must be rejected with the 256 bytes
        # still confined to private diagnostic storage.
        third=b"\xb8"+struct.pack("<I",0x02000004)+b"\x0f\\x05"
        tail=first+second+third+exitcode
        instruction=start+lea+struct.pack("<i",len(tail))+tail+payload
        failed=self.check(sample(instruction),2)
        self.assertIn("capture_bytes=256",failed.stdout)
        self.assertIn("exited=0",failed.stdout)

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
