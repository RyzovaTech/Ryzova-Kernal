# SPDX-License-Identifier: AGPL-3.0-only
"""Reproducible original Clang-Darwin assembly -> synthetic Ryzova MAC-2A demo.

Host-only reference: never links Apple frameworks, runs guest code natively,
forwards guest syscalls, or demonstrates Ryzova guest boot/macOS app support.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from test_compact_macos_m1 import sample, extract_freestanding_text_object

ASM=r"""
.text
.globl _ryz_entry
_ryz_entry:
    movl $0x02000004, %eax
    movl $1, %edi
    leaq Lmessage(%rip), %rsi
    movl $18, %edx
    syscall
    movl $0x02000001, %eax
    xorl %edi, %edi
    syscall
Lmessage:
    .ascii "Hello from Ryzova\n"
"""
EXPECTED=b"Hello from Ryzova\n"


def main():
    with tempfile.TemporaryDirectory(prefix="ryzova-mac2a-") as d:
        root=Path(d)
        assembly=root/"darwin-hello.s"
        object_path=root/"darwin-hello.o"
        executable_path=root/"darwin-hello.macho"
        probe_path=root/"mac2-research"
        assembly.write_text(ASM)
        subprocess.run(
            ["clang","-target","x86_64-apple-macosx13.0","-c",
             str(assembly),"-o",str(object_path)],
            check=True,text=True,capture_output=True,timeout=30
        )
        code=extract_freestanding_text_object(object_path.read_bytes())
        executable_path.write_bytes(sample(code))
        c=ROOT/"ryzova/compat/macos"
        subprocess.run(
            [os.environ.get("PHASE5_CC","cc"),"-std=c11","-O1",
             "-Wall","-Wextra","-Werror","-pedantic",
             str(c/"macho64.c"),str(c/"macho_vm.c"),
             str(c/"macho_darwin_probe.c"),"-o",str(probe_path)],
            check=True,text=True,capture_output=True,timeout=45
        )
        r=subprocess.run([str(probe_path),str(executable_path)],
                         text=True,capture_output=True,timeout=10)
        if r.returncode!=0 or "MAC2_VM status=0" not in r.stdout or (
                "exited=1 exit_code=0" not in r.stdout or
                "native_guest=0 host_syscall_forwarding=0" not in r.stdout):
            raise RuntimeError("bounded MAC2A test execution was not accepted")
        evidence=next((row.split(" ",1)[1].strip()
                       for row in r.stdout.splitlines()
                       if row.startswith("MAC2_CAPTURE_HEX ")),None)
        if evidence is None or bytes.fromhex(evidence)!=EXPECTED:
            raise RuntimeError("MAC2A captured output mismatched source bytes")
        print(json.dumps({
            "schema":"ryzova-compact-macos-m2a-demo/v1",
            "source":"Clang x86_64-apple-macosx13.0 relocation-free MH_OBJECT",
            "code_length":len(code),
            "darwin_mh_object_sha256":hashlib.sha256(object_path.read_bytes()).hexdigest(),
            "original_assembly_sha256":hashlib.sha256(assembly.read_bytes()).hexdigest(),
            "bounded_research_fixture_sha256":hashlib.sha256(executable_path.read_bytes()).hexdigest(),
            "captured_text":EXPECTED.decode("ascii").rstrip(),
            "host_interpreter_verified":True,
            "native_ryzova_guest_verified":False,
            "linked_macos_application_verified":False,
            "host_syscall_forwarding":False
        },sort_keys=True))


if __name__=="__main__":
    main()
