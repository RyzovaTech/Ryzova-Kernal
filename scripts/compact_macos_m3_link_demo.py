# SPDX-License-Identifier: AGPL-3.0-only
"""Original Mach-O object linker: source-built cross-object relocation proof.

The **host-only** bounded Ryzova interpreter runs a synthetic MH_EXECUTE.
This is not dyld, libSystem, a runnable Apple application, native Ryzova
guest execution, or general macOS link compatibility.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"
ENTRY=""".text
.globl _ryz_entry
_ryz_entry:
    call _ryz_helper
    ret
"""
HELPER=""".text
.globl _ryz_helper
_ryz_helper:
    movl $42, %eax
    ret
"""

def command(argv):
    res=subprocess.run(argv,text=True,capture_output=True,timeout=45)
    if res.returncode!=0:
        raise RuntimeError(f"command failed {argv[0]}: {res.stderr}")
    return res

def main():
    with tempfile.TemporaryDirectory(prefix="ryzova-mac3c-") as folder:
        d=Path(folder)
        files=[]
        for name,code in (("entry",ENTRY),("helper",HELPER)):
            path=d/(name+".S")
            obj=d/(name+".o")
            path.write_text(code)
            command(["clang","-target","x86_64-apple-macosx13.0",
                     "-c",str(path),"-o",str(obj)])
            files.append(obj)
        probe=d/"ryz-mac3c-link"
        cc=os.environ.get("PHASE5_CC","cc")
        command([cc,"-std=c11","-Wall","-Wextra","-Werror","-pedantic",
                 "-O2",str(C/"macho64.c"),str(C/"macho_vm.c"),
                 str(C/"macho_static_link.c"),
                 str(C/"macho_static_link_probe.c"),
                 "-o",str(probe)])
        res=command([str(probe),str(files[0]),str(files[1])])
        for marker in (
            "MAC3C_LINK status=0","branch_relocations=1",
            "resolved_externals=1","vm_status=0 eax=42 returned=1",
            "native_guest=0 dyld=0 libsystem=0 host_forwarding=0"
        ):
            if marker not in res.stdout:
                raise RuntimeError("missing exact linker proof: "+marker)
        report={
            "schema":"ryzova-mac3c-link-prototype/v1",
            "darwin_entry_object_sha256":hashlib.sha256(files[0].read_bytes()).hexdigest(),
            "darwin_helper_object_sha256":hashlib.sha256(files[1].read_bytes()).hexdigest(),
            "cross_object_branch_relocation_applied":True,
            "synthesized_macho_guest_integer_result":42,
            "ran_in_host_only_restricted_interpreter":True,
            "native_ryzova_guest_executed":False,
            "linked_real_macos_application":False,
            "dyld_or_libsystem_implemented":False,
            "host_syscall_forwarding":False
        }
        print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
