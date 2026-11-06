# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-3 source-built Darwin symbol and dylib metadata-only demonstration."""
import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests"))
from test_compact_macos_m3 import program,string_command


def build_command(args):
    proc=subprocess.run(args,text=True,capture_output=True,timeout=45)
    if proc.returncode:
        raise RuntimeError("host compilation failed: "+proc.stderr)


def main():
    with tempfile.TemporaryDirectory(prefix="ryzova-mac3-") as tmp:
        base=Path(tmp)
        asm=base/"darwin-import.s"
        obj=base/"darwin-import.o"
        exec_file=base/"m3a-synthetic.macho"
        symprobe=base/"symprobe"
        dep_probe=base/"depprobe"
        src=ROOT/"ryzova/compat/macos"
        asm.write_text(
            ".text\n.globl _ryz_entry\n_ryz_entry:\n"
            " call _missing_symbol\n ret\n"
        )
        build_command(["clang","-target","x86_64-apple-macosx13.0",
                       "-c",str(asm),"-o",str(obj)])
        cc=os.environ.get("PHASE5_CC","cc")
        common=[cc,"-std=c11","-Wall","-Wextra","-Werror","-pedantic","-O2"]
        build_command(common+[str(src/"macho_symbol_meta.c"),
                              str(src/"macho_symbol_meta_probe.c"),
                              "-o",str(symprobe)])
        build_command(common+[str(src/"macho_link_meta.c"),
                              str(src/"macho_link_meta_probe.c"),
                              "-o",str(dep_probe)])
        out=subprocess.run([str(symprobe),str(obj)],
                           capture_output=True,text=True,timeout=8)
        expected=["MAC3_SYMBOL status=0",
                  "MAC3_SYMBOL_NAME _ryz_entry 1",
                  "MAC3_SYMBOL_NAME _missing_symbol 0",
                  "symbol_resolution=0 native_guest=0"]
        if out.returncode!=0 or any(x not in out.stdout for x in expected):
            raise RuntimeError("real Darwin object symbol inventory failed")
        synthetic=program([
            string_command(0x0c,"/usr/lib/libSystem.B.dylib"),
            string_command(0x0e,"/usr/lib/dyld",12)
        ])
        exec_file.write_bytes(synthetic)
        manifest=subprocess.run([str(dep_probe),str(exec_file)],
                                capture_output=True,text=True,timeout=8)
        expected=["MAC3_METADATA status=0",
                  "MAC3_DEP 0 /usr/lib/libSystem.B.dylib",
                  "MAC3_DYLD /usr/lib/dyld",
                  "native_guest=0 dylib_loading=0 symbol_resolution=0"]
        if manifest.returncode!=0 or any(x not in manifest.stdout for x in expected):
            raise RuntimeError("inert synthetic dylib inventory failed")
        report={
            "schema":"ryzova-mac3-metadata-evidence/v1",
            "darwin_object_sha256":hashlib.sha256(obj.read_bytes()).hexdigest(),
            "original_assembly_sha256":hashlib.sha256(asm.read_bytes()).hexdigest(),
            "synthetic_manifest_sha256":hashlib.sha256(exec_file.read_bytes()).hexdigest(),
            "object_symbol_import_verified":True,
            "inert_library_dependency_name_verified":True,
            "dynamic_linker_implemented":False,
            "symbol_resolution_performed":False,
            "host_libraries_loaded":False,
            "native_ryzova_guest_executed":False,
            "macos_application_executed":False,
        }
        print(json.dumps(report,sort_keys=True))


if __name__=="__main__":
    main()
