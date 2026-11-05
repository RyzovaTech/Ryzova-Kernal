# SPDX-License-Identifier: AGPL-3.0-only
"""W7: execute real Windows ARM64 PE with two independently compiled VMs.

One VM runs on Linux AMD64 and the other on Linux AArch64 under qemu-aarch64.
Not a Ryzova native ARM64 kernel, Windows ARM64 host or physical board test.
Both execute the original, import-free Windows ARM64 Clang/LLD binaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "ryzova/compat/windows"
MAIN = SRC / "arm64_probe_main.c"
ENGINE = SRC / "arm64_probe.c"
FIXTURES = (
    ("integer", ROOT / "tests/fixtures/windows_w7_arm64_reference.c"),
    ("call", ROOT / "tests/fixtures/windows_w7_arm64_call_reference.c"),
)
SCHEMA = "compact-windows-w7-linux-aarch64-qemu-user/v1"
RESULT = re.compile(
    r"^CW_ARM64_RESULT status=(\d+) exit=(\d+) steps=(\d+) "
    r"pc=([0-9a-f]+) insn=([0-9a-f]{8})$"
)


def sha256(data):
    if type(data) is not bytes:
        raise TypeError("bytes required")
    return hashlib.sha256(data).hexdigest()


def arm64_linux_elf(executable):
    if not isinstance(executable, bytes) or len(executable) < 64:
        raise ValueError("missing Linux AArch64 ELF")
    if (executable[:6] != b"\x7fELF\x02\x01" or
            int.from_bytes(executable[18:20], "little") != 183 or
            int.from_bytes(executable[16:18], "little") not in (2, 3)):
        raise ValueError("Linux ELF64 AArch64 required (EM_AARCH64=183)")
    return sha256(executable)


def pe_entry_raw(image):
    """Map only the file-backed executable entry of the original PE."""
    if (type(image) is not bytes or len(image) < 256 or
            len(image) > 4*1024*1024 or image[:2] != b"MZ"):
        raise ValueError("bounded Windows ARM64 PE32+ required")
    def field(off,n):
        if off < 0 or n not in (2,4) or off > len(image)-n:
            raise ValueError("PE field out of bounds")
        return int.from_bytes(image[off:off+n], "little")
    pe=field(0x3c,4)
    if pe>len(image)-24 or image[pe:pe+4]!=b"PE\x00\x00":
        raise ValueError("invalid PE signature")
    if field(pe+4,2)!=0xaa64:
        raise ValueError("classic Windows ARM64 required")
    sections=field(pe+6,2)
    optsize=field(pe+20,2)
    opt=pe+24
    if not 1<=sections<=8 or optsize<112 or opt>len(image)-optsize:
        raise ValueError("unbounded PE headers")
    if field(opt,2)!=0x20b:
        raise ValueError("PE32+ required")
    entry=field(opt+16,4)
    table=opt+optsize
    if table>len(image) or sections*40>len(image)-table or entry%4:
        raise ValueError("unaligned/unbacked entry")
    for i in range(sections):
        sec=table+i*40
        rva=field(sec+12,4)
        bytes_=field(sec+16,4)
        raw=field(sec+20,4)
        flags=field(sec+36,4)
        if (flags&0x20000000 and not flags&0x80000000 and
                rva<=entry and entry-rva<bytes_ and
                raw<=len(image) and bytes_<=len(image)-raw):
            return raw+(entry-rva)
    raise ValueError("entry not backed by executable PE section")


def mutate(image,kind):
    """Negative cases generated from actual Windows ARM64 compiler PE."""
    pe=int.from_bytes(image[0x3c:0x40],"little")
    d=bytearray(image)
    if kind=="arm64ec-denied":
        d[pe+4:pe+6]=(0xa641).to_bytes(2,"little")
    elif kind in ("svc-denied","illegal-denied","step-limit"):
        offset=pe_entry_raw(image)
        code={"svc-denied":0xd4000001,
              "illegal-denied":0xffffffff,
              "step-limit":0x14000000}[kind]
        d[offset:offset+4]=code.to_bytes(4,"little")
    elif kind=="imports-denied":
        opt=pe+24
        if int.from_bytes(image[opt+108:opt+112],"little")<2:
            raise ValueError("PE lacks explicit import directory slots")
        d[opt+120:opt+124]=(0x1000).to_bytes(4,"little")
    else:
        raise ValueError("unknown PE mutation")
    return bytes(d)


def parse_result(stdout,returncode,stderr):
    if (type(stdout) is not bytes or len(stdout)>1024 or
            type(stderr) is not bytes or stderr or
            type(returncode) is not int):
        raise ValueError("unbounded or noisy ARM64 VM result")
    try:
        content=stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("non-ASCII VM receipt") from exc
    found=RESULT.fullmatch(content)
    if not found:
        raise ValueError("invalid ARM64 VM receipt")
    status,exit_code,steps=(int(found[i]) for i in (1,2,3))
    pc,insn=int(found[4],16),int(found[5],16)
    if (status not in (0,1,2,3,4) or
            returncode!=(0 if status==0 else status+1) or
            not 0<=steps<=4096 or pc>0xffffffff or insn>0xffffffff):
        raise ValueError("status/process exit/step budget conflict")
    return {"status":status,"exit_code":exit_code,"steps":steps,
            "last_rva_hex":f"{pc:x}","last_opcode_hex":f"{insn:08x}",
            "process_exit":returncode}


def command(args,timeout=90):
    proc=subprocess.run([str(x) for x in args],capture_output=True,
                        timeout=timeout,check=False)
    if proc.returncode:
        text=(proc.stdout+proc.stderr)[-1800:].decode("utf-8","replace")
        raise RuntimeError("compiler failed: "+text)


def invoke(prefix,image):
    proc=subprocess.run([*(str(x) for x in prefix),str(image)],capture_output=True,
                        timeout=15,check=False)
    return parse_result(proc.stdout,proc.returncode,proc.stderr)


def require(name):
    path=shutil.which(name)
    if not path:
        raise RuntimeError("strict W7 toolchain unavailable: "+name)
    return path


def qualify(output):
    if platform.system()!="Linux" or platform.machine().lower() not in ("x86_64","amd64"):
        raise RuntimeError("strict differential requires Linux AMD64 host")
    cc=require("cc")
    armcc=require("aarch64-linux-gnu-gcc")
    clang=require("clang")
    linker=require("lld-link")
    qemu=require("qemu-aarch64")
    sources=(ENGINE,MAIN,SRC/"arm64_probe.h",*(p for _,p in FIXTURES))
    original_hashes={str(p.relative_to(ROOT)):sha256(p.read_bytes()) for p in sources}
    with tempfile.TemporaryDirectory(prefix="cw-w7-arm64-qemu-user-") as directory:
        root=Path(directory)
        host=root/"w7-amd64"
        arm=root/"w7-linux-aarch64"
        flags=["-std=c11","-O2","-Wall","-Wextra","-Werror"]
        command([cc,*flags,ENGINE,MAIN,"-o",host])
        command([armcc,*flags,"-static","-fno-pie","-no-pie",ENGINE,MAIN,"-o",arm])
        arm_sha=arm64_linux_elf(arm.read_bytes())
        host_bytes=host.read_bytes()
        if (host_bytes[:6]!=b"\x7fELF\x02\x01" or
                int.from_bytes(host_bytes[18:20],"little")!=62):
            raise ValueError("host interpreter is not ELF64 x86-64")
        engines={"amd64-host":[host],"linux-aarch64-qemu-user":[qemu,arm]}
        cases={}
        for title,src in FIXTURES:
            for opt in ("O0","O2"):
                key=title+"-"+opt
                obj=root/(key+".obj")
                exe=root/(key+".exe")
                command([clang,"--target=aarch64-windows-msvc","-"+opt,
                         "-c",src,"-o",obj])
                command([linker,"/machine:arm64","/entry:main","/subsystem:console",
                         "/nodefaultlib","/out:"+str(exe),obj])
                original=exe.read_bytes()
                pe_entry_raw(original)
                measurements={name:invoke(cmd,exe) for name,cmd in engines.items()}
                if (measurements["amd64-host"]!=measurements["linux-aarch64-qemu-user"] or
                        any(v["status"]!=0 or v["exit_code"]!=37
                            for v in measurements.values())):
                    raise ValueError("original Windows ARM64 PE mismatch: "+key)
                cases[key]={
                    "source_sha256":original_hashes[str(src.relative_to(ROOT))],
                    "windows_arm64_pe_sha256":sha256(original),
                    "windows_arm64_pe_bytes":len(original),
                    "amd64_host_vm":measurements["amd64-host"],
                    "qemu_linux_arm64_vm":measurements["linux-aarch64-qemu-user"],
                    "cross_isa_exact_receipts_equal":True,
                }
        negative={}
        original=(root/"integer-O2.exe").read_bytes()
        for kind,want in (("arm64ec-denied",1),("svc-denied",2),
                          ("illegal-denied",2),("step-limit",4),
                          ("imports-denied",1)):
            image=mutate(original,kind)
            binary=root/(kind+".exe")
            binary.write_bytes(image)
            host_result=invoke(engines["amd64-host"],binary)
            emulated=invoke(engines["linux-aarch64-qemu-user"],binary)
            if host_result!=emulated or host_result["status"]!=want:
                raise ValueError("negative ARM64 differential mismatch: "+kind)
            if kind=="step-limit" and emulated["steps"]!=4096:
                raise ValueError("guest instruction budget bypassed")
            negative[kind]={
                "mutated_pe_sha256":sha256(image),
                "expected_status":want,"receipt":emulated,
                "cross_isa_exact_receipts_equal":True,
            }
        if len(cases)!=4 or len(negative)!=5:
            raise ValueError("incomplete Windows ARM64 differential matrix")
        report={
            "schema":SCHEMA,
            "source_sha256":original_hashes,
            "host_architecture":"linux-amd64",
            "qemu_linux_arm64_executable_machine":"EM_AARCH64 183",
            "qemu_linux_arm64_interpreter_sha256":arm_sha,
            "host_amd64_interpreter_sha256":sha256(host_bytes),
            "windows_arm64_pe_positive_cases":cases,
            "windows_arm64_pe_negative_cases":negative,
            "qemu_linux_aarch64_userspace_interpreter_verified":True,
            "native_ryzova_arm64_kernel_boot_qualified":False,
            "windows_arm64_host_reference_qualified":False,
            "windows_arm64_imports_qualified":False,
            "windows_v1_release_qualified":False,
            "physical_arm64_hardware_qualified":False,
        }
        output=Path(output)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"schema":SCHEMA,"positive":4,"negative":5,
                          "qemu_linux_aarch64_userspace_interpreter_verified":True,
                          "native_ryzova_arm64_kernel_boot_qualified":False},
                         sort_keys=True))
        return report


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",required=True,type=Path)
    qualify(parser.parse_args().output)
