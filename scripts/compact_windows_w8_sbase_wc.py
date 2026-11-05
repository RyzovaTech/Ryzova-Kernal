# SPDX-License-Identifier: AGPL-3.0-only
"""W8: compile genuine MIT sbase wc source on Windows and audit its PE.

Original upstream wc.c/utf.h/arg.h/LICENSE are kept byte-for-byte at pinned
Git blob IDs; only a separately labeled, ASCII-only Windows-host bridge is
Ryzova-authored. This is not yet a native Ryzova/9P/Win32 app acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

from compact_windows_import_audit import discover

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/windows_w8_sbase_wc"
UPSTREAM = "michaelforney/sbase"
UPSTREAM_COMMIT = "b30fb56804bfed69b45ef0e944d2e029e4d26258"
GIT_BLOBS = {
    "wc.c": "c89d19f8d90073ca99462a06e679ab1816dfbd5c",
    "arg.h": "0b23c53a9d2bcffc92e0e6db208ec65d7f13438d",
    "utf.h": "8e0707a7028acf8ed5eb4b5deea685de1d5e7bb4",
    "LICENSE": "bbbfa8c5e7d4b14a8ccc3bd53388a5232eb02fe8",
}
SCHEMA = "compact-windows-w8-sbase-wc-host/v1"
CASES = (
    ("default", (), b"alpha beta\nsecond\n", b"2 3 18\n"),
    ("lines", ("-l",), b"a b\nc\n", b"2\n"),
    ("words", ("-w",), b"a b\nc\n", b"3\n"),
    ("bytes", ("-c",), b"a b\nc\n", b"6\n"),
)



def pe_instruction_window(image, absolute_ip):
    """Extract bounded executable-section bytes from the *exact* PE file.

    This is read-only triage, not a decoder, loader or evidence of execution.
    Never guess byte offsets from an RVA without validating PE headers.
    """
    if (type(image) is not bytes or not 256 <= len(image) <= 4*1024*1024 or
            image[:2] != b"MZ" or type(absolute_ip) is not int):
        raise ValueError("bounded PE image and absolute guest IP required")
    def value(off, size):
        if off < 0 or size not in (2, 4, 8) or off > len(image)-size:
            raise ValueError("out-of-range PE field")
        return int.from_bytes(image[off:off+size], "little")
    pe=value(0x3c, 4)
    if pe > len(image)-24 or image[pe:pe+4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    if value(pe+4,2) != 0x8664:
        raise ValueError("diagnostic is AMD64-only")
    count=value(pe+6,2)
    opt_bytes=value(pe+20,2)
    if not 1 <= count <= 96 or opt_bytes < 112:
        raise ValueError("unbounded PE sections")
    opt=pe+24
    if opt > len(image)-opt_bytes or value(opt,2) != 0x20b:
        raise ValueError("PE32+ optional header required")
    base=value(opt+24,8)
    if absolute_ip < base or absolute_ip-base > 0xffffffff:
        raise ValueError("guest IP outside original PE image base")
    rva=absolute_ip-base
    section_table=opt+opt_bytes
    if count*40 > len(image)-section_table:
        raise ValueError("truncated PE section table")
    for index in range(count):
        section=section_table+index*40
        section_rva=value(section+12,4)
        raw_bytes=value(section+16,4)
        raw_off=value(section+20,4)
        characteristics=value(section+36,4)
        if not (characteristics & 0x20000000):
            continue  # only IMAGE_SCN_MEM_EXECUTE executable sections
        if (section_rva <= rva and rva-section_rva < raw_bytes and
                raw_off <= len(image) and raw_bytes <= len(image)-raw_off):
            delta=rva-section_rva
            before=min(12,delta)
            count=min(24,raw_bytes-delta)
            at=raw_off+delta
            if count < 4:
                raise ValueError("insufficient mapped instruction bytes")
            return {
                "pe_sha256": hashlib.sha256(image).hexdigest(),
                "image_base_hex": hex(base),
                "guest_ip_hex": hex(absolute_ip),
                "rva_hex": hex(rva),
                "mapped_section_index": index,
                "preceding_bytes_hex": image[at-before:at].hex(),
                "at_ip_bytes_hex": image[at:at+count].hex(),
                "supported_instruction_claim": False,
            }
    raise ValueError("guest IP not backed by an executable PE section")

def git_blob_sha(blob):
    if type(blob) is not bytes:
        raise TypeError("blob bytes required")
    return hashlib.sha1(b"blob " + str(len(blob)).encode() + b"\0" + blob).hexdigest()


def verify_upstream_sources(directory=FIXTURE):
    directory = Path(directory)
    observed = {}
    for name, sha in GIT_BLOBS.items():
        p = directory / "upstream" / name
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 16384:
            raise ValueError("missing or oversized original upstream source " + name)
        blob = p.read_bytes()
        if git_blob_sha(blob) != sha:
            raise ValueError("original upstream Git blob drift: " + name)
        observed[name] = {
            "git_blob_sha1": sha, "sha256": hashlib.sha256(blob).hexdigest(),
            "bytes": len(blob),
        }
    if b"MIT License" not in (directory / "upstream/LICENSE").read_bytes():
        raise ValueError("upstream MIT license missing")
    for name in ("bridge.c", "util.h", "win32_mincrt.c"):
        p = directory / name
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 16384:
            raise ValueError("missing bounded platform bridge")
        observed[name] = {"sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                          "bytes": p.stat().st_size}
    return observed


def verify_case(name, outcome):
    expected = next((case[3] for case in CASES if case[0] == name), None)
    if expected is None:
        raise ValueError("unknown named sbase wc reference case")
    if (type(outcome.returncode) is not int or outcome.returncode != 0 or
            type(outcome.stdout) is not bytes or type(outcome.stderr) is not bytes or
            len(outcome.stdout) > 4096 or len(outcome.stderr) > 4096):
        raise ValueError("sbase wc reference failed: " + name)
    normalized = outcome.stdout.replace(b"\r\n", b"\n")
    if normalized != expected or outcome.stderr:
        raise ValueError("sbase wc output mismatch: " + name)
    return {
        "case": name, "host_passed": True, "exit_code": 0,
        "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
        "stdout_text_lf": normalized.decode("ascii"),
        "stdout_bytes": len(outcome.stdout),
    }


def compile_windows(cl_path, root, output):
    """Invoke Microsoft x64 tools, never arbitrary downloaded executables."""
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Microsoft Windows AMD64 host compiler required")
    if type(cl_path) is not str or not cl_path:
        raise RuntimeError("Visual Studio vcvars64.bat path required")
    vcvars = Path(cl_path)
    if not vcvars.is_file() or vcvars.name.lower() != "vcvars64.bat":
        raise RuntimeError("Visual Studio vcvars64.bat missing")
    output.mkdir(parents=True, exist_ok=True)
    executable = output / "sbase-wc.exe"
    source = root / "upstream/wc.c"
    bridge = root / "bridge.c"
    batch = output / "build.cmd"
    # Use absolute fixed source paths; every source byte is provenance checked.
    # /MT is deliberate to reduce external CRT DLL dependencies, but native
    # Ryzova PE import/ISA admission must still be measured independently.
    parts = [
        "@echo off", 'call "' + str(vcvars) + '"',
        "if errorlevel 1 exit /b 1",
        'cl /nologo /O1 /W3 /MT /D_CRT_SECURE_NO_WARNINGS ' +
        '/I"' + str(root) + '" /I"' + str(root / "upstream") + '" ' +
        '"' + str(source) + '" "' + str(bridge) + '" ' +
        '/Fe:"' + str(executable) + '"',
        "if errorlevel 1 exit /b 1",
        "exit /b 0",
    ]
    batch.write_bytes(("\r\n".join(parts) + "\r\n").encode("utf-8"))
    done = subprocess.run(["cmd.exe", "/d", "/c", str(batch)],
                          cwd=output, capture_output=True, timeout=150)
    if done.returncode != 0 or not executable.is_file():
        raise RuntimeError("MSVC source build failed: " +
                           (done.stdout + done.stderr)[-3500:].decode("utf-8", "replace"))
    return executable



def compile_mincrt_windows(vcvars_path, root, output):
    """Build real upstream wc.c with only four explicitly imported Win32 APIs.

    No UCRT/MSVCRT DLL or custom dynamic loader; this is NOT a guest proof.
    """
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("real Windows AMD64 compiler required")
    if not Path(vcvars_path).is_file():
        raise RuntimeError("missing VS x64 toolchain setup")
    output.mkdir(parents=True, exist_ok=True)
    upstream = root/"upstream/wc.c"
    adapter = root/"win32_mincrt.c"
    wcobj=output/"mincrt-wc.obj"
    bridgeobj=output/"mincrt-bridge.obj"
    executable=output/"sbase-wc-mincrt.exe"
    batch=output/"build-mincrt.cmd"
    opts=(' /nologo /c /O1 /W3 /GS- /Zl /Oi- /D_CRT_SECURE_NO_WARNINGS '
          '/DCW_W8_MINCRT /I"'+str(root)+'" /I"'+str(root/"upstream")+'" ')
    lines=[
        "@echo off",'call "'+str(vcvars_path)+'"','if errorlevel 1 exit /b 1',
        'cl'+opts+'"'+str(upstream)+'" /Fo:"'+str(wcobj)+'"',
        "if errorlevel 1 exit /b 1",
        'cl'+opts+'"'+str(adapter)+'" /Fo:"'+str(bridgeobj)+'"',
        "if errorlevel 1 exit /b 1",
        'link /nologo /machine:x64 /entry:cw_wc_entry /subsystem:console '
        '/nodefaultlib /fixed /dynamicbase:no /debug:none "'+
        str(wcobj)+'" "'+str(bridgeobj)+'" kernel32.lib /out:"'+str(executable)+'"',
        "if errorlevel 1 exit /b 1","exit /b 0",
    ]
    batch.write_bytes(("\r\n".join(lines)+"\r\n").encode("utf-8"))
    process=subprocess.run(["cmd.exe","/d","/c",str(batch)],cwd=output,
                           capture_output=True,timeout=150)
    if process.returncode != 0 or not executable.is_file():
        raise RuntimeError("CRTless original sbase source compiler failed: "+
                           (process.stdout+process.stderr)[-5000:].decode("utf-8","replace"))
    return executable


def run_mincrt_reference(app, plan, full_reference):
    if not app.is_file() or app.is_symlink() or not 256 <= app.stat().st_size <= 4*1024*1024:
        raise ValueError("out-of-bound MSVC no-CRT PE")
    data=app.read_bytes()
    name,args,input_bytes,expected=CASES[0]
    outcome=subprocess.run([str(app)],input=input_bytes,
                           capture_output=True,timeout=12,check=False)
    try:
        verified=verify_case(name,outcome)
    except ValueError as error:
        raise RuntimeError(
            "CRTless Windows app execution mismatch; "
            "exit_code="+str(outcome.returncode)+
            " stdout_hex="+outcome.stdout[:80].hex()+
            " stderr_excerpt="+outcome.stderr[:120].decode("utf-8","replace")
        ) from error
    ref=full_reference["named_workloads"][0]
    if verified["stdout_text_lf"]!=ref["stdout_text_lf"]:
        raise ValueError("no-CRT output not equal original source Windows-host reference")
    bad=subprocess.run([str(app)],input=b"\xc3\xa9\n",capture_output=True,
                       timeout=12,check=False)
    if bad.returncode==0 or b"non-ASCII" not in bad.stderr:
        raise ValueError("no-CRT adapter silently misinterpreted non-ASCII")
    audit=None;rejection=None
    try:
        audit=discover(data,plan)
        if audit.get("architecture")!="amd64":
            raise ValueError("no-CRT PE not AMD64")
    except ValueError as exc:
        rejection=str(exc)[:256]
    direct=audit.get("direct_imports") if audit else None
    missing=audit.get("missing_or_ordinal_imports",[]) if audit else []
    modules=audit.get("modules",[]) if audit else []
    # Structural eligibility is ONLY a triage signal. cw_plan may reject
    # other PE metadata, and current Ryzova lacks console stdin access.
    eligible=bool(
        audit is not None and rejection is None and
        type(direct) is int and direct<=32 and len(missing)==0 and
        len(modules)<=4 and not audit.get("delay_load_modules") and
        not audit.get("runtime_directories_unqualified")
    )
    return {
        "strategy":"original sbase wc.c + separate Win32 no-CRT stdin bridge",
        "windows_reference_default_passed":True,
        "unsupported_utf8_rejected":True,
        "same_default_stdout_as_crt_host_reference":True,
        "source_binary_sha256":hashlib.sha256(data).hexdigest(),
        "pe_bytes":len(data),"direct_imports":direct,
        "import_modules":modules,"missing_or_ordinal_imports":missing,
        "parser_rejection":rejection,
        "candidate_structurally_eligible_for_native_investigation":eligible,
        "current_guest_console_stdin_absent":True,
        "requires_new_guest_resource_grant_before_native_execution":True,
        "native_guest_execution_qualified":False,
        "windows_v1_release_qualified":False,
    }


def run_reference(app, plan, provenance, commit, runner_version):
    if type(commit) is not str or re.fullmatch(r"[a-f0-9]{40}", commit) is None:
        raise ValueError("exact source commit missing")
    if type(runner_version) is not str or not 1 <= len(runner_version) <= 100:
        raise ValueError("Windows image runner version missing")
    if not app.is_file() or app.is_symlink() or app.stat().st_size > 4*1024*1024:
        raise ValueError("produced PE exceeds bounded loader input size")
    image = app.read_bytes()
    cases = []
    for name, args, data, _ in CASES:
        outcome = subprocess.run([str(app), *args], input=data,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=12, check=False)
        cases.append(verify_case(name, outcome))
    # Non-ASCII is deliberately UNSUPPORTED by the bridge, not silently counted.
    rejected = subprocess.run([str(app), "-m"], input=b"\xc3\xa9\n",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=12, check=False)
    if rejected.returncode == 0 or b"non-ASCII" not in rejected.stderr:
        raise ValueError("host ASCII-only bridge failed closed")
    audit = None
    parser_rejection = None
    try:
        audit = discover(image, plan)
        if audit.get("architecture") != "amd64":
            raise ValueError("not AMD64 PE")
    except ValueError as exc:
        parser_rejection = str(exc)[:256]
    direct = audit.get("direct_imports") if audit else None
    missing = audit.get("missing_or_ordinal_imports", []) if audit else []
    blockers = ["Original named application not run in native Ryzova QEMU",
                "Platform bridge is ASCII-only and uses MSVC CRT on the Windows host",
                "Transitive Windows DLL/CRT imports and instruction paths not qualified"]
    if parser_rejection:
        blockers.append("PE parser rejected Windows compiler output: " + parser_rejection)
    if direct is not None and direct > 32:
        blockers.append("Original native PE 32-import cap exceeded")
    if missing:
        blockers.append(str(len(missing)) + " missing Win32/CRT imports")
    return {
        "schema": SCHEMA,
        "upstream_repo": UPSTREAM,
        "upstream_commit": UPSTREAM_COMMIT,
        "upstream_provenance": provenance,
        "license": "MIT, original complete sbase LICENSE included",
        "source_commit": commit,
        "windows_os_version": platform.version(),
        "runner_image_version": runner_version,
        "windows_reference_qualified": True,
        "named_workloads": cases,
        "unsupported_non_ascii_rejected": True,
        "pe_sha256": hashlib.sha256(image).hexdigest(),
        "pe_bytes": len(image),
        "pe_direct_imports": direct,
        "pe_import_modules": audit.get("modules", []) if audit else [],
        "pe_missing_direct_imports": missing,
        "pe_parser_rejection": parser_rejection,
        "native_ryzova_guest_executed": False,
        "native_guest_execution_qualified": False,
        "transitive_runtime_qualified": False,
        "windows_v1_release_qualified": False,
        "blocking_reasons": blockers,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--probe-ip", type=lambda v: int(v,0), default=None,
                    help="guest VM unsupported absolute AMD64 instruction pointer, diagnostics only")
    args = ap.parse_args()
    provenance = verify_upstream_sources()
    if os.name != "nt":
        raise RuntimeError("native Windows Server AMD64 reference runner required")
    root = os.environ.get("ProgramFiles(x86)")
    if not root:
        raise RuntimeError("Visual Studio installation not found")
    vswhere = Path(root) / "Microsoft Visual Studio/Installer/vswhere.exe"
    found = subprocess.run([str(vswhere), "-latest", "-products", "*",
                            "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                            "-property", "installationPath"],
                           capture_output=True, timeout=15, check=True, text=True).stdout.strip()
    if not found:
        raise RuntimeError("MSVC toolchain missing")
    output = ROOT / "artifacts/windows/w8-sbase"
    app = compile_windows(str(Path(found)/"VC/Auxiliary/Build/vcvars64.bat"),
                          FIXTURE, output)
    plan = json.loads((ROOT/"ryzova/compact/windows-v1-plan.json").read_text())
    report = run_reference(app, plan, provenance, os.environ.get("GITHUB_SHA", ""),
                           os.environ.get("ImageVersion", ""))
    mincrt = compile_mincrt_windows(str(Path(found)/"VC/Auxiliary/Build/vcvars64.bat"),
                                   FIXTURE, output)
    report["no_crt_candidate"] = run_mincrt_reference(mincrt, plan, report)
    if args.probe_ip is not None:
        diagnostic=pe_instruction_window(mincrt.read_bytes(), args.probe_ip)
        report["no_crt_opcode_probe"] = diagnostic
        print("W8_REAL_PE_OPCODE_PROBE "+json.dumps(diagnostic,sort_keys=True))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n",
                           encoding="utf-8")
    print(json.dumps({
        "name": "sbase wc (original MIT source, ASCII-only bridge)",
        "reference_passed": report["windows_reference_qualified"],
        "workloads": len(report["named_workloads"]),
        "pe_bytes": report["pe_bytes"],
        "pe_direct_imports": report["pe_direct_imports"],
        "missing_direct_count": len(report["pe_missing_direct_imports"]),
        "missing_import_sample": report["pe_missing_direct_imports"][:20],
        "no_crt_pe_imports": report["no_crt_candidate"]["direct_imports"],
        "no_crt_missing_imports": len(report["no_crt_candidate"]["missing_or_ordinal_imports"]),
        "no_crt_structural_candidate": report["no_crt_candidate"]["candidate_structurally_eligible_for_native_investigation"],
        "no_crt_parser_rejection": report["no_crt_candidate"]["parser_rejection"],
        "native_guest_execution_qualified": False,
        "windows_v1_release_qualified": False,
    }, sort_keys=True))
