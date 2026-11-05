# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-04: correlate *candidate* guest failure RIPs with locked ELF bytes.

This is a read-only, fail-closed triage instrument. It NEVER executes
instructions, declares ISA compatibility, changes guest limits, or trusts
unmatched addresses. Actual failing opcode and machine state must still be
confirmed by a native guest and differential reference. Only Ryzova's
declared ET_DYN main/ld-musl biases are considered (see process.c).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

MAX_IMAGE = 64 * 1024 * 1024
MAX_TARGETS = 16
MAX_BYTES = 15
MAIN_PIE_BIAS = 0x400000
INTERP_BIAS = 0x800000
_VERSION = "compact-linux-clx04-rip-discovery/v1"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


def locate_candidate(image, rip, *, bias=0):
    """Return bounded file-backed PT_LOAD bytes for a *candidate* instruction.

    RIP can identify the *next* instruction after a fault, not necessarily
    the faulting opcode. JIT, guest mmap and dlopen locations cannot be
    attributed from the two initial ELF images alone.
    """
    if (type(image) is not bytes or not 64 <= len(image) <= MAX_IMAGE
            or image[:6] != b"\x7fELF\x02\x01" or image[6] != 1
            or type(rip) is not int or not 0 <= rip < 2**64
            or type(bias) is not int or not 0 <= bias < 2**64
            or int.from_bytes(image[18:20], "little") != 62):
        return None
    e_type = int.from_bytes(image[16:18], "little")
    if e_type not in (2, 3) or (e_type == 2 and bias != 0):
        return None
    if int.from_bytes(image[52:54], "little") != 64:
        return None
    phoff = int.from_bytes(image[32:40], "little")
    entsize = int.from_bytes(image[54:56], "little")
    count = int.from_bytes(image[56:58], "little")
    if entsize != 56 or not 1 <= count <= 128 or phoff > len(image) or count * entsize > len(image) - phoff:
        return None
    for i in range(count):
        at = phoff + i * entsize
        segment = image[at:at + entsize]
        if int.from_bytes(segment[:4], "little") != 1:
            continue
        flags = int.from_bytes(segment[4:8], "little")
        offset = int.from_bytes(segment[8:16], "little")
        vaddr = int.from_bytes(segment[16:24], "little")
        filesz = int.from_bytes(segment[32:40], "little")
        memsz = int.from_bytes(segment[40:48], "little")
        if (filesz == 0 or filesz > memsz or offset > len(image)
                or filesz > len(image) - offset or vaddr > 2**64 - bias):
            continue
        start = vaddr + bias
        if rip < start or rip - start >= filesz:
            continue
        within = rip - start
        actual = offset + within
        n = min(MAX_BYTES, filesz - within)
        return {
            "rip_hex": hex(rip),
            "load_bias_hex": hex(bias),
            "elf_file_offset": actual,
            "candidate_bytes_hex": image[actual:actual + n].hex(),
            "segment_executable": bool(flags & 1),
            "bytes_are_only_candidate": True,
        }
    return None



def relocated_interpreter_bias(main_image):
    """Mirror the bounded main PT_LOAD high-water relocation in process.c.

    The dynamic linker is at 0x800000 only when a main executable fits below
    that address. Large PIEs relocate it to the next 2-MiB boundary after
    the mapped main ELF, including BSS/page rounding (not file length).
    No ELF bytes or memory are modified by this diagnostic.
    """
    if (type(main_image) is not bytes or not 64 <= len(main_image) <= MAX_IMAGE
            or main_image[:7] != b"\x7fELF\x02\x01\x01"
            or int.from_bytes(main_image[18:20], "little") != 62):
        return None
    e_type = int.from_bytes(main_image[16:18], "little")
    if e_type not in (2, 3):
        return None
    bias = MAIN_PIE_BIAS if e_type == 3 else 0
    phoff = int.from_bytes(main_image[32:40], "little")
    entsize = int.from_bytes(main_image[54:56], "little")
    count = int.from_bytes(main_image[56:58], "little")
    if (int.from_bytes(main_image[52:54], "little") != 64 or entsize != 56
            or not 1 <= count <= 128 or phoff > len(main_image)
            or count * entsize > len(main_image) - phoff):
        return None
    main_high = 0
    for i in range(count):
        at = phoff + i * entsize
        segment = main_image[at:at + entsize]
        if int.from_bytes(segment[:4], "little") != 1:
            continue
        flags = int.from_bytes(segment[4:8], "little")
        offset = int.from_bytes(segment[8:16], "little")
        vaddr = int.from_bytes(segment[16:24], "little")
        filesz = int.from_bytes(segment[32:40], "little")
        memsz = int.from_bytes(segment[40:48], "little")
        # Insist on bounded file-backed, mapped, W^X program headers.
        # A malformed ELF is NOT evidence of an executable loader mapping.
        if (memsz == 0 or filesz > memsz or offset > len(main_image)
                or filesz > len(main_image) - offset or flags & ~7
                or flags & 3 == 3 or vaddr % 4096 != offset % 4096
                or vaddr + bias < 0x10000
                or vaddr + bias + memsz > 0x0000800000000000):
            return None
        end = (vaddr + bias + memsz + 4095) & ~4095
        main_high = max(main_high, end)
    if not main_high:
        return None
    if main_high > INTERP_BIAS:
        if main_high > 0x0000800000000000 - 0x200000:
            return None
        return (main_high + 0x1fffff) & ~0x1fffff
    return INTERP_BIAS


def pinned_musl_candidate(root, targets, main_image, rip):
    """Return a separately SHA-pinned loader candidate (or None), never a guess."""
    bias = relocated_interpreter_bias(main_image)
    if bias is None:
        return None
    interp = (root / "lib/libc.so").resolve()
    if (not interp.is_relative_to(root) or not interp.is_file()
            or interp.stat().st_size > MAX_IMAGE):
        return None
    musl = next((v for v in targets if v.get("target") == "musl"), None)
    if not musl or type(musl.get("elf")) is not dict:
        return None
    raw = interp.read_bytes()
    if hashlib.sha256(raw).hexdigest() != musl["elf"].get("sha256"):
        return None
    found = locate_candidate(raw, rip, bias=bias)
    return {"image": "musl-interpreter", **found} if found is not None else None


def create_report(root, profiles):
    """Use only named, checksum-recorded target files from the measured root."""
    if type(profiles) is not dict or type(profiles.get("targets")) is not list:
        raise ValueError("target profiles required")
    targets = profiles["targets"]
    if len(targets) > MAX_TARGETS:
        raise ValueError("bounded target profiles required")
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("actual measured root required")
    records = []
    for target in targets:
        if type(target) is not dict:
            raise ValueError("malformed target")
        name = target.get("target")
        if type(name) is not str or not _IDENTIFIER.fullmatch(name):
            raise ValueError("invalid target name")
        # Output from the executable report, rather than a package name or
        # synthesized "successful" status, determines the candidate.
        elf = target.get("elf")
        if type(elf) is not dict or type(elf.get("sha256")) is not str:
            raise ValueError("missing image provenance")
        rip_string = (target.get("guest_actual_result") or {}).get("last_rip_hex")
        result = {"target":name, "guest_smoke_passed":target.get("guest_smoke_passed") is True,
                  "guest_actual_result":target.get("guest_actual_result"), "candidate":None,
                  "limitations":"candidate bytes do not prove a decoded/failing ISA opcode"}
        # Never label an ordinary successful exit RIP as a failed opcode.
        if (target.get("guest_smoke_passed") is not True
                and type(rip_string) is str
                and re.fullmatch(r"[0-9a-f]{1,16}",rip_string)):
            rip = int(rip_string,16)
            # Pin to exactly the measured executable basename, never use any
            # untrusted guest pathname or arbitrary path from a profile.
            names = {"busybox":"/bin/busybox", "python":"/usr/bin/python3.12",
                     "git":"/usr/bin/git", "gcc":"/bin/gcc", "binutils":"/bin/as",
                     "make":"/usr/bin/make", "musl":"/lib/libc.so"}
            if name not in names:
                raise ValueError("unknown frozen target")
            image = (root / names[name].lstrip("/")).resolve()
            # The pinned target build legitimately uses /bin/gcc and /bin/as
            # symlinks. Resolve those inside the measured root, never outside.
            if (not image.is_relative_to(root) or not image.is_file()
                    or image.stat().st_size > MAX_IMAGE):
                raise ValueError("missing bounded measured executable")
            data = image.read_bytes()
            if hashlib.sha256(data).hexdigest() != elf["sha256"]:
                raise ValueError("measured target digest mismatch")
            etype = int.from_bytes(data[16:18], "little") if len(data) >= 64 else 0
            candidate = locate_candidate(data,rip,bias=MAIN_PIE_BIAS if etype==3 else 0)
            if candidate is not None:
                result["candidate"] = {"image": "main", **candidate}
            else:
                result["candidate"] = pinned_musl_candidate(root, targets, data, rip)
        records.append(result)
        # Successful --version does not qualify actual CPython execution.
        # Preserve a separate, digest-bound candidate for the -c proof.
        probe=target.get("python_code_probe")
        if name=="python" and type(probe) is dict:
            observed=probe.get("actual")
            detail={"target":"python-code", "guest_smoke_passed":probe.get("passed") is True,
                    "guest_actual_result":observed, "candidate":None,
                    "limitations":"actual -c execution is required; RIP is only a byte candidate"}
            cursor=(observed or {}).get("last_rip_hex") if type(observed) is dict else None
            if (probe.get("passed") is not True and
                    type(cursor) is str and re.fullmatch(r"[0-9a-f]{1,16}",cursor)):
                image=(root/"usr/bin/python3.12").resolve()
                if (not image.is_relative_to(root) or not image.is_file()
                        or image.stat().st_size>MAX_IMAGE):
                    raise ValueError("missing bounded pinned Python")
                binary=image.read_bytes()
                if hashlib.sha256(binary).hexdigest()!=elf["sha256"]:
                    raise ValueError("measured Python ELF digest mismatch")
                etype=int.from_bytes(binary[16:18],"little") if len(binary)>=64 else 0
                candidate=locate_candidate(binary,int(cursor,16),
                                           bias=MAIN_PIE_BIAS if etype==3 else 0)
                if candidate is not None:
                    detail["candidate"]={"image":"main",**candidate}
                else:
                    # -c can fail inside a *relocated* pinned musl loader.
                    # Version-smoke success does not validate this code probe.
                    detail["candidate"]=pinned_musl_candidate(
                        root, targets, binary, int(cursor,16))
            records.append(detail)
    return {
        "schema":_VERSION,
        "measured_profile_sha256":hashlib.sha256(json.dumps(profiles,sort_keys=True).encode()).hexdigest(),
        "guest_linux_v1_complete":False,
        "reports":records,
        "limitations":["Only initial main ELF and SHA-pinned musl interpreter relocation",
                       "Cannot diagnose dlopen, remapped pages or JIT code",
                       "RIP is a bounded candidate, not proof of a faulting instruction",
                       "No change to interpreter, CPU support, resource budgets or release status"],
    }



def bounded_failure_console_lines(report):
    """Seven compact, evidence-only diagnostic lines for GitHub CI logs."""
    lines=[]
    for record in report.get("reports",[]):
        if record.get("guest_smoke_passed") is True:
            continue
        actual=record.get("guest_actual_result") or {}
        candidate=record.get("candidate")
        row={"target":record.get("target"),
             "vm_status":actual.get("status"),
             "last_rip_hex":actual.get("last_rip_hex"),
             "unsupported_syscall_nr":actual.get("unsupported_syscall_nr"),
             "candidate_elf_bytes_hex":candidate.get("candidate_bytes_hex") if candidate else None,
             "candidate_image":candidate.get("image") if candidate else None,
             "opcode_failure_verified":False}
        lines.append("CLX04_GUEST_FAILURE "+json.dumps(row,sort_keys=True,separators=(",",":")))
    return lines


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--profiles",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    source=json.loads(a.profiles.read_text())
    report=create_report(a.root,source)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"schema":report["schema"],
                      "candidates":sum(x["candidate"] is not None for x in report["reports"]),
                      "targets":len(report["reports"]),
                      "guest_linux_v1_complete":False},sort_keys=True))
    for line in bounded_failure_console_lines(report):
        print(line)
