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
            source = "main"
            if candidate is None:
                # The only supported initial dynamic loader is the existing
                # separately verified musl 1.2.6 interpreter at 0x800000.
                interpreter = (root / "lib/libc.so").resolve()
                if (interpreter.is_relative_to(root) and interpreter.is_file()
                        and interpreter.stat().st_size <= MAX_IMAGE):
                    libc = interpreter.read_bytes()
                    musl = next((v for v in targets if v.get("target")=="musl"),None)
                    if musl and type(musl.get("elf")) is dict and hashlib.sha256(libc).hexdigest() == musl["elf"].get("sha256"):
                        candidate = locate_candidate(libc,rip,bias=INTERP_BIAS)
                        source = "musl-interpreter"
            if candidate is not None:
                result["candidate"] = {"image":source, **candidate}
        records.append(result)
    return {
        "schema":_VERSION,
        "measured_profile_sha256":hashlib.sha256(json.dumps(profiles,sort_keys=True).encode()).hexdigest(),
        "guest_linux_v1_complete":False,
        "reports":records,
        "limitations":["Only initial main ELF and pinned musl interpreter biases",
                       "Cannot diagnose dlopen, remapped pages or JIT code",
                       "RIP is a bounded candidate, not proof of a faulting instruction",
                       "No change to interpreter, CPU support, resource budgets or release status"],
    }


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
