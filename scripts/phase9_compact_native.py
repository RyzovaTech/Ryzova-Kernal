# SPDX-License-Identifier: AGPL-3.0-only
"""Native Compact execution fixtures and strict serial evidence, not a full ABI."""
import hashlib
import re
import struct


def elf(code, data=b""):
    """A real static ELF64 executable, independently runnable on Linux AMD64."""
    image = bytearray(0x200 + len(data))
    image[:64] = struct.pack("<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1,
        0x400100, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    image[64:120] = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000,
                               0x400000, len(image), len(image), 4096)
    image[0x100:0x100 + len(code)] = code
    image[0x200:] = data
    return bytes(image)


def fixtures(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected full source commit")
    message = f"FLEX_COMPACT_{commit}\n".encode()
    # mov eax,1; mov edi,1; lea rsi,[rip+disp]; mov edx,len; syscall;
    # mov eax,60; xor edi,edi; syscall. No compiler/runtime dependency.
    code = (b"\xb8\x01\0\0\0\xbf\x01\0\0\0\x48\x8d\x35"
            + struct.pack("<i", 0x200 - (0x100 + 17))
            + b"\xba" + struct.pack("<I", len(message)) + b"\x0f\x05"
            + b"\xb8\x3c\0\0\0\x31\xff\x0f\x05")
    return {"hello": elf(code, message), "loop": elf(b"\xeb\xfe"),
            "opcode": elf(b"\xcc"),
            "syscall": elf(b"\xb8\x39\0\0\0\x0f\x05"),
            "exit7": elf(b"\xb8\x3c\0\0\0\xbf\x07\0\0\0\x0f\x05")}


def commands():
    result = []
    index = 26
    for name in ("hello", "loop", "opcode", "syscall", "exit7"):
        result.append(f"hget http://10.0.2.2:8000/compact-{name}.elf > /tmp/c-{name}; "
                      f"echo RYZOVA_RUNTIME_STAGE_{index}")
        index += 1
        # Markers printed separately from the command echo; guest output is
        # captured only between standalone lines.
        result.append(f"echo COMPACT_{name}_BEGIN; compact-linux /tmp/c-{name}; "
                      f"echo COMPACT_{name}_END; echo RYZOVA_RUNTIME_STAGE_{index}")
        index += 1
    result.append("sha1sum -2 256 /tmp/c-hello; echo RYZOVA_RUNTIME_STAGE_36; "
                  "echo RYZOVA_COMPACT_DONE")
    return result


def inspect(build_serial, serial, commit):
    def line(raw, value):
        return re.search(rb"(?:^|\r?\n)" + re.escape(value) + rb"(?:\r?\n|$)", raw) is not None
    checks = {"native_build": line(build_serial, b"COMPACT_NATIVE_BUILD_OK"),
              "stages": all(line(serial, f"RYZOVA_RUNTIME_STAGE_{i}".encode())
                            for i in range(26, 37)),
              "completed": line(serial, b"RYZOVA_COMPACT_DONE"),
              "no_panic": re.search(rb"(?im)^panic:", serial) is None}
    expected = {"hello": (0, 1, 0, 8, 2), "loop": (4, 0, 0, 2048, 0),
                "opcode": (3, 0, 0, 1, 0), "syscall": (5, 0, 0, 2, 0),
                "exit7": (0, 1, 7, 3, 1)}
    for name, values in expected.items():
        section = re.search(rb"(?:^|\r?\n)COMPACT_" + name.encode()
            + rb"_BEGIN\r?\n(.*?)\r?\nCOMPACT_" + name.encode()
            + rb"_END(?:\r?\n|$)", serial, re.S)
        status, exited, exitcode, steps, calls = values
        marker = (f"COMPACT_LINUX_RESULT status={status} exited={exited} "
                  f"exit={exitcode} steps={steps} syscalls={calls}").encode()
        checks[name] = section is not None and line(section.group(1), marker)
        if name == "hello":
            checks["source_challenge_output"] = section is not None and line(
                section.group(1), f"FLEX_COMPACT_{commit}".encode())
    digest = hashlib.sha256(fixtures(commit)["hello"]).hexdigest()
    checks["input_sha256"] = re.search(rb"(?:^|\r?\n)" + digest.encode()
        + rb"\s+/tmp/c-hello(?:\r?\n|$)", serial) is not None
    return {"schema": "flex-compact-native-subset/v1", "source_commit": commit,
            "input_sha256": digest, "checks": checks, "passed": all(checks.values()),
            "execution": "native Plan 9 application interpreting Linux AMD64 subset",
            "general_linux_compatibility": False, "windows_execution": False,
            "mac_execution": False, "physical_hardware_certified": False}
