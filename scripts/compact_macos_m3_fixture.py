# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the project-owned, freestanding M3 Mach-O fixture."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAGE = 4096
BASE = 0x200000
ENTRY = 0x200


def build():
    with tempfile.TemporaryDirectory() as directory:
        obj = Path(directory) / "guest.o"
        binary = Path(directory) / "guest.bin"
        subprocess.run(["as", "--64", str(ROOT / "tests/fixtures/macos_m3_guest.S"),
                        "-o", obj], check=True)
        subprocess.run(["objcopy", "-O", "binary", "-j", ".text", obj, binary], check=True)
        code = binary.read_bytes()
    if len(code) > PAGE - ENTRY:
        raise ValueError("fixture exceeds text page")
    image = bytearray(PAGE)
    struct.pack_into("<8I", image, 0, 0xfeedfacf, 0x01000007, 3, 2, 3, 168, 0, 0)
    for offset, name, va, file_offset, file_size, protection in (
        (32, b"__TEXT", BASE, 0, PAGE, 5),
        (104, b"__DATA", BASE + PAGE, PAGE, 0, 3),
    ):
        struct.pack_into("<II16sQQQQIIII", image, offset, 0x19, 72, name, va,
                         PAGE, file_offset, file_size, protection, protection, 0, 0)
    struct.pack_into("<IIQQ", image, 176, 0x80000028, 24, ENTRY, 0)
    image[ENTRY:ENTRY + len(code)] = code
    return bytes(image)


if __name__ == "__main__":
    Path(sys.argv[1]).write_bytes(build())
