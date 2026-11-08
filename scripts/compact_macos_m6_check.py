# SPDX-License-Identifier: GPL-3.0-only
"""Compare the actual macOS binaries with the hosted Flex harness."""
from pathlib import Path
import subprocess
import sys
import tempfile


def check(runner, references):
    for arch, mode in (("x86_64", "--files-x86"), ("arm64", "--files-arm64")):
        binary = references / f"compact-macos-m6-{arch}" / "m6"
        with tempfile.TemporaryDirectory() as directory:
            outer = Path(directory)
            root = outer / "grant"
            root.mkdir()
            entry = root / "entry.txt"
            entry.write_bytes(b"IN!\n")
            outside = outer / "outside.txt"
            outside.write_bytes(b"SAFE\n")
            (root / "alias").symlink_to(outside)
            for grant, name, expected in ((root, "entry.txt", 61), (root, "../outside.txt", 13),
                                          (root, "alias", 13), ("-", "entry.txt", 13)):
                result = subprocess.run([runner, mode, binary, grant, name, "demo"],
                                        capture_output=True, timeout=5)
                if (result.returncode, result.stdout, result.stderr) != (
                        expected, b"IN!\n" if expected == 61 else b"", b""):
                    raise ValueError(f"{arch} {name}: {result}")
                if entry.read_bytes() != b"IN!\nFLEX_NOTE=demo" or outside.read_bytes() != b"SAFE\n":
                    raise ValueError(f"{arch} {name}: file byte mismatch")
        print(f"{arch}: output, status, write and denied access verified")


if __name__ == "__main__":
    check(Path(sys.argv[1]), Path(sys.argv[2]))
