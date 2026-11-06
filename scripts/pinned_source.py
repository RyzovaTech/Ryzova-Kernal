# SPDX-License-Identifier: GPL-3.0-only
"""Fetch SHA-256-pinned CI sources with bounded, atomic writes.

An authenticated cache hit avoids network access. Every cache and mirror byte is
checked against an expected digest; unavailable or tampered sources fail closed.
This is a reproducibility helper, not proof of upstream signature authenticity.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import urllib.request


def fetch_pinned(destination, urls, expected_sha256, *, max_bytes, timeout=60):
    destination = Path(destination)
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)):
        raise ValueError("expected_sha256 must be a lowercase 64-character hex digest")
    if not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if destination.exists():
        if not destination.is_file():
            raise ValueError("pinned archive cache is not a regular file: " + str(destination))
        with destination.open("rb") as cached:
            h = hashlib.sha256()
            count = 0
            while True:
                block = cached.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > max_bytes:
                    raise ValueError("oversized cached pinned source: " + str(destination))
                h.update(block)
        if h.hexdigest() != expected_sha256:
            raise ValueError("cached pinned source SHA256 mismatch: " + str(destination))
        return destination

    destination.parent.mkdir(parents=True, exist_ok=True)
    failures = []
    for url in urls:
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError("pinned source URL must be HTTPS")
        temporary = None
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                with tempfile.NamedTemporaryFile(
                    mode="wb", prefix="." + destination.name + ".",
                    dir=destination.parent, delete=False
                ) as output:
                    temporary = Path(output.name)
                    h = hashlib.sha256()
                    count = 0
                    while True:
                        chunk = response.read(min(1024 * 1024, max_bytes - count + 1))
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > max_bytes:
                            raise ValueError("pinned source download exceeds maximum size")
                        h.update(chunk)
                        output.write(chunk)
            if h.hexdigest() != expected_sha256:
                raise ValueError("downloaded source SHA256 mismatch")
            os.replace(temporary, destination)
            return destination
        except (OSError, ValueError) as error:
            failures.append(type(error).__name__ + ": " + str(error))
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    raise RuntimeError("all pinned source mirrors failed: " + "; ".join(failures))
