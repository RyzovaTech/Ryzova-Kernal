# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal read-only 9P2000 TCP server for Ryzova's *native guest* mount test.

This is a deliberately unauthenticated, *loopback-only*, test service. The
QEMU slirp guest reaches it through 10.0.2.2; no production network listener
or kernel-side TLS authentication is installed. The data is public test-only.
"""
from __future__ import annotations

import hashlib
import socket
import socketserver
import struct

from ryzova.remote.p9 import (
    MAX_FRAME, RATTACH, RCLUNK, RERROR, ROPEN, RREAD, RVERSION, RWALK,
    TATTACH, TCLUNK, TOPEN, TREAD, TVERSION, TWALK, Cursor, NinePError,
    frame, unframe,
)

TAUTH, RFLUSH, TFLUSH, TSTAT, RSTAT = 102, 109, 108, 124, 125
TWRITE, TCREATE, TREMOVE, TWSTAT = 118, 114, 122, 126
DMDIR, QTDIR = 0x80000000, 0x80
MAX_READ = 4096


def _s(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) > 255:
        raise NinePError("oversized stat name")
    return struct.pack("<H", len(data)) + data


def _qid(name: str) -> bytes:
    qtype = QTDIR if name == "/" else 0
    path = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "little")
    return struct.pack("<BIQ", qtype, 0, path)


def _stat(name: str, data: bytes | None) -> bytes:
    directory = data is None
    mode = (DMDIR | 0o555) if directory else 0o444
    body = (struct.pack("<HI", 0, 0) + _qid(name)
            + struct.pack("<IIIQ", mode, 0, 0, 0 if directory else len(data))
            + _s("." if directory else name)
            + _s("glenda") + _s("glenda") + _s("glenda"))
    return struct.pack("<H", len(body)) + body


class Native9PConnection:
    """Each TCP session has a separate fid table, avoiding cross-client reuse."""

    def __init__(self, files: dict[str, bytes]):
        self.files = files
        self.fids: dict[int, tuple[str, bool]] = {}
        self.negotiated = False
        self.msize = MAX_FRAME

    def _node(self, name: str) -> bytes | None:
        if name == "/":
            return None
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]

    def process(self, packet: bytes) -> bytes:
        kind, tag, cur = unframe(packet)
        try:
            answer, content = self._handle(kind, cur)
            cur.done()
            return frame(answer, tag, content)
        except (ValueError, KeyError, UnicodeError, NinePError, PermissionError,
                FileNotFoundError, struct.error):
            return frame(RERROR, tag, _s("read-only test service: request denied"))

    def _handle(self, kind: int, cur: Cursor) -> tuple[int, bytes]:
        if kind == TVERSION:
            msize = cur.unpack("<I")
            version = cur.string()
            if msize < 256 or version != "9P2000":
                raise NinePError("9P2000 required")
            self.msize = min(msize, MAX_FRAME)
            self.negotiated = True
            self.fids.clear()
            return RVERSION, struct.pack("<I", self.msize) + _s("9P2000")
        if not self.negotiated:
            raise NinePError("negotiate version first")
        if kind == TAUTH:
            # No authenticated users: mount -n is explicitly for a public,
            # disposable QEMU fixture, not a credentialed remote service.
            raise PermissionError("auth unsupported")
        if kind == TFLUSH:
            cur.unpack("<H")
            return RFLUSH, b""
        if kind == TATTACH:
            fid, afid = cur.unpack("<I"), cur.unpack("<I")
            cur.string()  # uname is not interpreted as OS authorization
            aname = cur.string()
            if fid in self.fids or afid != 0xffffffff or aname:
                raise PermissionError()
            self.fids[fid] = ("/", False)
            return RATTACH, _qid("/")
        if kind == TWALK:
            fid, newfid, count = cur.unpack("<I"), cur.unpack("<I"), cur.unpack("<H")
            if (fid not in self.fids or (newfid in self.fids and fid != newfid) or
                    count > 1):
                raise NinePError("only one-level walk")
            old, opened = self.fids[fid]
            if opened:
                raise PermissionError()
            if count == 0:
                self.fids[newfid] = (old, False)
                return RWALK, struct.pack("<H", 0)
            name = cur.string()
            if name == ".." or (name != "." and (old != "/" or name not in self.files)):
                raise FileNotFoundError()
            new = old if name == "." else name
            self.fids[newfid] = (new, False)
            return RWALK, struct.pack("<H", 1) + _qid(new)
        if kind == TOPEN:
            fid, mode = cur.unpack("<I"), cur.unpack("<B")
            if fid not in self.fids or mode != 0:
                raise PermissionError()
            name, opened = self.fids[fid]
            if opened:
                raise PermissionError()
            self.fids[fid] = (name, True)
            return ROPEN, _qid(name) + struct.pack("<I", MAX_READ)
        if kind == TREAD:
            fid, offset, count = cur.unpack("<I"), cur.unpack("<Q"), cur.unpack("<I")
            if fid not in self.fids or not self.fids[fid][1]:
                raise PermissionError()
            if count > MAX_READ or count > self.msize - 11:
                raise NinePError("read exceeds msize")
            name = self.fids[fid][0]
            if name == "/":
                value = b"".join(_stat(path, contents)
                                 for path, contents in sorted(self.files.items()))
                # Directory reads must be aligned at stat-record boundaries.
                if offset not in (0, len(value)):
                    raise NinePError("directory seek not supported")
                if offset == 0 and len(value) > count:
                    raise NinePError("directory stat too large")
            else:
                value = self._node(name)
            data = value[offset:offset + count]
            return RREAD, struct.pack("<I", len(data)) + data
        if kind == TSTAT:
            fid = cur.unpack("<I")
            if fid not in self.fids:
                raise FileNotFoundError()
            name = self.fids[fid][0]
            data = _stat(name, self._node(name))
            return RSTAT, struct.pack("<H", len(data)) + data
        if kind == TCLUNK:
            fid = cur.unpack("<I")
            if fid not in self.fids:
                raise FileNotFoundError()
            del self.fids[fid]
            return RCLUNK, b""
        if kind in (TWRITE, TCREATE, TREMOVE, TWSTAT):
            raise PermissionError("read-only")
        raise NinePError("unsupported request")


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = Native9PConnection(self.server.files)
        self.request.settimeout(8)
        try:
            while True:
                header = self._read(4)
                if header is None:
                    break
                size = struct.unpack("<I", header)[0]
                if size < 7 or size > MAX_FRAME:
                    break
                body = self._read(size - 4)
                if body is None:
                    break
                response = conn.process(header + body)
                self.request.sendall(response)
                self.server.frames += 1
        except (OSError, NinePError, struct.error):
            pass

    def _read(self, length):
        buf = bytearray()
        while len(buf) < length:
            data = self.request.recv(length-len(buf))
            if not data:
                return None
            buf.extend(data)
        return bytes(buf)


class Native9PTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, files: dict[str, bytes], port=15640):
        if not isinstance(files, dict) or len(files) != 1:
            raise ValueError("one public read-only fixture only")
        for name, value in files.items():
            if (name != "probe" or not isinstance(value, bytes)
                    or not 0 < len(value) <= MAX_READ):
                raise ValueError("invalid native 9P fixture")
        self.files = files.copy()
        self.frames = 0
        # Never listen on a public interface. Slirp's 10.0.2.2 reaches the
        # QEMU host's loopback address. If unavailable, verification fails.
        super().__init__(("127.0.0.1", port), _TCPHandler)
