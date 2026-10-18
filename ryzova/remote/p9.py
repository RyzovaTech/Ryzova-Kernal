# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 6.1: minimal read-only 9P2000 frame server/client over injected transport.

Only protocol subset, no real mount, no network sockets. Authentication is
provided separately by the mandatory LocalAuthenticatedTransport test adapter.
"""
import hashlib
import struct


class NinePError(Exception):
    pass


TVERSION, RVERSION = 100, 101
RERROR = 107
TATTACH, RATTACH = 104, 105
TWALK, RWALK = 110, 111
TOPEN, ROPEN = 112, 113
TREAD, RREAD = 116, 117
TCLUNK, RCLUNK = 120, 121
MAX_FRAME = 8192
READ_LIMIT = 4096


def _string(s):
    data = s.encode("utf-8")
    if len(data) > 255:
        raise NinePError("overlong 9P name")
    return struct.pack("<H", len(data)) + data


class Cursor:
    def __init__(self, b):
        self.data, self.pos = b, 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise NinePError("truncated 9P message")
        chunk = self.data[self.pos:self.pos+n]
        self.pos += n
        return chunk

    def unpack(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self):
        length = self.unpack("<H")
        if length > 255:
            raise NinePError("overlong 9P string")
        return self.take(length).decode("utf-8")

    def done(self):
        if self.pos != len(self.data):
            raise NinePError("trailing 9P bytes")


def frame(msg_type, tag, payload=b""):
    if len(payload) + 7 > MAX_FRAME or not 0 <= tag <= 65535:
        raise NinePError("9P frame limit")
    return struct.pack("<IBH", len(payload)+7, msg_type, tag) + payload


def unframe(raw):
    if len(raw) < 7 or len(raw) > MAX_FRAME:
        raise NinePError("9P frame length")
    count, kind, tag = struct.unpack_from("<IBH", raw)
    if count != len(raw):
        raise NinePError("9P frame length mismatch")
    return kind, tag, Cursor(raw[7:])


def _qid(name):
    path = int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "little")
    return struct.pack("<BIQ", 0x80 if name == "/" else 0, 0, path)


class ReadOnly9PServer:
    def __init__(self, files):
        if not isinstance(files, dict) or len(files) > 32:
            raise ValueError("bounded flat content dictionary required")
        self.files = {}
        for name, value in files.items():
            if (not isinstance(name, str) or not name or name in (".","..") or
                "/" in name or chr(0) in name or len(name.encode("utf-8")) > 128 or
                not isinstance(value, bytes) or len(value) > 65536):
                raise ValueError("invalid remote resource")
            self.files[name] = value
        self.fids = {}
        self.negotiated = False

    def process(self, raw):
        msg_type, tag, cur = unframe(raw)
        try:
            answer_type, result = self._handle(msg_type, cur)
            cur.done()
            return frame(answer_type, tag, result)
        except (NinePError, ValueError, UnicodeError, struct.error) as err:
            return frame(RERROR, tag, _string("invalid request"))
        except PermissionError:
            return frame(RERROR, tag, _string("read-only permission denied"))
        except FileNotFoundError:
            return frame(RERROR, tag, _string("not found"))

    def _handle(self, kind, cur):
        if kind == TVERSION:
            msize=cur.unpack("<I")
            version=cur.string()
            if msize < 256 or msize > MAX_FRAME or version != "9P2000":
                raise NinePError("unsupported version")
            self.fids.clear()
            self.negotiated = True
            return RVERSION, struct.pack("<I", MAX_FRAME) + _string("9P2000")
        if not self.negotiated:
            raise NinePError("version required")
        if kind == TATTACH:
            fid=cur.unpack("<I")
            afid=cur.unpack("<I")
            uname=cur.string()
            aname=cur.string()
            if fid in self.fids or afid != 0xffffffff or aname or uname:
                raise NinePError("restricted attach")
            self.fids[fid] = ("/", False)
            return RATTACH, _qid("/")
        if kind == TWALK:
            fid=cur.unpack("<I")
            newfid=cur.unpack("<I")
            n=cur.unpack("<H")
            if fid not in self.fids or newfid in self.fids or n != 1:
                raise NinePError("restricted walk")
            name=cur.string()
            parent, _ = self.fids[fid]
            if parent != "/" or name not in self.files:
                raise FileNotFoundError()
            self.fids[newfid]=(name,False)
            return RWALK, struct.pack("<H",1) + _qid(name)
        if kind == TOPEN:
            fid=cur.unpack("<I")
            mode=cur.unpack("<B")
            if fid not in self.fids or mode != 0:
                raise PermissionError()
            path, opened = self.fids[fid]
            if path == "/" or opened:
                raise PermissionError()
            self.fids[fid]=(path,True)
            return ROPEN, _qid(path) + struct.pack("<I", READ_LIMIT)
        if kind == TREAD:
            fid=cur.unpack("<I")
            offset=cur.unpack("<Q")
            count=cur.unpack("<I")
            if fid not in self.fids or not self.fids[fid][1]:
                raise PermissionError()
            if count > READ_LIMIT:
                raise NinePError("read quota")
            contents=self.files[self.fids[fid][0]]
            return RREAD, struct.pack("<I",len(contents[offset:offset+count])) + contents[offset:offset+count]
        if kind == TCLUNK:
            fid=cur.unpack("<I")
            if fid not in self.fids:
                raise NinePError("unknown fid")
            del self.fids[fid]
            return RCLUNK, b""
        raise PermissionError()  # write/create/remove/stat not available


class ReadOnly9PClient:
    def __init__(self, request):
        self.request = request
        self.tag = 0

    def call(self, operation, payload, response_kind):
        self.tag=(self.tag+1) % 65535
        kind, tag, cursor = unframe(self.request(frame(operation,self.tag,payload)))
        if tag != self.tag:
            raise NinePError("9P mismatched tag")
        if kind == RERROR:
            message=cursor.string()
            cursor.done()
            raise NinePError("remote 9P error: "+message)
        if kind != response_kind:
            raise NinePError("unexpected 9P reply type")
        return cursor

    def read_file(self, name, max_total=65536):
        if (not isinstance(name,str) or not name or name in (".","..") or
            "/" in name or chr(0) in name or max_total > 65536 or max_total < 0):
            raise NinePError("invalid read scope")
        c=self.call(TVERSION,struct.pack("<I",MAX_FRAME)+_string("9P2000"),RVERSION)
        if c.unpack("<I") != MAX_FRAME or c.string() != "9P2000":
            raise NinePError("failed negotiation")
        c.done()
        c=self.call(TATTACH,struct.pack("<II",1,0xffffffff)+_string("")+_string(""),RATTACH)
        c.take(13);c.done()
        try:
            c=self.call(TWALK,struct.pack("<IIH",1,2,1)+_string(name),RWALK)
            if c.unpack("<H") != 1:raise NinePError("no file walked")
            c.take(13);c.done()
            try:
                c=self.call(TOPEN,struct.pack("<IB",2,0),ROPEN)
                c.take(13);unit=c.unpack("<I");c.done()
                if unit < 1 or unit > READ_LIMIT:
                    raise NinePError("invalid iounit")
                offset=0
                chunks=[]
                while offset < max_total:
                    step=min(READ_LIMIT,max_total-offset)
                    cur=self.call(TREAD,struct.pack("<IQI",2,offset,step),RREAD)
                    n=cur.unpack("<I")
                    if n > step:raise NinePError("oversized read response")
                    block=cur.take(n);cur.done()
                    if not block:break
                    chunks.append(block);offset+=n
                return b"".join(chunks)
            finally:
                self.call(TCLUNK,struct.pack("<I",2),RCLUNK).done()
        finally:
            self.call(TCLUNK,struct.pack("<I",1),RCLUNK).done()
