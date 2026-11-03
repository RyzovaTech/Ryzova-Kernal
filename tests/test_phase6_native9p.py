# SPDX-License-Identifier: AGPL-3.0-only
"""Native guest-facing 9P2000 server protocol tests over real loopback TCP."""
import socket
import struct
import threading
import unittest
from ryzova.remote.native9p import (
    Native9PTCPServer, Native9PConnection, TSTAT, RSTAT, TWRITE, RERROR)
from ryzova.remote.p9 import (
    frame, unframe, TVERSION, RVERSION, TATTACH, RATTACH,
    TWALK, RWALK, TOPEN, ROPEN, TREAD, RREAD, TCLUNK, RCLUNK,
    ReadOnly9PClient, MAX_FRAME)

def packet(sock, kind, tag, body):
    sock.sendall(frame(kind, tag, body))
    def read(n):
        buf=b""
        while len(buf)<n:
            b=sock.recv(n-len(buf))
            if not b:raise EOFError()
            buf+=b
        return buf
    header=read(4)
    n=struct.unpack("<I",header)[0]
    return unframe(header+read(n-4))

def string(s):
    b=s.encode()
    return struct.pack("<H",len(b))+b

class Native9PTests(unittest.TestCase):
    def setUp(self):
        self.server=Native9PTCPServer({"probe":b"Ryzova QEMU native 9P data\n"},port=0)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
    def test_real_tcp_mount_style_requests(self):
        with socket.create_connection(("127.0.0.1",self.server.server_address[1]),timeout=3) as s:
            s.settimeout(3)
            k,_,c=packet(s,TVERSION,1,struct.pack("<I",MAX_FRAME)+string("9P2000"))
            self.assertEqual(k,RVERSION)
            self.assertEqual(c.unpack("<I"),MAX_FRAME)
            self.assertEqual(c.string(),"9P2000")
            k,_,c=packet(s,TATTACH,2,struct.pack("<II",1,0xffffffff)+string("glenda")+string(""))
            self.assertEqual(k,RATTACH);c.take(13);c.done()
            k,_,c=packet(s,TSTAT,3,struct.pack("<I",1))
            self.assertEqual(k,RSTAT)
            size=c.unpack("<H")
            self.assertEqual(len(c.take(size)),size)
            k,_,c=packet(s,TWALK,4,struct.pack("<IIH",1,2,1)+string("probe"))
            self.assertEqual(k,RWALK);self.assertEqual(c.unpack("<H"),1);c.take(13)
            k,_,c=packet(s,TOPEN,5,struct.pack("<IB",2,0))
            self.assertEqual(k,ROPEN);c.take(13);self.assertEqual(c.unpack("<I"),4096)
            k,_,c=packet(s,TREAD,6,struct.pack("<IQI",2,0,4096))
            self.assertEqual(k,RREAD)
            self.assertEqual(c.take(c.unpack("<I")),b"Ryzova QEMU native 9P data\n")
            k,_,_=packet(s,TWRITE,7,struct.pack("<IQI",2,0,1)+b"x")
            self.assertEqual(k,RERROR)
            k,_,_=packet(s,TCLUNK,8,struct.pack("<I",2));self.assertEqual(k,RCLUNK)
    def test_client_compatibility_with_existing_phase6_wire_reader(self):
        from ryzova.remote.p9 import ReadOnly9PClient
        def request(raw):
            with socket.create_connection(("127.0.0.1",self.server.server_address[1]),timeout=2) as s:
                # This client would create a *new* connection for each call;
                # use one persistent transport session for FID lifecycle.
                raise AssertionError("persistent connection required")
        with socket.create_connection(("127.0.0.1",self.server.server_address[1]),timeout=2) as s:
            def exchange(raw):
                s.sendall(raw)
                header=b""
                while len(header)<4:
                    header+=s.recv(4-len(header))
                size=struct.unpack("<I",header)[0]
                body=b""
                while len(body)<size-4:
                    body+=s.recv(size-4-len(body))
                return header+body
            client=ReadOnly9PClient(exchange)
            self.assertEqual(client.read_file("probe"),b"Ryzova QEMU native 9P data\n")
    def test_bad_version_is_refused(self):
        p=Native9PConnection({"probe":b"x"})
        k,_,_=unframe(p.process(frame(TVERSION,1,struct.pack("<I",8192)+string("9P2000.u"))))
        self.assertEqual(k,RERROR)
    def test_root_open_directory_and_read_stat_list(self):
        p=Native9PConnection({"probe":b"xyz"})
        p.process(frame(TVERSION,1,struct.pack("<I",8192)+string("9P2000")))
        p.process(frame(TATTACH,2,struct.pack("<II",5,0xffffffff)+string("glenda")+string("")))
        kind,_,_=unframe(p.process(frame(TOPEN,3,struct.pack("<IB",5,0))))
        self.assertEqual(kind,ROPEN)
        kind,_,cur=unframe(p.process(frame(TREAD,4,struct.pack("<IQI",5,0,4096))))
        self.assertEqual(kind,RREAD)
        stat=cur.take(cur.unpack("<I"))
        self.assertIn(b"probe",stat)
    def test_write_and_traversal_denied(self):
        p=Native9PConnection({"probe":b"x"})
        p.process(frame(TVERSION,1,struct.pack("<I",8192)+string("9P2000")))
        p.process(frame(TATTACH,2,struct.pack("<II",1,0xffffffff)+string("glenda")+string("")))
        kind,_,_=unframe(p.process(frame(TWALK,3,struct.pack("<IIH",1,2,1)+string(".."))))
        self.assertEqual(kind,RERROR)
        kind,_,_=unframe(p.process(frame(TWRITE,4,struct.pack("<IQI",1,0,1)+b"x")))
        self.assertEqual(kind,RERROR)


class Native9PStateTests(unittest.TestCase):
    def connection(self, max_fids=256):
        conn = Native9PConnection({"probe": b"public"}, max_fids=max_fids)
        self.send(conn, TVERSION, struct.pack("<I", 8192) + string("9P2000"))
        self.send(conn, TATTACH, struct.pack("<II", 1, 0xffffffff)
                  + string("glenda") + string(""))
        return conn

    def send(self, conn, kind, body):
        return unframe(conn.process(frame(kind, 1, body)))[0]

    def test_rejected_requests_never_commit_connection_state(self):
        operations = (
            (TVERSION, struct.pack("<I", 512) + string("9P2000")),
            (TATTACH, struct.pack("<II", 3, 0xffffffff) + string("u") + string("")),
            (TWALK, struct.pack("<IIH", 1, 3, 1) + string("probe")),
            (TWALK, struct.pack("<IIH", 1, 3, 0)),
            (TWALK, struct.pack("<IIH", 1, 1, 1) + string("probe")),
            (TOPEN, struct.pack("<IB", 1, 0)),
            (TCLUNK, struct.pack("<I", 1)),
        )
        for kind, body in operations:
            for malformed in [body + b"X"] + [body[:n] for n in range(len(body))]:
                with self.subTest(kind=kind, size=len(malformed)):
                    conn = self.connection()
                    before = (conn.fids.copy(), conn.negotiated, conn.msize)
                    self.assertEqual(self.send(conn, kind, malformed), RERROR)
                    self.assertEqual((conn.fids, conn.negotiated, conn.msize), before)

    def test_rejected_attach_cannot_be_opened(self):
        conn = self.connection()
        body = struct.pack("<II", 42, 0xffffffff) + string("u") + string("")
        self.assertEqual(self.send(conn, TATTACH, body + b"X"), RERROR)
        self.assertEqual(self.send(conn, TOPEN, struct.pack("<IB", 42, 0)), RERROR)
        self.assertEqual(self.send(conn, TATTACH, body), RATTACH)
        self.assertEqual(self.send(conn, TOPEN, struct.pack("<IB", 42, 0)), ROPEN)

    def test_fid_budget_reclaimed_by_clunk_and_version(self):
        conn = self.connection(max_fids=2)
        clone = lambda old, new: struct.pack("<IIH", old, new, 0)
        self.assertEqual(self.send(conn, TWALK, clone(1, 2)), RWALK)
        self.assertEqual(self.send(conn, TWALK, clone(1, 3)), RERROR)
        attach = struct.pack("<II", 3, 0xffffffff) + string("u") + string("")
        self.assertEqual(self.send(conn, TATTACH, attach), RERROR)
        self.assertEqual(len(conn.fids), 2)
        self.assertEqual(self.send(conn, TWALK, clone(1, 1)), RWALK)
        self.assertEqual(self.send(conn, TCLUNK, struct.pack("<I", 2)), RCLUNK)
        self.assertEqual(self.send(conn, TWALK, clone(1, 3)), RWALK)
        self.assertEqual(self.send(conn, TVERSION,
                         struct.pack("<I", 8192) + string("9P2000")), RVERSION)
        self.assertEqual(conn.fids, {})

    def test_invalid_fid_limits_rejected(self):
        for limit in (0, -1, 4097, True, 1.5, None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                Native9PConnection({"probe": b"x"}, max_fids=limit)


if __name__ == "__main__":
    unittest.main()

