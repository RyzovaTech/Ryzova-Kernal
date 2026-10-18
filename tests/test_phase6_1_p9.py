# SPDX-License-Identifier: AGPL-3.0-only
import struct
import unittest
from ryzova.remote.trust import Endpoint, PeerPolicy, LocalAuthenticatedTransport, RemoteDenied
from ryzova.remote.p9 import (ReadOnly9PServer, ReadOnly9PClient, NinePError,
    frame, unframe, TOPEN, TATTACH, TVERSION, TREAD, RERROR, MAX_FRAME)

def connected(files=None,enabled=True):
    names=frozenset({"9p"})
    a=Endpoint("client",b"S"*32,PeerPolicy(enabled,frozenset({"server"}),names))
    b=Endpoint("server",b"S"*32,PeerPolicy(enabled,frozenset({"client"}),names))
    server=ReadOnly9PServer(files or {"readme":b"1234567890"})
    transport=LocalAuthenticatedTransport(a,b,{"9p":server.process})
    return ReadOnly9PClient(lambda raw:transport.request("9p",raw)),server,transport
class P9Tests(unittest.TestCase):
    def test_version_attach_walk_open_read_clunk(self):
        client,server,_=connected()
        self.assertEqual(client.read_file("readme"),b"1234567890")
        self.assertEqual(server.fids,{})
    def test_multiframe_and_end_of_file(self):
        blob=b"abcdef"*1600
        cli,server,_=connected({"block":blob})
        self.assertEqual(cli.read_file("block"),blob)
    def test_empty_file(self):
        cli,_,_=connected({"empty":b""})
        self.assertEqual(cli.read_file("empty"),b"")
    def test_limited_read_does_not_exceed_quota(self):
        cli,_,_=connected({"block":b"x"*12000})
        self.assertEqual(len(cli.read_file("block",max_total=4096)),4096)
    def test_missing_file_fails_closed(self):
        cli,server,_=connected()
        with self.assertRaises(NinePError):cli.read_file("missing")
        self.assertEqual(server.fids,{})
    def test_no_traversal_or_absolute_paths(self):
        cli,_,_=connected()
        for name in ("../readme","/etc/passwd","", ".", "..", "a/b"):
            with self.subTest(name=name),self.assertRaises(NinePError):
                cli.read_file(name)
    def test_server_refuses_write_open(self):
        srv=ReadOnly9PServer({"a":b"ok"})
        srv.process(frame(TVERSION,1,struct.pack("<I",MAX_FRAME)+b"\x06\x009P2000"))
        response=srv.process(frame(TATTACH,2,struct.pack("<II",1,0xffffffff)+b"\x00\x00\x00\x00"))
        result=srv.process(frame(TOPEN,3,struct.pack("<IB",1,1)))
        kind,_,_=unframe(result)
        self.assertEqual(kind,RERROR)
    def test_bad_frame_fails(self):
        srv=ReadOnly9PServer({"a":b"ok"})
        with self.assertRaises(NinePError):srv.process(b"invalid")
    def test_unsigned_transport_stays_off(self):
        cli,_,_=connected(enabled=False)
        with self.assertRaises(RemoteDenied):cli.read_file("readme")
    def test_no_implicit_local_file_access(self):
        with self.assertRaises(ValueError):ReadOnly9PServer({"../etc":b"bad"})
        cli,_,_=connected()
        with self.assertRaises(NinePError):cli.read_file("passwd")
if __name__=="__main__":unittest.main()
