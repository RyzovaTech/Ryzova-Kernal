# SPDX-License-Identifier: AGPL-3.0-only
import json
import unittest
from ryzova.remote.trust import Endpoint, PeerPolicy, RemoteDenied, LocalAuthenticatedTransport

KEY=b"T"*32
def pair(enabled=True,now=lambda:1000):
    a=Endpoint("client",KEY,PeerPolicy(enabled,frozenset({"server"}),
                  frozenset({"9p","page","compute"})),now)
    b=Endpoint("server",KEY,PeerPolicy(enabled,frozenset({"client"}),
                  frozenset({"9p","page","compute"})),now)
    return a,b
class TrustTests(unittest.TestCase):
    def test_denied_by_default(self):
        a,b=pair(False)
        with self.assertRaises(RemoteDenied):a.sign("server","request","9p",b"x")
    def test_end_to_end_authenticated_roundtrip(self):
        a,b=pair()
        tr=LocalAuthenticatedTransport(a,b,{"9p":lambda x:x.upper()})
        self.assertEqual(tr.request("9p",b"hello"),b"HELLO")
        self.assertEqual(tr.request("9p",b"hi"),b"HI")
    def test_replay_rejected(self):
        a,b=pair()
        packet=a.sign("server","request","page",b"data")
        self.assertEqual(b.verify(packet,"request","page"),b"data")
        with self.assertRaises(RemoteDenied):b.verify(packet,"request","page")
    def test_tamper_rejected(self):
        a,b=pair()
        packet=json.loads(a.sign("server","request","page",b"data"))
        packet["message"]["body"]="eA=="
        with self.assertRaises(RemoteDenied):b.verify(json.dumps(packet).encode(),"request","page")
    def test_wrong_direction_and_operation_rejected(self):
        a,b=pair()
        packet=a.sign("server","request","9p",b"x")
        with self.assertRaises(RemoteDenied):b.verify(packet,"response","9p")
        with self.assertRaises(RemoteDenied):b.verify(packet,"request","page")
    def test_expiration_and_unknown_peer_rejected(self):
        a,b=pair(now=lambda:1000)
        packet=a.sign("server","request","9p",b"x")
        b._clock=lambda:1050
        with self.assertRaises(RemoteDenied):b.verify(packet,"request","9p")
        with self.assertRaises(RemoteDenied):a.sign("other","request","9p",b"x")
    def test_oversized_and_corrupt_rejected(self):
        a,b=pair()
        with self.assertRaises(RemoteDenied):a.sign("server","request","9p",b"a"*8193)
        with self.assertRaises(RemoteDenied):b.verify(b"not JSON","request","9p")
        with self.assertRaises(RemoteDenied):b.verify(b"X"*18000,"request","9p")
    def test_policy_rejects_arbitrary_operation(self):
        a,_=pair()
        with self.assertRaises(RemoteDenied):a.sign("server","request","exec","x".encode())
    def test_authenticated_invalid_base64_is_rejected_not_crashed(self):
        import base64, hashlib, hmac
        from ryzova.remote.trust import _canonical
        a,b=pair()
        wrapper=json.loads(a.sign("server","request","9p",b"hello"))
        wrapper["message"]["body"]="%%%not base64%%%"
        wrapper["hmac"]=hmac.new(KEY,_canonical(wrapper["message"]),hashlib.sha256).hexdigest()
        with self.assertRaises(RemoteDenied):
            b.verify(json.dumps(wrapper).encode(),"request","9p")
    def test_empty_or_invalid_authentication_envelope(self):
        _,b=pair()
        for malformed in (b'{}',b'[]',b'null',b'{"message":1}',b'{"message":{}}'):
            with self.subTest(malformed=malformed),self.assertRaises(RemoteDenied):
                b.verify(malformed,"request","9p")
    def test_reflection_is_rejected(self):
        a,b=pair()
        packet=a.sign("server","request","9p",b"x")
        with self.assertRaises(RemoteDenied):a.verify(packet,"request","9p")
if __name__=="__main__":unittest.main()
