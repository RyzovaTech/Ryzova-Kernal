# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import unittest
from ryzova.remote.cache import RemotePageCache, CacheUnavailable, IntegrityFailure
from ryzova.remote.trust import Endpoint, PeerPolicy, LocalAuthenticatedTransport
from ryzova.remote.p9 import ReadOnly9PServer, ReadOnly9PClient

def digest(blob):
    return hashlib.sha256(blob).hexdigest()

def source(files, *, enabled=True):
    allow=frozenset({"9p"})
    c=Endpoint("client",b"K"*32,PeerPolicy(enabled,frozenset({"server"}),allow))
    s=Endpoint("server",b"K"*32,PeerPolicy(enabled,frozenset({"client"}),allow))
    wire=LocalAuthenticatedTransport(c,s,{"9p":ReadOnly9PServer(files).process})
    return ReadOnly9PClient(lambda raw: wire.request("9p", raw))

class CacheTests(unittest.TestCase):
    def test_full_phase6_1_through_phase6_2_pipeline(self):
        body=b"A"*4096
        client=source({"page0":body})
        cache=RemotePageCache(2)
        got=cache.get("page0",digest(body),client.read_file)
        self.assertEqual(got,body)
        self.assertEqual(cache.resident_bytes,4096)
        self.assertEqual(cache.get("page0",digest(body),lambda _: self.fail("unexpected remote fetch")),body)
        self.assertEqual((cache.hits,cache.misses),(1,1))
    def test_fail_closed_corrupt_remote_page(self):
        b=b"B"*4096
        cli=source({"page":b"C"*4096})
        with self.assertRaises(IntegrityFailure):
            RemotePageCache().get("page",digest(b),cli.read_file)
    def test_offline_does_not_fake_a_cache_miss(self):
        c=RemotePageCache()
        with self.assertRaises(CacheUnavailable):
            c.get("page",digest(b"D"*4096),lambda _: (_ for _ in ()).throw(TimeoutError("offline")))
        self.assertEqual(c.resident_bytes,0)
    def test_disabled_remote_access(self):
        cli=source({"page":b"A"*4096},enabled=False)
        with self.assertRaises(CacheUnavailable):
            RemotePageCache().get("page",digest(b"A"*4096),cli.read_file)
    def test_lru_bounded_and_eviction(self):
        c=RemotePageCache(capacity_pages=2)
        for i in range(3):
            b=bytes([i])*4096
            self.assertEqual(c.get(f"p{i}",digest(b),lambda _:b),b)
        self.assertEqual(c.resident_bytes,8192)
        self.assertEqual(c.evictions,1)
    def test_no_critical_or_secret_kernel_pages(self):
        c=RemotePageCache()
        for p in ("secret","kernel","credentials"):
            with self.subTest(p=p), self.assertRaises(ValueError):
                c.get("page",digest(b"x"*4096),lambda _: b"x"*4096,purpose=p)
    def test_reject_malformed_ids_hashes_and_lengths(self):
        c=RemotePageCache()
        for name in ("../passwd","x/y","A","", "x"*65):
            with self.subTest(name=name), self.assertRaises(ValueError):
                c.get(name,digest(b"x"*4096),lambda _:b"x"*4096)
        with self.assertRaises(ValueError):
            c.get("ok","0"*63,lambda _:b"x"*4096)
        with self.assertRaises(IntegrityFailure):
            c.get("ok",digest(b"x"*4096),lambda _:b"x"*20)
    def test_invalidate_and_clear(self):
        c=RemotePageCache()
        b=b"x"*4096
        c.get("ok",digest(b),lambda _:b)
        c.invalidate("ok")
        self.assertEqual(c.resident_bytes,0)
        c.get("ok",digest(b),lambda _:b)
        c.clear()
        self.assertEqual(c.resident_bytes,0)
if __name__=="__main__":unittest.main()
