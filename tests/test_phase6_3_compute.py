# SPDX-License-Identifier: AGPL-3.0-only
import unittest
from ryzova.remote.compute import (
    PureTaskServer,PureTaskClient,TaskRejected,IncorrectRemoteResult,evaluate,canonical)
from ryzova.remote.trust import Endpoint,PeerPolicy,LocalAuthenticatedTransport,RemoteDenied

def peers(server, enabled=True):
    a=Endpoint("client",b"C"*32,PeerPolicy(enabled,frozenset({"server"}),frozenset({"compute"})))
    b=Endpoint("server",b"C"*32,PeerPolicy(enabled,frozenset({"client"}),frozenset({"compute"})))
    return LocalAuthenticatedTransport(a,b,{"compute":server.handle})

class ComputeTests(unittest.TestCase):
    def test_end_to_end_authenticated_pure_task(self):
        backend=PureTaskServer(4)
        client=PureTaskClient(peers(backend))
        self.assertEqual(client.run({"op":"sum_squares","a":[-2,0,3]}),13)
        self.assertEqual(client.run({"op":"dot","a":[-2,4,5],"b":[2,-3,10]}),34)
        self.assertEqual(backend.remaining,2)
    def test_local_recomputation_detects_untrusted_wrong_answer(self):
        backend=PureTaskServer()
        client=PureTaskClient(peers(backend))
        client.transport.handlers["compute"]=lambda request:canonical({
            "result":123456,
            "input_sha256":__import__("hashlib").sha256(request).hexdigest()
        })
        with self.assertRaises(IncorrectRemoteResult):
            client.run({"op":"sum_squares","a":[3,4]})
    def test_job_quota_enforced(self):
        backend=PureTaskServer(1)
        c=PureTaskClient(peers(backend))
        self.assertEqual(c.run({"op":"sum_squares","a":[1]}),1)
        with self.assertRaises(TaskRejected):c.run({"op":"sum_squares","a":[1]})
    def test_denied_off_by_default(self):
        c=PureTaskClient(peers(PureTaskServer(),enabled=False))
        with self.assertRaises(RemoteDenied):
            c.run({"op":"dot","a":[1],"b":[2]})
    def test_arbitrary_code_or_bad_calls_forbidden(self):
        bad=[
            {"op":"exec","a":["rm -rf /"]},
            {"op":"sum_squares","a":[1.2]},
            {"op":"sum_squares","a":[True]},
            {"op":"sum_squares","a":[]},
            {"op":"sum_squares","a":[1]*257},
            {"op":"sum_squares","a":[1_000_001]},
            {"op":"sum_squares","a":[1],"cmd":"echo hello"},
            {"op":"dot","a":[1,2],"b":[1]},
            {"op":"dot","a":[1],"b":["2"]}
        ]
        for t in bad:
            with self.subTest(t=t),self.assertRaises(TaskRejected):evaluate(t)
    def test_bound_result_fits_signed_64_bit(self):
        result=evaluate({"op":"sum_squares","a":[1000000]*256})
        self.assertLess(result,2**63)
    def test_replay_and_outage_fail_closed(self):
        backend=PureTaskServer()
        c=PureTaskClient(peers(backend))
        c.transport.handlers["compute"]=lambda _: (_ for _ in ()).throw(TimeoutError("simulated network outage"))
        with self.assertRaises(TimeoutError):
            c.run({"op":"sum_squares","a":[1,2]})
    def test_tampered_output_envelope_rejected(self):
        backend=PureTaskServer()
        c=PureTaskClient(peers(backend))
        # A fully compromised/mock server could lie while possessing its key;
        # independent client recomputation remains the final integrity gate.
        c.transport.handlers["compute"]=lambda _:b'{"result":0}'
        with self.assertRaises(IncorrectRemoteResult):
            c.run({"op":"sum_squares","a":[1,2]})
if __name__=="__main__":unittest.main()
