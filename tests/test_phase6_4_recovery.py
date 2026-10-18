# SPDX-License-Identifier: AGPL-3.0-only
import unittest
from ryzova.remote.recovery import RemoteCircuit, ServiceUnavailable

class Transport:
    def __init__(self): self.calls=0;self.failing=False
    def request(self, op, data):
        self.calls+=1
        if self.failing: raise TimeoutError("SECRET_AUTH_TOKEN_123")
        return data[::-1]

class CircuitTests(unittest.TestCase):
    def test_default_disabled(self):
        tr=Transport();c=RemoteCircuit(tr)
        with self.assertRaises(ServiceUnavailable):c.request("9p",b"x")
        self.assertEqual(tr.calls,0)
    def test_healthy_success_metrics_do_not_store_bytes(self):
        tr=Transport();c=RemoteCircuit(tr,enabled=True)
        self.assertEqual(c.request("9p",b"MY_PASSWORD"),b"DROWSSAP_YM")
        self.assertEqual(c.telemetry()["counters"]["success"],1)
        self.assertNotIn("MY_PASSWORD",str(c.telemetry()))
    def test_trip_and_recover_after_cooldown(self):
        ticks=[100.]
        tr=Transport();tr.failing=True
        c=RemoteCircuit(tr,enabled=True,clock=lambda:ticks[0],cooldown_seconds=5.)
        for _ in range(2):
            with self.assertRaises(ServiceUnavailable):c.request("9p",b"x")
        self.assertTrue(c.telemetry()["open"])
        calls=tr.calls
        with self.assertRaises(ServiceUnavailable):c.request("9p",b"x")
        self.assertEqual(calls,tr.calls)
        ticks[0]=106.;tr.failing=False
        self.assertEqual(c.request("9p",b"abc"),b"cba")
        self.assertFalse(c.telemetry()["open"])
    def test_timeout_after_slow_blocking_call(self):
        ticks=[20.]
        class Slow:
            def request(self,op,payload):
                ticks[0]+=2.0
                return b"ok"
        c=RemoteCircuit(Slow(),enabled=True,clock=lambda:ticks[0],
                        deadline_seconds=.5,failure_threshold=1)
        with self.assertRaises(ServiceUnavailable):c.request("page",b"abc")
        self.assertTrue(c.telemetry()["open"])
    def test_unbounded_response_refused(self):
        class Huge:
            def request(self,op,payload):return b"A"*8193
        c=RemoteCircuit(Huge(),enabled=True)
        with self.assertRaises(ServiceUnavailable):c.request("compute",b"ok")
    def test_cannot_forward_unknown_or_large_operations(self):
        c=RemoteCircuit(Transport(),enabled=True)
        for op,data in (("shell",b"a"),("9p",b"z"*8193)):
            with self.subTest(op=op),self.assertRaises(ServiceUnavailable):
                c.request(op,data)
    def test_counters_are_bounded_and_no_exception_details(self):
        t=Transport();t.failing=True
        c=RemoteCircuit(t,enabled=True,event_capacity=3,failure_threshold=16)
        for _ in range(8):
            with self.assertRaises(ServiceUnavailable):c.request("9p",b"token")
        self.assertEqual(len(c.telemetry()["events"]),3)
        self.assertNotIn("SECRET_AUTH_TOKEN_123",str(c.telemetry()))
    def test_negative_config(self):
        with self.assertRaises(ValueError):RemoteCircuit(Transport(),failure_threshold=0)
        with self.assertRaises(ValueError):RemoteCircuit(Transport(),event_capacity=0)
if __name__=="__main__":unittest.main()
