# SPDX-License-Identifier: AGPL-3.0-only
import unittest
from ryzova.compact.contract_v1 import negotiate, ContractError

class CompactContractTests(unittest.TestCase):
    def request(self, **changes):
        obj = {"environment": "compact/linux", "api_major": 1, "api_minor": 0, "capabilities": ["namespace.read"]}
        obj.update(changes)
        return obj

    def test_negotiation(self):
        result = negotiate(self.request())
        self.assertEqual(result["abi"], "none")
        self.assertEqual(result["status"], "contract-only")

    def test_environment_names(self):
        for name in ("compact/linux", "compact/windows", "compact/mac"):
            self.assertEqual(negotiate(self.request(environment=name))["environment"], name)

    def test_reject_incompatible_or_unsafe(self):
        for bad in ({"api_major": 2}, {"api_major": True}, {"api_minor": 1},
                    {"environment": "../linux"}, {"environment": "compact/LINUX"},
                    {"capabilities": ["native.exec"]}, {"capabilities": ["ipc.9p", "ipc.9p"]},
                    {"capabilities": "ipc.9p"}):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                negotiate(self.request(**bad))

    def test_reject_extra_fields(self):
        with self.assertRaises(ContractError):
            negotiate(self.request(privileged=True))

if __name__ == "__main__":
    unittest.main()
