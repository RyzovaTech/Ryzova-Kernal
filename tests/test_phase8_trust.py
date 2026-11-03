# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.0 host-only trust-policy security tests; NOT guest TLS certification."""
import hashlib
import unittest

from ryzova.remote.phase8_trust import PeerGrant, ResearchTrustPolicy, TrustDenied

# Deliberately opaque bytes: this module does not parse/validate X.509.
# A production caller must obtain DER from an already verified TLS session.
CERT = b"test-only-opaque-leaf"
PIN = hashlib.sha256(CERT).hexdigest()
NEW_CERT = b"rotated-test-only-leaf"
NEW_PIN = hashlib.sha256(NEW_CERT).hexdigest()


class Phase8TrustTests(unittest.TestCase):
    def setUp(self):
        self.grant = PeerGrant("peer01", PIN, 200)
        self.policy = ResearchTrustPolicy(peers=(self.grant,), enabled=True)
        self.args = dict(peer_id="peer01", cert_der=CERT, path="probe",
                         byte_count=128, now=100, tls_authenticated=True,
                         tls_version="TLSv1.2")

    def test_exact_authenticated_identity_and_file_read_scope(self):
        self.assertTrue(self.policy.authorize_read(**self.args))
        self.assertTrue(self.policy.authorize_read(
            **dict(self.args, tls_version="TLSv1.3", byte_count=4096)))
        self.assertEqual(self.policy.generation, 1)

    def test_default_denies_without_opt_in(self):
        with self.assertRaises(TrustDenied):
            ResearchTrustPolicy(peers=(self.grant,)).authorize_read(**self.args)
        with self.assertRaises(TrustDenied):
            ResearchTrustPolicy().authorize_read(**self.args)

    def test_unknown_or_mismatched_certificate_denied(self):
        for cert in (b"wrong", b"", b"x" * 16385, bytearray(CERT), None):
            with self.subTest(cert_type=type(cert).__name__), self.assertRaises(TrustDenied):
                self.policy.authorize_read(**dict(self.args, cert_der=cert))

    def test_tls_assertion_and_version_are_mandatory(self):
        for version, authenticated in (("TLSv1.1", True), ("plaintext", True),
                                       ("TLSv1.2", False), ("TLSv1.3", 1),
                                       (None, True)):
            with self.subTest(version=version, authenticated=authenticated):
                with self.assertRaises(TrustDenied):
                    self.policy.authorize_read(**dict(
                        self.args, tls_version=version, tls_authenticated=authenticated))

    def test_expiry_path_identity_count_and_time_fail_closed(self):
        for patch in (dict(now=200), dict(now=201), dict(now=-1), dict(now=False),
                      dict(peer_id="other"), dict(path="../probe"),
                      dict(path="secrets"), dict(path="/probe"),
                      dict(byte_count=0), dict(byte_count=4097),
                      dict(byte_count=True), dict(byte_count=1.0)):
            with self.subTest(patch=patch), self.assertRaises(TrustDenied):
                self.policy.authorize_read(**dict(self.args, **patch))

    def test_revocation_increments_generation_without_mutating_old_snapshot(self):
        revoked = self.policy.revoke_peer("peer01", new_generation=2)
        with self.assertRaises(TrustDenied):
            revoked.authorize_read(**self.args)
        self.assertTrue(self.policy.authorize_read(**self.args))
        with self.assertRaises(ValueError):
            revoked.revoke_peer("peer01", new_generation=3)
        with self.assertRaises(ValueError):
            self.policy.revoke_peer("peer01", new_generation=1)
        with self.assertRaises(ValueError):
            self.policy.revoke_peer("unknown", new_generation=2)

    def test_rotation_revokes_previous_pin_and_rejects_rollback(self):
        updated = self.policy.rotate_pin("peer01", NEW_PIN, new_generation=2)
        with self.assertRaises(TrustDenied):
            updated.authorize_read(**self.args)
        self.assertTrue(updated.authorize_read(**dict(self.args, cert_der=NEW_CERT)))
        with self.assertRaises(ValueError):
            updated.rotate_pin("peer01", PIN, new_generation=3)
        with self.assertRaises(ValueError):
            self.policy.rotate_pin("peer01", NEW_PIN, new_generation=1)
        with self.assertRaises(ValueError):
            self.policy.rotate_pin("peer01", PIN, new_generation=2)

    def test_reject_malformed_grant_fields(self):
        base = dict(peer_id="peer01", cert_sha256=PIN, expires_at=200, files=("probe",))
        for patch in (dict(peer_id="../foo"), dict(peer_id="a/other"),
                      dict(cert_sha256="a" * 63), dict(cert_sha256=PIN.upper()),
                      dict(expires_at=-1), dict(expires_at=True),
                      dict(files=("../private",)), dict(files=("probe", "probe")),
                      dict(files=["probe"]), dict(files=([],)), dict(files=("..",)),
                      dict(files=tuple("p" + str(i) for i in range(17)))):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                PeerGrant(**(base | patch))

    def test_duplicate_identity_and_fingerprint_are_rejected(self):
        with self.assertRaises(ValueError):
            ResearchTrustPolicy(peers=(self.grant, self.grant), enabled=True)
        with self.assertRaises(ValueError):
            ResearchTrustPolicy(peers=(self.grant, PeerGrant("peer02", PIN, 200)),
                                enabled=True)

    def test_preexisting_revoked_pin_cannot_authorize(self):
        p = ResearchTrustPolicy(peers=(self.grant,), revoked_sha256=frozenset({PIN}),
                                enabled=True)
        with self.assertRaises(TrustDenied):
            p.authorize_read(**self.args)
        with self.assertRaises(ValueError):
            p.rotate_pin("unknown", NEW_PIN, new_generation=2)

    def test_invalid_policy_state_rejected(self):
        for kw in (dict(enabled=1), dict(generation=0), dict(generation=True),
                   dict(peers=[self.grant]), dict(peers=tuple(self.grant for _ in range(17))),
                   dict(revoked_sha256={PIN}),
                   dict(revoked_sha256=frozenset({"a" * 63}))):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                ResearchTrustPolicy(**kw)


if __name__ == "__main__":
    unittest.main()
