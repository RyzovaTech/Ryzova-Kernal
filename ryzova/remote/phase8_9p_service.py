# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 8.1: opt-in TLS-bound 9P peer authorization for isolated host tests.

This guard is called ONLY inside a TLS1.3 peer's established, mutually
authenticated SSLSocket handler. It authenticates the gateway TLS client,
NOT the Ryzova guest. There is no client identity propagation across the
TLS1.2 guest -> ingress -> gateway chain.
"""
import ssl
import struct
import time

from ryzova.remote.p9 import NinePError, TREAD, unframe
from ryzova.remote.phase8_trust import ResearchTrustPolicy, TrustDenied


def authorize_peer_request(policy, tls, configured_peer_id, packet=None,
                           connection=None, now=None):
    """Enforce an immutable host policy against TLS-derived leaf bytes.

    An optional packet checks per-session FIDs for TREAD; the actual 9P
    handler owns/updates FIDs. On policy failure the caller must close the
    connection, never replay or transparently downgrade the request.
    """
    if type(policy) is not ResearchTrustPolicy or not isinstance(tls, ssl.SSLSocket):
        raise TrustDenied("remote read denied")
    if (tls.context.verify_mode != ssl.CERT_REQUIRED or
            tls.version() != "TLSv1.3"):
        raise TrustDenied("remote read denied")
    try:
        der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise TrustDenied("remote read denied") from exc
    if type(der) is not bytes or not der:
        raise TrustDenied("remote read denied")

    file_name, count = "probe", 1
    if packet is not None:
        if type(packet) is not bytes or connection is None:
            raise TrustDenied("remote read denied")
        try:
            kind, _, cursor = unframe(packet)
            if kind == TREAD:
                fid = cursor.unpack("<I")
                cursor.unpack("<Q")
                count = cursor.unpack("<I")
                cursor.done()
                state = connection.fids.get(fid)
                if state is None or state[1] is not True:
                    raise TrustDenied("remote read denied")
                file_name = state[0]
                if file_name == "/":
                    raise TrustDenied("remote read denied")
        except (AttributeError, KeyError, TypeError, ValueError,
                NinePError, struct.error):
            raise TrustDenied("remote read denied") from None
    policy.authorize_read(
        peer_id=configured_peer_id, cert_der=der, path=file_name,
        byte_count=count, now=int(time.time()) if now is None else now,
        tls_authenticated=True, tls_version=tls.version(),
    )
    return True
