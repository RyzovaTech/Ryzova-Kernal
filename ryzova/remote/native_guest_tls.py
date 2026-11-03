# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded TLS1.2 guest-facing 9P ingress for disposable QEMU research only.

The native Ryzova tlsclient checks a pinned SHA256 server leaf certificate.
TLS terminates here on CI Linux loopback, not at the remote peer. The next
gateway -> peer hop uses separate mutually authenticated TLS1.3. No production
identity, arbitrary filesystem access, or TLS downgrade path is provided.
"""
import socket
import socketserver
import ssl
import struct
import threading
import hashlib
import hmac
import re

from ryzova.remote.native_bridge import ALLOWED_9P, BridgeDenied, read_frame
from ryzova.remote.p9 import RERROR, frame, unframe

DEFAULT_MAX_SESSIONS = 8
DEFAULT_MAX_FRAMES = 256


class _NativeTLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        self.request.settimeout(6)
        try:
            with srv.context.wrap_socket(self.request, server_side=True) as tls:
                tls.settimeout(6)
                if tls.version() != "TLSv1.2":
                    raise BridgeDenied("native 9front TLS version mismatch")
                if srv.guest_client_pin is not None:
                    # Bind identity to the live TLS client certificate, never
                    # to 9P uname, a request boolean or a forwarded header.
                    der = tls.getpeercert(binary_form=True)
                    if (tls.context.verify_mode != ssl.CERT_REQUIRED or not der
                            or not hmac.compare_digest(hashlib.sha256(der).hexdigest(),
                                                       srv.guest_client_pin)):
                        raise BridgeDenied("guest certificate mismatch")
                    with srv.metrics_lock:
                        srv.authenticated_guest_sessions += 1
                with srv.metrics_lock:
                    srv.tls12_sessions += 1
                # One upstream socket per admitted guest session. Never replay
                # a 9P request after an EOF/timeout; a fresh mount must retry.
                with socket.create_connection(
                    ("127.0.0.1", srv.gateway_port), timeout=6
                ) as upstream:
                    upstream.settimeout(6)
                    for _ in range(srv.max_frames_per_session):
                        packet = read_frame(tls)
                        kind, tag, _ = unframe(packet)
                        if kind not in ALLOWED_9P:
                            # Commit the denial metric before writing
                            # RERROR to avoid racing client assertions.
                            with srv.metrics_lock:
                                srv.denied_writes += 1
                            tls.sendall(frame(RERROR, tag, b"\x0b\x00read denied"))
                            continue
                        upstream.sendall(packet)
                        response = read_frame(upstream)
                        _, reply_tag, _ = unframe(response)
                        if reply_tag != tag:
                            raise BridgeDenied("upstream response tag mismatch")
                        tls.sendall(response)
                        with srv.metrics_lock:
                            srv.forwarded_frames += 1
                    with srv.metrics_lock:
                        srv.frame_quota_closes += 1
        except (OSError, ssl.SSLError, ValueError, BridgeDenied, EOFError,
                struct.error):
            # Authentication errors, partial frames, EOFs and peer failures
            # close this session. No transparent downgrade or request replay.
            pass


class NativeGuestTLS12Endpoint(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, certificate, key, gateway_port, port=15641,
                 max_sessions=DEFAULT_MAX_SESSIONS,
                 max_frames_per_session=DEFAULT_MAX_FRAMES, *,
                 guest_ca=None, guest_client_pin=None, guest_identity=None):
        if type(gateway_port) is not int or not 0 < gateway_port < 65536:
            raise ValueError("upstream gateway port required")
        if type(max_sessions) is not int or not 1 <= max_sessions <= 32:
            raise ValueError("bounded TLS guest session limit required")
        if (type(max_frames_per_session) is not int or
                not 1 <= max_frames_per_session <= 4096):
            raise ValueError("bounded 9P session frame quota required")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=certificate, keyfile=key)
        if any(v is not None for v in (guest_ca, guest_client_pin, guest_identity)):
            if (not isinstance(guest_ca, str) or not guest_ca
                    or type(guest_client_pin) is not str
                    or re.fullmatch(r"[a-f0-9]{64}", guest_client_pin) is None
                    or type(guest_identity) is not str
                    or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", guest_identity) is None):
                raise ValueError("complete pinned guest mTLS identity required")
            ctx.load_verify_locations(cafile=guest_ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        self.guest_client_pin = guest_client_pin
        self.guest_identity = guest_identity
        self.authenticated_guest_sessions = 0
        self.context = ctx
        self.gateway_port = gateway_port
        self.max_sessions = max_sessions
        self.max_frames_per_session = max_frames_per_session
        self.metrics_lock = threading.Lock()
        self.tls12_sessions = 0
        self.forwarded_frames = 0
        self.denied_writes = 0
        self.active_sessions = 0
        self.peak_sessions = 0
        self.rejected_connections = 0
        self.frame_quota_closes = 0
        # QEMU slirp 10.0.2.2 reaches host localhost, not public interfaces.
        super().__init__(("127.0.0.1", port), _NativeTLSHandler)

    def verify_request(self, request, client_address):
        # Reject before creating a handler thread; accepting then limiting
        # inside handle() would leave an unbounded thread-exhaustion vector.
        with self.metrics_lock:
            if self.active_sessions >= self.max_sessions:
                self.rejected_connections += 1
                return False
            self.active_sessions += 1
            self.peak_sessions = max(self.peak_sessions, self.active_sessions)
            return True

    def process_request(self, request, client_address):
        try:
            super().process_request(request, client_address)
        except BaseException:
            # Recover a slot if Python cannot create the handler thread.
            with self.metrics_lock:
                self.active_sessions -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.metrics_lock:
                self.active_sessions -= 1
