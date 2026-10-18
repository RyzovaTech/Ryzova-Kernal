# SPDX-License-Identifier: AGPL-3.0-only
"""Phase 7: disposable native-QEMU 9P -> mTLS gateway -> 9P peer prototype.

The QEMU guest->gateway hop is still PLAINTEXT and UNAUTHENTICATED. Only
the gateway->peer TCP hop is mutually TLS 1.3 authenticated. Binds loopback
only and may be used only for public CI fixtures, never privileged mounts.
"""
import hashlib
import socket
import socketserver
import ssl
import struct
import threading

from ryzova.remote.native9p import Native9PConnection
from ryzova.remote.p9 import MAX_FRAME, RERROR, frame, unframe

ALLOWED_9P = frozenset((100, 104, 108, 110, 112, 116, 120, 124))
TIMEOUT = 5.0


class BridgeDenied(Exception):
    pass


def _read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise BridgeDenied("peer disconnected")
        data.extend(part)
    return bytes(data)


def read_frame(sock):
    header = _read_exact(sock, 4)
    size = struct.unpack("<I", header)[0]
    if not 7 <= size <= MAX_FRAME:
        raise BridgeDenied("bounded 9P frame required")
    return header + _read_exact(sock, size - 4)


def _fingerprint(der):
    if not isinstance(der, bytes) or not der:
        raise BridgeDenied("missing peer certificate")
    return hashlib.sha256(der).hexdigest()


def _tls13_version(sock):
    if sock.version() != "TLSv1.3":
        raise BridgeDenied("TLS1.3 required")


def _pin(expected):
    if not isinstance(expected, str) or len(expected) != 64:
        raise ValueError("pinned peer certificate SHA256 required")
    try:
        bytes.fromhex(expected)
    except ValueError as exc:
        raise ValueError("bad certificate pin") from exc
    return expected.lower()


class _PeerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        connection = Native9PConnection(server.files)
        self.request.settimeout(TIMEOUT)
        try:
            with server.context.wrap_socket(self.request, server_side=True) as tls:
                _tls13_version(tls)
                if _fingerprint(tls.getpeercert(binary_form=True)) != server.client_pin:
                    raise BridgeDenied("client certificate mismatch")
                with server.metrics_lock:
                    server.secure_sessions += 1
                while True:
                    request = read_frame(tls)
                    message, _, _ = unframe(request)
                    if message not in ALLOWED_9P:
                        raise BridgeDenied("unexpected write/privileged request")
                    response = connection.process(request)
                    tls.sendall(response)
                    with server.metrics_lock:
                        server.frames += 1
        except (BridgeDenied, TimeoutError, OSError, ssl.SSLError, ValueError,
                EOFError, struct.error):
            # EOF after a proper 9P exchange is normal; do not claim success
            # from exceptions. Frame/session counts are checked independently.
            pass


class SecureReadOnly9PPeer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, files, context, client_pin, port=0):
        if not isinstance(context, ssl.SSLContext):
            raise ValueError("TLS server context required")
        if not isinstance(files, dict) or set(files) != {"probe"} or not isinstance(files["probe"], bytes):
            raise ValueError("one public test fixture allowed")
        if not 0 < len(files["probe"]) <= 4096:
            raise ValueError("fixture size bound")
        self.files = files.copy()
        self.context = context
        self.client_pin = _pin(client_pin)
        self.metrics_lock = threading.Lock()
        self.frames = 0
        self.secure_sessions = 0
        super().__init__(("127.0.0.1", port), _PeerHandler)


class _GatewayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        self.request.settimeout(TIMEOUT)
        try:
            with socket.create_connection(("127.0.0.1", server.upstream_port),
                                          timeout=TIMEOUT) as raw:
                raw.settimeout(TIMEOUT)
                with server.context.wrap_socket(raw, server_hostname="localhost") as tls:
                    _tls13_version(tls)
                    if _fingerprint(tls.getpeercert(binary_form=True)) != server.server_pin:
                        raise BridgeDenied("server pin mismatch")
                    with server.metrics_lock:
                        server.verified_tls_sessions += 1
                    while True:
                        request = read_frame(self.request)
                        kind, tag, cursor = unframe(request)
                        if kind not in ALLOWED_9P:
                            self.request.sendall(frame(RERROR, tag,
                                b"\x0b\x00read denied"))
                            with server.metrics_lock:
                                server.denied_writes += 1
                            continue
                        tls.sendall(request)
                        response = read_frame(tls)
                        _, response_tag, _ = unframe(response)
                        if response_tag != tag:
                            raise BridgeDenied("9P transaction tag mismatch")
                        self.request.sendall(response)
                        with server.metrics_lock:
                            server.forwarded_frames += 1
        except (BridgeDenied, TimeoutError, OSError, ssl.SSLError, ValueError,
                EOFError, struct.error):
            # Fail closed: never fall back to an unauthenticated upstream.
            pass


class Local9PTLSGateway(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, context, server_pin, upstream_port, port=15640):
        if not isinstance(context, ssl.SSLContext) or not 0 < upstream_port < 65536:
            raise ValueError("invalid gateway configuration")
        self.context = context
        self.server_pin = _pin(server_pin)
        self.upstream_port = upstream_port
        self.metrics_lock = threading.Lock()
        self.forwarded_frames = 0
        self.verified_tls_sessions = 0
        self.denied_writes = 0
        super().__init__(("127.0.0.1", port), _GatewayHandler)
