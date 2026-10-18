# SPDX-License-Identifier: AGPL-3.0-only
"""Native Ryzova tlsclient-compatible TLS1.2 test endpoint, loopback only.

TLS terminates here on the Linux CI host; native guest tlsclient authenticates
the presented server certificate SHA256 thumbprint. This endpoint forwards only
read-only 9P2000 to the separately mutually-TLS1.3-authenticated gateway/peer.
No production credentials or general network listening are supported.
"""
import socket
import socketserver
import ssl
import struct
import threading

from ryzova.remote.native_bridge import read_frame, ALLOWED_9P, BridgeDenied
from ryzova.remote.p9 import unframe, frame, RERROR


class _NativeTLSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        srv=self.server
        self.request.settimeout(6)
        try:
            with srv.context.wrap_socket(self.request,server_side=True) as tls:
                tls.settimeout(6)
                if tls.version() != "TLSv1.2":
                    raise BridgeDenied("native 9front TLS version mismatch")
                with srv.metrics_lock:
                    srv.tls12_sessions += 1
                with socket.create_connection(("127.0.0.1",srv.gateway_port),timeout=6) as upstream:
                    upstream.settimeout(6)
                    while True:
                        packet=read_frame(tls)
                        kind,tag,_=unframe(packet)
                        if kind not in ALLOWED_9P:
                            tls.sendall(frame(RERROR,tag,b"\x0b\x00read denied"))
                            with srv.metrics_lock:
                                srv.denied_writes += 1
                            continue
                        upstream.sendall(packet)
                        response=read_frame(upstream)
                        _,reply_tag,_=unframe(response)
                        if reply_tag != tag:
                            raise BridgeDenied("upstream response tag mismatch")
                        tls.sendall(response)
                        with srv.metrics_lock:
                            srv.forwarded_frames += 1
        except (OSError, ssl.SSLError, ValueError, BridgeDenied, EOFError,struct.error):
            # TLS handshake errors, disconnects and downgrades fail closed.
            pass


class NativeGuestTLS12Endpoint(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

    def __init__(self, certificate, key, gateway_port, port=15641):
        if not isinstance(gateway_port,int) or not 0<gateway_port<65536:
            raise ValueError("upstream gateway port required")
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.maximum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=certificate,keyfile=key)
        self.context=ctx
        self.gateway_port=gateway_port
        self.metrics_lock=threading.Lock()
        self.tls12_sessions=0
        self.forwarded_frames=0
        self.denied_writes=0
        # QEMU slirp 10.0.2.2 reaches host localhost, not public interfaces.
        super().__init__(("127.0.0.1",port),_NativeTLSHandler)
