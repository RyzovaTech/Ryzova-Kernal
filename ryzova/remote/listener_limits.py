# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded admission for loopback research listeners, before thread creation."""
import socketserver
import threading


def bounded_limit(value, maximum, label):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"{label} must be 1..{maximum}")
    return value


class BoundedTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, *, max_sessions=8,
                 max_frames_per_session=256):
        self.max_sessions = bounded_limit(max_sessions, 32, "session limit")
        self.max_frames_per_session = bounded_limit(
            max_frames_per_session, 4096, "frame limit")
        self.metrics_lock = threading.Lock()
        self.active_sessions = 0
        self.peak_sessions = 0
        self.rejected_connections = 0
        self.frame_quota_closes = 0
        super().__init__(address, handler)

    def verify_request(self, request, client_address):
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
            with self.metrics_lock:
                self.active_sessions -= 1
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.metrics_lock:
                self.active_sessions -= 1

    def record_frame_quota_close(self):
        with self.metrics_lock:
            self.frame_quota_closes += 1
