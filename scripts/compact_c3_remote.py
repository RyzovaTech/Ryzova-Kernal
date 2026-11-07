# SPDX-License-Identifier: GPL-3.0-only
"""Source-bound test resource delivered through a pinned guest TLS 9P mount."""
import hashlib
import json
from pathlib import Path
import re
import sys

MOUNT = "/n/compactc3"
FILENAME = "probe"
RESOURCE = f"{MOUNT}/{FILENAME}"
PIN = "/tmp/compactc3-pin"


def payload(commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("exact source commit required")
    return (json.dumps(dict(items=[2, 3, 5], source=commit), separators=(",", ":")) + "\n").encode()


def route_fixture(commit):
    root = str(Path(__file__).resolve().parents[1])
    if root not in sys.path:
        sys.path.insert(0, root)
    from ryzova.remote.phase7_fixture import Ephemeral9PTLSFixture

    return Ephemeral9PTLSFixture(payload(commit))


def mount_commands(route):
    port = route.guest_tls.server_address[1]
    return [
        f"echo 'x509 sha256={route.guest_cert_sha256}' >{PIN}",
        f"mkdir -p {MOUNT}",
        f"srv -enq 'tlsclient -n localhost -t {PIN} tcp!10.0.2.2!{port}' compactc3",
        f"mount -n /srv/compactc3 {MOUNT}",
    ]


def transport_evidence(route, commit):
    counts = dict(guest_tls_sessions=route.guest_tls.tls12_sessions,
                  guest_9p_frames=route.guest_tls.forwarded_frames,
                  verified_peer_sessions=route.gateway.verified_tls_sessions,
                  peer_authenticated_sessions=route.peer.secure_sessions,
                  peer_9p_frames=route.peer.frames)
    if (any(counts[key] < 1 for key in (
            "guest_tls_sessions", "verified_peer_sessions", "peer_authenticated_sessions")) or
            min(counts["guest_9p_frames"], counts["peer_9p_frames"]) < 5):
        raise ValueError(f"Compact C3 pinned 9P route did not carry the guest workload: {counts}")
    return dict(schema="compact-c3-remote-file/v1", source_commit=commit,
                namespace_path=RESOURCE, input_sha256=hashlib.sha256(payload(commit)).hexdigest(),
                guest_server_pin=route.guest_cert_sha256, peer_location="CI host loopback",
                **counts)


def linux_commands():
    return [
        f"if($c1 -r -b 16777216 -M 'r:/home/share={MOUNT}' /tmp/c1-jq -c . /home/share/{FILENAME} >/tmp/c3.out >[2]/tmp/c3.log) echo C3_LINUX_EXIT_OK",
        "grep -v '^COMPACT_(LINUX_RESULT|JOBS_STATS|RESOURCE_STATS) ' /tmp/c3.log >/tmp/c3.err",
        "sha1sum -2 256 /tmp/c3.out /tmp/c3.err; cat /tmp/c3.out /tmp/c3.log; echo COMPACT_C3_LINUX_DONE",
    ]


def linux_result(serial, commit):
    def digest_line(path, data):
        return re.findall(rb"(?m)^([0-9a-f]{64})[ \t]+" + re.escape(path) + rb"\r?$", data)

    expected = payload(commit)
    if (not re.search(rb"(?m)^C3_LINUX_EXIT_OK\r?$", serial) or
            digest_line(b"/tmp/c3.out", serial) != [hashlib.sha256(expected).hexdigest().encode()] or
            digest_line(b"/tmp/c3.err", serial) != [hashlib.sha256(b"").hexdigest().encode()] or
            not re.search(rb"(?m)^COMPACT_C3_LINUX_DONE\r?$", serial)):
        raise ValueError("Compact Linux remote jq output differs")
    return dict(exit_code=0, stdout_hex=expected.hex(), stderr_hex="")
