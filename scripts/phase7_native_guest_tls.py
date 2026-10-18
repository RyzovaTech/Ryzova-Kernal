# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed QEMU guest-native pinned TLS1.2 -> 9P file/digest proof."""
import hashlib
import re
from phase6_native_9p import payload_for_commit

PORT=15641

def commands(cert_sha256):
    if not isinstance(cert_sha256,str) or not re.fullmatch(r"[a-f0-9]{64}",cert_sha256):
        raise ValueError("exact server DER thumbprint required")
    # A QEMU serial console is the TEST HARNESS trust provisioning channel.
    # Production cannot use this ephemeral test provisioning scheme.
    return (
      ("phase7-native-guest-tls-mount",
       "echo 'x509 sha256="+cert_sha256+"' > /tmp/ryzova7-trusted; "
       "mkdir -p /n/ryzova7; "
       "srv -enq 'tlsclient -n localhost -t /tmp/ryzova7-trusted tcp!10.0.2.2!15641' ryzova7; "
       "mount -n /srv/ryzova7 /n/ryzova7; "
       "echo RYZOVA_NATIVE_TLS_READ_BEGIN; "
       "cat /n/ryzova7/probe; echo RYZOVA_NATIVE_TLS_READ_END; "
       "echo RYZOVA_RUNTIME_STAGE_16"),
      ("phase7-native-guest-tls-sha256",
       "sha1sum -2 256 /n/ryzova7/probe; "
       "echo RYZOVA_RUNTIME_STAGE_17; echo RYZOVA_NATIVE_TLS_DONE"),
    )


def _line(data,s):
    return re.search(rb"(?:^|\r?\n)"+re.escape(s)+rb"(?:\r?\n|$)",data) is not None

def inspect(serial,commit,cert_sha256,metrics):
    payload=payload_for_commit(commit).rstrip(b"\n")
    digest=hashlib.sha256(payload_for_commit(commit)).hexdigest().encode()
    start=re.search(rb"(?:^|\r?\n)RYZOVA_NATIVE_TLS_READ_BEGIN\r?\n(.*?)"
                    rb"(?:\r?\n)RYZOVA_NATIVE_TLS_READ_END(?:\r?\n|$)",serial,re.S)
    section=start.group(1) if start else b""
    check={
      "native_guest_read_over_tls":_line(section,payload),
      "native_guest_sha256_matched":
        bool(re.search(rb"(?:^|\r?\n)"+re.escape(digest)+rb"\s+/n/ryzova7/probe(?:\r?\n|$)",serial)),
      "native_guest_tls_stages_completed":
        _line(serial,b"RYZOVA_RUNTIME_STAGE_16") and _line(serial,b"RYZOVA_RUNTIME_STAGE_17")
        and _line(serial,b"RYZOVA_NATIVE_TLS_DONE"),
      "server_negotiated_guest_tls12":
        type(metrics.get("native_tls12_sessions")) is int and metrics["native_tls12_sessions"]>=1,
      "actual_native_tls_9p_frames":
        type(metrics.get("native_tls_9p_frames")) is int and metrics["native_tls_9p_frames"]>=5,
      "upstream_tls13_still_authenticated":
        type(metrics.get("upstream_tls13_sessions")) is int and metrics["upstream_tls13_sessions"]>=1,
      "source_commit_sha256_bound":bool(re.fullmatch(r"[a-f0-9]{64}",cert_sha256)),
      "no_kernel_panic":re.search(rb"(?im)(?:^|\n)panic:",serial) is None,
    }
    return {"schema":"ryzova-phase7-native-guest-tls-proof/v1",
            "passed":all(check.values()),"checks":check,"source_commit":commit,
            "guest_certificate_sha256":cert_sha256,"payload_sha256":digest.decode(),
            "metrics":metrics,
            "guest_to_host_encryption":"TLS1.2, guest certificate-thumbprint pin",
            "host_to_peer_encryption":"mutual TLS1.3 with pinned certificates",
            "production_key_provisioning_verified":False,
            "guest_mutual_tls_client_certificate_verified":False,
            "remote_physical_machine_verified":False,
            "release_permitted":False}
