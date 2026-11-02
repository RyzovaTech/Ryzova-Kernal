# Windows resource filesystem overlay

This is an isolated overlay of 9front hjfs, derived from the exact tracked
`sys/src/cmd/hjfs` sources in the build commit (upstream MIT notice in LICENSE).
New barrier/protocol code is AGPL-3.0-only. The native evidence builder copies
upstream hjfs sources into this separate build directory and replaces only these
overlay files. The installed binary is `cw-hjfs`; the boot hjfs binary and original
hjfs/Linux sources are unchanged.

`-F` enables the version 1 durability profile on **only** the dedicated
`/dev/sd01/data` QEMU virtio-SCSI disk. Initialization verifies the controller,
opens the matching unit's exclusive raw capability and successfully probes a
non-immediate SCSI SYNCHRONIZE CACHE before any formatting. This is not a general
hardware/driver qualification. Use `-r` only on a disposable fresh resource disk;
it formats that disk. No generic file image or boot unit is accepted by `-F`.

A reserved virtual `.ryzova-sync-v1` control fid is available on that same 9P
connection to a non-none native user. It supports exact bounded nonce requests
and distinct nonce ACKs. In strict mode there is no periodic background sync or
administrative command pipe. The barrier write-locks the filesystem, drains queued
buffer returns, submits dirty buffers, waits behind all device writes, rejects
sticky write errors and obtains SCSI GOOD status after SYNCHRONIZE CACHE. Only
then can the nonce ACK be read. Failure never leaves a previous ACK readable.

The native launcher pins the control descriptor, version/Qid, banner and matching
9P device/type for the grant root. Ordinary files, cross-mount capabilities and
command pipes cannot qualify. Guest file APIs cannot open this reserved control
name. The trusted native launcher/owning service remain inside the trust boundary;
this does not authenticate an actively malicious native administrator or server.
