# Compact Windows — physical power-cut qualification boundary

The merged W6 evidence covers a **dedicated QEMU virtio-SCSI device**,
`SYNCHRONIZE CACHE`, independently nonce-acknowledged flushes, VM SIGKILL,
reboot and byte-for-byte file SHA-256 recovery. These are excellent virtual
regressions, **not experiments on a powered-off physical drive**.

Real-device qualification requires a designated disposable device, firmware
inventory, protected test operator, independently controlled power-cut
hardware, a separate witness recorder, **at least three** ACK→external-cut→
power-restore→cold-boot→SHA verification cycles, unique nonces and strictly
increasing independent controller event counters, plus *physical* I/O
failure and sticky-error/zero-ACK probes. Avoid testing on personal or
production storage: destructive cuts risk data loss and damage.

`scripts/compact_windows_physical_powercut.py` validates the device/run
manifest, bounded chronology, exact file hashes and external Ed25519 signature.
The trust key fingerprint **must be pinned out-of-band by the hardware test
reviewer**; the report may not choose its own trusted witness. The tool is
only a **review candidate** generator. It never makes a physical power cut,
does not validate that the described physical experiment actually happened,
and **always returns `physical_hardware_qualified=false`**. Independent
operator review and signed release approval must remain distinct from tool
output. Unit tests use synthetic manifests and ephemeral cryptographic keys
solely to verify tamper detection; they are not hardware observations.

Only after a real lab has collected externally witnessed, signed physical
runs (device/controller IDs, firmware, serial digest, real power-off event
and cold recovery logs), and a human reviewer confirms source/runtime/driver
provenance, might an independent *future* release qualification record
assert real hardware durability. Do not add this assertion to W6 or CI based
on fabricated/simulated evidence.

ARM64 Windows, ARM64EC/X, arbitrary Win32 APIs, GUI, device drivers and
general compatibility are **other separate release gates** and are not
established by the physical evidence validator.

Source-of-truth references:
- `docs/COMPACT-WINDOWS-W6.md` — QEMU virtual device observations
- `ryzova/compact/windows-v1-plan.json` — pending formal release requirements
- Microsoft PE/ARM64 ABI specification — separate execution scope

This feature must not alter existing driver-agent code or upstream sync.

## W9 original raw-log bundle gate

A signed manifest with hash-shaped strings is **not enough**. The W9
validator CLI now also requires `--evidence-directory` containing each
independent cycle's `flush-ack.serial`, `power-cut.serial` and
`reboot.serial` plus `negative/flush-fault.serial` and
`negative/flush-sticky.serial`. Files must be nonempty regular files,
within 1 MiB, opened via non-following directory/file handles and must
exactly match the SHA-256 digest signed in the witness manifest. Duplicate,
missing, mutated, symlinked or oversized evidence is rejected.
The CLI now marks `ready_for_independent_hardware_review=true` only when
both Ed25519 signature **and actual raw log bundle** verify. All tests use
synthetic temporary data and self-generated test keys, explicitly *not*
physical measurements. Even a correctly signed and hashed bundle still
reports `physical_hardware_qualified=false` until separately witnessed
real power-cut tests and human review have actually occurred.
