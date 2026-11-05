# Compact Windows AMD64 physical bench

The first bench gate runs the existing W3 console/API program and six W5 CRT
and fault fixtures on a physical AMD64 PC. It uses the existing Compact
Windows runner with no file grant. Capture the Flex boot and the entire
bench command on the same serial or console capture.

## Prepare the bench

Use a source checkout and the matching native `9pc64` and `compact-windows`
build outputs. The operator supplies these two binaries and records their
build provenance. See [the native build guide](BUILD.md). Obtain the
`windows-w6-compiler-fixtures` ZIP from a successful W6 run and extract it.
The preparation tool checks the MSVC fixture receipts, source file hashes
and executable hashes before copying the seven selected PEs.

```sh
python3 scripts/compact_windows_hardware.py prepare \
  --fixtures /path/to/w6-fixtures --kernel /path/to/9pc64 \
  --runtime /path/to/compact-windows --out cw-bench
```

Keep the original bundle for verification. Boot the bundle kernel from a
separate test boot medium configured to load `9pc64`. On the test system,
mount its FAT boot partition with `9fs 9fat` and confirm that
`/n/9fat/9pc64` is the selected boot file. Copy `bench.rc`,
`compact-windows` and the PE files into `/tmp/cw-hw`. The Plan 9 runner
needs execute permission. From a native rc shell, capture:

```rc
rc /tmp/cw-hw/bench.rc
```

The command reads the boot file and the fixture files and runs the fixture
programs without a namespace file grant. It requires no storage formatting,
disk controller commands or power interruption.

## Verify the capture

Record these fields based on the actual bench machine. Use true values for
the two observations only after witnessing the corresponding events.

```json
{
  "machine_model": "actual motherboard or PC model",
  "cpu_model": "actual AMD64 CPU",
  "firmware_version": "actual UEFI or BIOS version",
  "boot_device": "actual test boot device model and interface",
  "operator_observed_bare_metal": true,
  "operator_booted_kernel_from_bundle": true
}
```

```sh
python3 scripts/compact_windows_hardware.py verify \
  --bundle cw-bench --serial bench.log --hardware hardware.json --out receipt.json
```

Retain the raw capture, hardware observations, original manifest and receipt.
The verifier ties the capture to the staged binaries, checks the configured
boot-file hash and Flex identity, then reuses the W6 native case parser for
stdout, stderr, guest exit/fault and API checks. Hardware identity and the
choice of active boot file are operator observations.

## Dedicated physical storage gate

Record the separate test disk model, transport, controller and firmware
before designing a storage backend for it. The current acknowledged
`cw-hjfs` backend is scoped to the dedicated QEMU virtio-SCSI unit. The
physical backend needs device-specific evidence of cache synchronization
completion, failure propagation and recovery. Once it has those checks,
the physical durability test uses a disposable resource disk, records the
successful W4 flush acknowledgements, cuts power to the bench, then compares
the recovered file hash after boot. Keep the boot disk and resource disk
evidence separate.
