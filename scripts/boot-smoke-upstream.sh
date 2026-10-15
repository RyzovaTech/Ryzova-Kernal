#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Diagnostic QEMU boot of an official 9front release, NOT a build of the Ryzova source.
set -euo pipefail
mkdir -p artifacts/qemu
cd artifacts/qemu
release="11952"
url="https://build.9front.org/release/9front-${release}.amd64.qcow2.gz"
printf '%s\n' "Official upstream 9front release VM (not Ryzova source): $url" | tee summary.txt
echo 'SOURCE_BUILD_VERIFIED=false' >> summary.txt
echo 'RYZOVA_KERNEL_BOOT_VERIFIED=false' >> summary.txt
curl --fail --location --retry 3 --retry-delay 5 --connect-timeout 25 --max-time 850 "$url" --output upstream.qcow2.gz
sha256sum upstream.qcow2.gz | tee compressed-sha256.txt
gzip -t upstream.qcow2.gz
gzip -dc upstream.qcow2.gz > upstream.qcow2
qemu-img info upstream.qcow2 | tee image-info.txt
# Keep a copy-on-write overlay; do not alter the official image.
qemu-img create -f qcow2 -F qcow2 -b upstream.qcow2 boot-overlay.qcow2
echo "Starting QEMU with software emulation (KVM not required)"
qemu-system-x86_64 \
  -machine pc,accel=tcg -cpu qemu64 -m 1024 -smp 2 \
  -device virtio-scsi-pci,id=scsi \
  -drive if=none,id=vd0,file=boot-overlay.qcow2,format=qcow2 \
  -device scsi-hd,drive=vd0 \
  -device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
  -vga std -display none \
  -serial file:serial.log \
  -monitor unix:monitor.sock,server=on,wait=off \
  -no-reboot -no-shutdown > qemu-host.log 2>&1 &
pid=$!
cleanup() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
trap cleanup EXIT
# Boot to a snapshotable state (do not count process-start as guest boot success).
sleep 75
if ! kill -0 "$pid" 2>/dev/null; then
  echo "QEMU exited unexpectedly; see qemu-host.log" >&2
  exit 1
fi
if test -S monitor.sock; then
  printf 'screendump boot-screen.ppm\n' | socat - UNIX-CONNECT:monitor.sock > monitor-output.txt || true
fi
echo "===== QEMU serial output (last 100 lines) ====="
tail -n 100 serial.log || true
echo "===== QEMU host log (last 100 lines) ====="
tail -n 100 qemu-host.log || true
echo "===== Screenshot metadata ====="
test -s boot-screen.ppm && file boot-screen.ppm || true
# STRICT verdict: a QEMU process or BIOS output alone does not prove 9front kernel boot.
if grep -Eaiq 'Plan 9 from Bell Labs|9front|^cpu[0-9]+:|^init: starting' serial.log; then
  echo 'UPSTREAM_VM_SERIAL_KERNEL_EVIDENCE=true' | tee -a summary.txt
  echo 'The upstream release VM emitted guest-identifying serial output.'
else
  echo 'UPSTREAM_VM_SERIAL_KERNEL_EVIDENCE=unconfirmed' | tee -a summary.txt
  echo 'No definitive 9front serial boot marker; review captured VGA screenshot manually.' >&2
  exit 1
fi
