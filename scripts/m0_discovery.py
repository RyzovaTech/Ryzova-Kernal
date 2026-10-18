#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M0.2 read-only Linux sysfs PCI/USB snapshot -> unverified Ryzova candidates.

Development-side host inventory, NOT a Ryzova kernel discovery implementation.
It does not issue writes, collect serial numbers, bind a driver, or certify hardware.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from m0_device_registry import CandidateIndex, RegistryError, read_json

HEXDIGITS = re.compile(r"(?:0x)?[0-9a-fA-F]+\Z")
DEVNAME = re.compile(r"[A-Za-z0-9:._-]{1,128}\Z")
MAX_ENTRIES = 16384


def read_hex_attribute(path, digits):
    """Small bounded read; reject partial/oversized or malformed sysfs fields."""
    if not path.is_file():
        raise RegistryError("missing sysfs field " + path.name)
    with path.open("rb") as f:
        value = f.read(64)
        if f.read(1):
            raise RegistryError("oversized sysfs field " + path.name)
    try:
        string = value.decode("ascii").strip()
    except UnicodeError:
        raise RegistryError("non-ASCII sysfs field " + path.name) from None
    if not HEXDIGITS.fullmatch(string):
        raise RegistryError("invalid sysfs hex " + path.name)
    number = int(string, 16)
    if number < 0 or number >= 1 << (4 * digits):
        raise RegistryError("out-of-range sysfs field " + path.name)
    return number


def enumerate_links(base, root):
    if not base.is_dir():
        return []
    entries = sorted(base.iterdir(), key=lambda p: p.name)
    if len(entries) > MAX_ENTRIES:
        raise RegistryError("too many sysfs entries")
    result = []
    for link in entries:
        if not DEVNAME.fullmatch(link.name):
            raise RegistryError("unsafe sysfs device name")
        target = link.resolve(strict=True)
        if not target.is_relative_to(root) or not target.is_dir():
            raise RegistryError("sysfs link escapes selected root")
        result.append((link.name, target))
    return result


def discovery(sysroot, registry, *, include_matches=True):
    root = sysroot.resolve(strict=True)
    if not root.is_dir():
        raise RegistryError("sysfs root must be directory")
    devices = []
    pci = enumerate_links(root / "bus/pci/devices", root)
    usb = enumerate_links(root / "bus/usb/devices", root)
    usb_devices = {}

    for name, path in pci:
        vendor = read_hex_attribute(path / "vendor", 4)
        device = read_hex_attribute(path / "device", 4)
        classtriplet = read_hex_attribute(path / "class", 6)
        revision = read_hex_attribute(path / "revision", 2)
        devices.append(dict(bus="pci", locator=name, vendor=vendor, device=device,
                            classcode=(classtriplet >> 16) & 255,
                            subclass=(classtriplet >> 8) & 255,
                            protocol=classtriplet & 255, revision=revision))

    for name, path in usb:
        # USB hubs and root hubs may lack one or more descriptor attributes.
        # Only device entries with both VID/PID can be matched.
        if not (path / "idVendor").is_file():
            continue
        vendor = read_hex_attribute(path / "idVendor", 4)
        device = read_hex_attribute(path / "idProduct", 4)
        revision = read_hex_attribute(path / "bcdDevice", 4)
        usb_devices[name] = (vendor, device, revision)
        # Device-level classes, where supplied, are distinct from interfaces.
        if all((path / k).is_file() for k in
               ("bDeviceClass", "bDeviceSubClass", "bDeviceProtocol")):
            devices.append(dict(bus="usb", locator=name, vendor=vendor, device=device,
                                classcode=read_hex_attribute(path / "bDeviceClass", 2),
                                subclass=read_hex_attribute(path / "bDeviceSubClass", 2),
                                protocol=read_hex_attribute(path / "bDeviceProtocol", 2),
                                revision=revision))

    for name, path in usb:
        if ":" not in name:
            continue
        parent = name.split(":", 1)[0]
        if parent not in usb_devices:
            continue
        if not all((path / k).is_file() for k in
                   ("bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol")):
            continue
        vendor, device, revision = usb_devices[parent]
        devices.append(dict(bus="usb", locator=name, vendor=vendor, device=device,
                            classcode=read_hex_attribute(path / "bInterfaceClass", 2),
                            subclass=read_hex_attribute(path / "bInterfaceSubClass", 2),
                            protocol=read_hex_attribute(path / "bInterfaceProtocol", 2),
                            revision=revision))

    devices.sort(key=lambda d: (d["bus"], d["locator"]))
    for d in devices:
        observation = registry.match(d["bus"], d["vendor"], d["device"],
                                     d["classcode"], d["subclass"], d["protocol"], d["revision"])
        d["source_candidate"] = observation if include_matches else None
        d["vendor_id"] = "%04x" % d.pop("vendor")
        d["device_id"] = "%04x" % d.pop("device")
        d["class_code"] = "%02x" % d.pop("classcode")
        d["subclass"] = "%02x" % d["subclass"]
        d["protocol"] = "%02x" % d["protocol"]
        d["revision"] = "%04x" % d["revision"]
        d["runtime_driver_bound"] = None
        d["hardware_verified"] = False
    payload = json.dumps(devices, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "ryzova-m0-discovery/v1",
        "collector": "linux-sysfs-readonly",
        "provenance": "unattested-host-observations",
        "observations_sha256": hashlib.sha256(payload).hexdigest(),
        "device_observations": len(devices),
        "source_candidates": sum(
            d["source_candidate"] is not None and
            d["source_candidate"]["result"] == "source-candidate" for d in devices),
        "newly_verified_hardware_models": 0,
        "auto_bind_allowed": False,
        "devices": devices,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sysfs-root", required=True, type=Path, help="Explicit Linux sysfs root (/sys or test fixture)")
    p.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--output", type=Path, help="Output snapshot, otherwise stdout")
    args = p.parse_args()
    try:
        root = args.root.resolve()
        reg = read_json(root / "ryzova/drivers/m0-device-registry.json")
        firmware = read_json(root / "ryzova/drivers/m0-firmware-manifest.json")
        index = CandidateIndex(reg, firmware, root)
        index.verify_pc64_configuration(root)
        report = discovery(args.sysfs_root, index)
    except (OSError, ValueError, RegistryError) as exc:
        p.exit(1, "M0 discovery rejected: " + str(exc) + "\n")
    text = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
