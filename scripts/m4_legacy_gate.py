#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M4 old-PC preservation policy: source/QEMU evidence cannot certify hardware."""
import json
from pathlib import Path
import sys

from m0_device_registry import CandidateIndex, RegistryError, read_json

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = ["modern-amd64", "legacy-amd64"]
NEEDED = {"amd-pcnet": "ether79c970", "realtek-rtl8139": "ether8139",
          "legacy-sata-ahci": "sdiahci", "legacy-usb-ehci": "usbehci"}


def audit(root=ROOT, manifest=None):
    root=Path(root)
    m=manifest if manifest is not None else read_json(root/"ryzova/drivers/m4-legacy-qualification.json")
    if (not isinstance(m,dict) or set(m)!={"schema","policy","platforms",
        "qemu_legacy_memory_mib","release_approval","hardware_models_certified","families"}
        or m["schema"]!="ryzova-m4-legacy-qualification/v1"
        or m["policy"]!="preserve-modern-and-legacy-no-source-only-certification"
        or m["platforms"]!=PLATFORM
        or type(m["qemu_legacy_memory_mib"]) is not int
        or not 128<=m["qemu_legacy_memory_mib"]<=512
        or m["release_approval"] is not False
        or type(m["hardware_models_certified"]) is not int
        or m["hardware_models_certified"]!=0):
        raise RegistryError("M4 policy must remain fail-closed, with modern and legacy AMD64 tracks")
    if not isinstance(m["families"],list) or len(m["families"])!=len(NEEDED):
        raise RegistryError("M4 missing legacy driver family")
    records=read_json(root/"ryzova/drivers/m0-device-registry.json")
    firmware=read_json(root/"ryzova/drivers/m0-firmware-manifest.json")
    index=CandidateIndex(records,firmware,root)
    index.verify_pc64_configuration(root)
    registry={entry["id"]:entry for entry in records["rules"]}
    seen=set()
    for row in m["families"]:
        if not isinstance(row,dict) or set(row)!={"id","driver","source","pci_candidate",
             "required_tests","physical_verified"}:
            raise RegistryError("M4 malformed legacy family")
        name=row["id"]
        if name not in NEEDED or name in seen or row["driver"]!=NEEDED[name]:
            raise RegistryError("M4 unknown/duplicate legacy family")
        seen.add(name)
        if row["physical_verified"] is not False:
            raise RegistryError("M4 cannot self-approve physical hardware")
        source=row["source"]
        if not isinstance(source,str) or not source.startswith("sys/src/9/"):
            raise RegistryError("invalid legacy driver source")
        path=(root/source).resolve()
        if not path.is_relative_to(root.resolve()) or not path.is_file():
            raise RegistryError("legacy driver missing")
        tests=row["required_tests"]
        if (not isinstance(tests,list) or len(tests)<5
            or "native-amd64-build" not in tests or len(tests)!=len(set(tests))
            or any(not isinstance(t,str) or not t for t in tests)):
            raise RegistryError("missing legacy qualification tests")
        if name in ("amd-pcnet","realtek-rtl8139"):
            if "low-memory-qemu-boot" not in tests:
                raise RegistryError("legacy low RAM regression lost")
        rid=row["pci_candidate"]
        if rid is not None:
            rule=registry.get(rid)
            if not rule or rule["source_file"]!=source or rule["bus"]!="pci" or rule["driver"]!=row["driver"] or rule["binding_enabled"] is not False:
                raise RegistryError("legacy registry source/driver mismatch")
        elif name!="legacy-usb-ehci":
            raise RegistryError("missing known PCI class candidate")
    if set(seen)!=set(NEEDED):
        raise RegistryError("M4 family inventory incomplete")
    return {
        "schema":"ryzova-m4-legacy-gate/v1",
        "gate":"blocked-pending-real-hardware",
        "class_families_tracked":len(seen),
        "verified_physical_models":0,
        "certified_models":0,
        "virtual_legacy_memory_mib":m["qemu_legacy_memory_mib"],
        "modern_and_legacy_regressions_required":True,
        "auto_bind_allowed":False,
        "real_legacy_pcs_qualified":False
    }


if __name__=="__main__":
    try:
        print(json.dumps(audit(),indent=2,sort_keys=True))
    except (OSError,ValueError,RegistryError) as e:
        sys.exit("M4 validation rejected: "+str(e))
