#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""M5 source-verified architecture/server readiness without false support counts."""
import json
from pathlib import Path
import re
import sys

from m0_device_registry import RegistryError, read_json

ROOT=Path(__file__).resolve().parents[1]
ORDER=("arm64-qemu-server","amd64-server","legacy-amd64")
EXPECTED={
    "arm64-qemu-server":("arm64",("pciqemu","ethervirtio10","sdvirtio10","usbxhcipci")),
    "amd64-server":("amd64",("sdnvme","sdvirtio10","ethervirtio10","etherx550","usbxhcipci")),
    "legacy-amd64":("amd64",("ether79c970","ether8139","sdiahci","usbehci")),
}


def audit(root=ROOT, matrix=None):
    root=Path(root).resolve()
    m=matrix if matrix is not None else read_json(root/"ryzova/drivers/m5-platform-matrix.json")
    if (not isinstance(m,dict) or set(m)!={"schema","policy","release_gate",
        "certified_models","automatic_cross_arch_driver_bind","profiles"} or
        m["schema"]!="ryzova-m5-architecture-matrix/v1" or
        m["policy"]!="source-readiness-not-hardware-certification" or
        m["release_gate"]!="blocked-pending-native-arm64-boot-and-lab" or
        type(m["certified_models"]) is not int or m["certified_models"]!=0 or
        m["automatic_cross_arch_driver_bind"] is not False):
        raise RegistryError("M5 must not auto-bind or claim unsupported devices")
    profiles=m["profiles"]
    if not isinstance(profiles,list) or [p.get("id") if isinstance(p,dict) else None for p in profiles]!=list(ORDER):
        raise RegistryError("M5 must retain ARM64, AMD64 server and legacy AMD64 profiles")
    validated=[]
    for profile in profiles:
        key=profile["id"]
        fields={"id","architecture","configuration","compiler_target",
                "required_link_drivers","safety_source","evidence",
                "native_compilation_verified","boot_verified",
                "physical_verified","evidence_needed"}
        if set(profile)!=fields or profile["architecture"]!=EXPECTED[key][0] or profile["compiler_target"]!=EXPECTED[key][0]:
            raise RegistryError("M5 invalid architecture profile metadata")
        if profile["required_link_drivers"]!=list(EXPECTED[key][1]):
            raise RegistryError("M5 architecture driver policy mismatch")
        expected_config="sys/src/9/arm64/qemu" if key=="arm64-qemu-server" else "sys/src/9/pc64/pc64"
        if profile["configuration"]!=expected_config:
            raise RegistryError("M5 build configuration altered without review")
        if profile["physical_verified"] is not False:
            raise RegistryError("M5 cannot certify untested physical boards")
        is_arm=key=="arm64-qemu-server"
        if is_arm:
            if (profile["native_compilation_verified"] is not False or
                profile["boot_verified"] is not False or
                profile["evidence"]!="source-integrated" or
                profile["safety_source"]!="sys/src/9/arm64/m5ecam.c"):
                raise RegistryError("M5 ARM64 native build/boot is not independently verified")
        else:
            if (profile["native_compilation_verified"] is not True or
                profile["boot_verified"] is not True or
                profile["safety_source"]!=("sys/src/9/pc/etherx550.c" if key=="amd64-server" else "sys/src/9/pc/ether79c970.c")):
                raise RegistryError("M5 unexpectedly changed established AMD64 evidence")
        tests=profile["evidence_needed"]
        if (not isinstance(tests,list) or len(tests)<5 or
            len(tests)!=len(set(tests)) or
            any(not isinstance(t,str) or not re.fullmatch("[a-z0-9-]{5,90}",t) for t in tests)):
            raise RegistryError("M5 qualification evidence requirements incomplete")
        conf=(root/expected_config).read_text(encoding="utf-8")
        for name in EXPECTED[key][1]:
            if not re.search(r"(?m)^\s*"+re.escape(name)+r"\s+(?:pci|$)",conf):
                raise RegistryError("M5 driver missing from config: "+key+" / "+name)
        src=(root/profile["safety_source"]).resolve()
        if not src.is_relative_to(root) or not src.is_file():
            raise RegistryError("M5 missing safety source")
        validated.append({"profile":key,"architecture":profile["architecture"],
                          "source_drivers":len(EXPECTED[key][1]),
                          "native_compilation_verified":profile["native_compilation_verified"],
                          "boot_verified":profile["boot_verified"],
                          "physical_verified":False})
    pci=(root/"sys/src/9/arm64/pciqemu.c").read_text()
    mk=(root/"sys/src/9/arm64/mkfile").read_text()
    if (not re.search(r"(?m)^\s*m5ecam\.\$O\\",mk) or
        '#include "m5ecam.h"' not in pci or
        "m5ecamoffset(BUSBNO(tbdf), BUSDNO(tbdf), BUSFNO(tbdf)," not in pci or
        "BUSTYPE(tbdf) != BusPCI" not in pci or
        "if(ecam == nil)" not in pci):
        raise RegistryError("M5 ARM64 ECAM guard is not linked and fail-closed")
    return {
        "schema":"ryzova-m5-readiness-audit/v1",
        "release_gate":"blocked-pending-native-arm64-boot-and-lab",
        "source_profile_count":len(validated),
        "arm64_native_boot_confirmed":False,
        "newly_certified_models":0,
        "auto_binding":False,
        "profiles":validated
    }


if __name__=="__main__":
    try:
        print(json.dumps(audit(),indent=2,sort_keys=True))
    except (OSError,ValueError,RegistryError) as e:
        sys.exit("M5 audit rejected: "+str(e))
