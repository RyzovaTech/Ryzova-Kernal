# SPDX-License-Identifier: AGPL-3.0-only
"""Direct Windows PE import inventory tests; every result stays non-executable."""
import copy
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from compact_windows_import_audit import discover

PLAN=json.loads((ROOT/"ryzova/compact/windows-v1-plan.json").read_text())


def sample(symbol=b"WriteFile",machine=0x8664,ordinal=False):
    b=bytearray(0x800)
    b[:2]=b"MZ"
    p=0x80;q=p+24
    struct.pack_into("<I",b,0x3c,p)
    b[p:p+4]=b"PE\0\0"
    struct.pack_into("<HH",b,p+4,machine,1)
    struct.pack_into("<H",b,p+20,240)
    struct.pack_into("<H",b,q,0x20b)
    struct.pack_into("<I",b,q+108,16)
    struct.pack_into("<II",b,q+120,0x2000,40) # import directory
    sec=q+240
    b[sec:sec+8]=b".idata\0\0"
    struct.pack_into("<III",b,sec+12,0x2000,512,0x400)
    # descriptor: oft, time, forward, name, iat
    struct.pack_into("<IIIII",b,0x400,0x2040,0,0,0x2060,0x2080)
    struct.pack_into("<Q",b,0x440,(1<<63)+42 if ordinal else 0x20a0)
    b[0x460:0x46d]=b"KERNEL32.DLL\0"
    if not ordinal:
        struct.pack_into("<H",b,0x4a0,0)
        b[0x4a2:0x4a2+len(symbol)+1]=symbol+b"\0"
    return bytes(b)

class ImportAuditTests(unittest.TestCase):
    def test_known_import_and_arm64_import_inventory_not_runtime_proof(self):
        for machine,architecture in ((0x8664,"amd64"),(0xaa64,"arm64-classic")):
            with self.subTest(machine=hex(machine)):
                report=discover(sample(machine=machine),PLAN)
                self.assertEqual(report["architecture"],architecture)
                self.assertEqual(report["supported_declared_imports"],["kernel32.dll!WriteFile"])
                self.assertEqual(report["missing_or_ordinal_imports"],[])
                self.assertTrue(report["declared_import_profile_covered"])
                self.assertFalse(report["guest_executable_verified"])
                self.assertFalse(report["general_windows_compatibility"])

    def test_unknown_name_ordinal_and_missing_module(self):
        report=discover(sample(symbol=b"Beep"),PLAN)
        self.assertEqual(report["missing_or_ordinal_imports"],["kernel32.dll!Beep"])
        self.assertFalse(report["declared_import_profile_covered"])
        report=discover(sample(ordinal=True),PLAN)
        self.assertEqual(report["missing_or_ordinal_imports"],["kernel32.dll!#42"])
        self.assertFalse(report["declared_import_profile_covered"])

    def test_no_imports_still_do_not_prove_application_execution(self):
        b=bytearray(sample())
        q=0x80+24
        struct.pack_into("<II",b,q+120,0,0)
        report=discover(bytes(b),PLAN)
        self.assertEqual(report["direct_imports"],0)
        self.assertFalse(report["guest_executable_verified"])

    def test_delay_load_imports_do_not_prove_win32_execution(self):
        # A classic RVA-based ImgDelayDescr (PE directory index 13).
        # Even if the name matches a declared API, the actual
        # LoadLibrary/GetProcAddress delay resolver is NOT implemented.
        image=bytearray(sample())
        opt=0x80+24
        struct.pack_into("<II",image,opt+112+13*8,0x20c0,64)
        struct.pack_into("<8I",image,0x4c0,1,0x2100,0x2110,0x2130,
                         0x2120,0,0,0)
        image[0x500:0x50b]=b"USER32.DLL\\0".replace(b"\\0",b"\\x00")
        struct.pack_into("<Q",image,0x520,0x2140)
        image[0x540:0x54e]=b"\\x00\\x00MessageBoxW\\x00".decode(
            "unicode_escape").encode("latin1")
        report=discover(bytes(image),PLAN)
        self.assertEqual(report["delay_load_modules"],["user32.dll"])
        self.assertEqual(report["delay_load_imports"],["user32.dll!MessageBoxW"])
        self.assertTrue(report["delay_load_requires_runtime_resolver"])
        self.assertFalse(report["declared_import_profile_covered"])
        self.assertFalse(report["guest_executable_verified"])
        self.assertFalse(report["general_windows_compatibility"])

        for mutation in (
            (0x4c0,0),                 # old VA-based form unsupported
            (0x4c0,2),                 # reserved descriptor flags
            (0x4c0+16,0),              # no INT
            (0x4c0+4,0xfffffff0),     # DLL outside input
            (0x520,0xffffffffffffffe0), # forged ordinal reserved bits
        ):
            at,value=mutation
            with self.subTest(at=at,value=value),self.assertRaises(ValueError):
                broken=bytearray(image)
                struct.pack_into("<Q" if at==0x520 else "<I",broken,at,value)
                discover(bytes(broken),PLAN)

    def test_clr_and_tls_directories_prevent_unsupported_coverage_claims(self):
        original=sample()
        for index in (9,14):
            with self.subTest(directory=index):
                img=bytearray(original)
                struct.pack_into("<II",img,0x80+24+112+index*8,0x2060,16)
                report=discover(bytes(img),PLAN)
                self.assertEqual(report["runtime_directories_unqualified"],[index])
                self.assertFalse(report["declared_import_profile_covered"])

    def test_unbounded_or_inconsistent_imports_fail_closed(self):
        b=sample()
        p=0x80;q=p+24
        mutants=[
            b[:140],b"BAD",bytes(bytearray(b).replace(b"PE\0\0",b"BAD!")),
            byte_swap(b,p+4,0xa641,2),
            byte_swap(b,p+4,0xa64e,2),
            byte_swap(b,q+108,0xffffffff),
            byte_swap(b,q+124,0),
            byte_swap(b,0x400+12,0xfffffff0),
            byte_swap(b,0x440,0xffffffffffffffe0,8),
            byte_swap(b,0x400+16,0),
            byte_swap(b,0x400+12,0),
            byte_swap(b,0x400+0,0xffffffff),
        ]
        for i,case in enumerate(mutants):
            with self.subTest(mutant=i),self.assertRaises(ValueError):
                discover(case,PLAN)

def byte_swap(data,at,value,width=4):
    x=bytearray(data)
    x[at:at+width]=value.to_bytes(width,"little")
    return bytes(x)

if __name__=="__main__":
    unittest.main()
