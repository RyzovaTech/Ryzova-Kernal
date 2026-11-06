# SPDX-License-Identifier: AGPL-3.0-only
"""MAC-3A dependency inventory: never link/resolve/load a guest dylib."""
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
C=ROOT/"ryzova/compat/macos"
BASE=0x100000000
MAX_IMAGE=4*1024*1024


def string_command(opcode,name,header=24):
    name=name if isinstance(name,bytes) else name.encode("ascii")
    size=(header+len(name)+1+7)&~7
    raw=bytearray(size)
    struct.pack_into("<II",raw,0,opcode,size)
    struct.pack_into("<I",raw,8,header)
    raw[header:header+len(name)]=name
    return bytes(raw)


def program(commands=None,*,dylib=False):
    segment=struct.pack("<II16sQQQQIIII",0x19,72,
                        b"__TEXT".ljust(16,bytes(1)),BASE,4096,0,4096,5,5,0,0)
    rest=list(commands or ())
    if not dylib:
        rest.insert(0,struct.pack("<IIQQ",0x80000028,24,0x300,0))
    commands=[segment,*rest]
    packed=b"".join(commands)
    if 32+len(packed)>=0x300:
        raise ValueError("synthetic command region must precede text")
    data=bytearray(4096)
    struct.pack_into("<8I",data,0,0xfeedfacf,0x01000007,3,
                     6 if dylib else 2,len(commands),len(packed),0,0)
    data[32:32+len(packed)]=packed
    data[0x300]=0xc3
    return data


class Mach3MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.dir=Path(cls.temp.name)
        cls.probe=cls.dir/"mac3meta"
        cc=os.environ.get("PHASE5_CC","cc")
        args=[cc,"-std=c11","-O1","-Wall","-Wextra","-Werror","-pedantic"]
        if os.environ.get("PHASE5_SANITIZE")=="1":
            args+=["-fsanitize=undefined","-fno-sanitize-recover=all"]
        args.extend([str(C/"macho_link_meta.c"),
                     str(C/"macho_link_meta_probe.c"),
                     "-o",str(cls.probe)])
        result=subprocess.run(args,capture_output=True,text=True,timeout=40)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_scan(self,data):
        file=self.dir/"manifest-test.macho"
        file.write_bytes(data)
        return subprocess.run([str(self.probe),str(file)],
                              capture_output=True,text=True,timeout=8)

    def accepted(self,data,expect=None):
        r=self.run_scan(data)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn("MAC3_METADATA status=0",r.stdout)
        self.assertIn("native_guest=0 dylib_loading=0 symbol_resolution=0",r.stdout)
        if expect:self.assertIn(expect,r.stdout)
        return r

    def denied(self,data):
        r=self.run_scan(data)
        self.assertEqual(r.returncode,2,r.stdout+r.stderr)
        self.assertIn("MAC3_METADATA status=",r.stdout)
        self.assertIn("native_guest=0 dylib_loading=0 symbol_resolution=0",r.stdout)

    def test_static_main_without_dependencies_is_metadata_only(self):
        self.accepted(program(), "dependencies=0 rpaths=0 dyld=0")

    def test_libsystem_dependencies_and_inert_dyld_path(self):
        commands=[
            string_command(0x0c,"/usr/lib/libSystem.B.dylib"),
            string_command(0x0c,"@rpath/libRyzova.dylib"),
            string_command(0x0e,"/usr/lib/dyld",12),
            string_command(0x8000001c,"@loader_path/Frameworks",12),
        ]
        result=self.accepted(program(commands),"dependencies=2 rpaths=1 dyld=1")
        self.assertIn("MAC3_DEP 0 /usr/lib/libSystem.B.dylib",result.stdout)
        self.assertIn("MAC3_DEP 1 @rpath/libRyzova.dylib",result.stdout)
        self.assertIn("MAC3_RPATH 0 @loader_path/Frameworks",result.stdout)
        self.assertIn("MAC3_DYLD /usr/lib/dyld",result.stdout)

    def test_dylib_must_have_install_name(self):
        good=program([string_command(0x0d,"@rpath/libFixture.dylib")],dylib=True)
        self.accepted(good,"MAC3_INSTALL_NAME @rpath/libFixture.dylib")
        self.denied(program([],dylib=True))
        self.denied(program([string_command(0x0d,"@rpath/libFixture.dylib"),
                             string_command(0x0d,"@rpath/libFixture2.dylib")],
                            dylib=True))
        self.denied(program([string_command(0x0d,"@rpath/libFixture.dylib")],
                            dylib=False))

    def test_reject_duplicate_dependencies_and_rpaths(self):
        dep=string_command(0x0c,"@rpath/libFixture.dylib")
        path=string_command(0x8000001c,"@loader_path/Frameworks",12)
        self.denied(program([dep,dep]))
        self.denied(program([path,path]))

    def test_paths_are_inert_allowlisted_nontraversing_ascii(self):
        invalid=[
            "/tmp/attack.dylib","../../host", "/usr/lib/../evil.dylib",
            "@rpath/../host", "@loader_path/./foo",
            "@executable_path//bad", "@rpath/", "/usr/lib/",
            "@rpath/lib spaces.dylib","@rpath/back\\slash",
            "@rpath/lib\x01bad", "@rpath/bad\x7fname",
        ]
        for path in invalid:
            with self.subTest(path=path):
                self.denied(program([string_command(0x0c,path)]))
        self.accepted(program([string_command(0x0c,
                            "/System/Library/Frameworks/Security.framework/Security")]))

    def test_reject_alternate_dyld_host_paths_and_unsafe_commands(self):
        self.denied(program([string_command(0x0e,"/usr/lib/other-dyld",12)]))
        self.denied(program([string_command(0x0e,"/usr/lib/dyld",12),
                             string_command(0x0e,"/usr/lib/dyld",12)]))
        for command in (0x1d,0x80000022,0x80000034,0x2,0xb,0x8000001f):
            with self.subTest(command=command):
                self.denied(program([struct.pack("<II",command,8)]))

    def test_malformed_load_command_size_offset_nul_and_bounds(self):
        valid=program([string_command(0x0c,"/usr/lib/libSystem.B.dylib")])
        index=32+72+24
        x=bytearray(valid)
        struct.pack_into("<I",x,index,9999)
        self.denied(x)
        x=bytearray(valid)
        struct.pack_into("<I",x,32+72+4,9)
        self.denied(x)
        x=bytearray(valid)
        command_base=32+72+24  # Segment + LC_MAIN precede LC_LOAD_DYLIB.
        size=struct.unpack_from("<I",x,command_base+4)[0]
        # Overwrite the *entire* dylib-name payload including padding so
        # there is no NUL terminator inside this load command.
        x[command_base+24:command_base+size]=b"A"*(size-24)
        self.denied(x)
        self.denied(valid[:110])

    def test_cpu_filetype_permissions_and_resource_budgets(self):
        x=program()
        for offset,value in ((4,0x0100000c),(8,8),(12,1),
                             (28,0xffffffff),(32+72-16,7),
                             (32+72-12,7)):
            with self.subTest(offset=offset):
                bad=bytearray(x)
                struct.pack_into("<I",bad,offset,value)
                self.denied(bad)
        too=bytearray(program())
        too.extend(bytes(MAX_IMAGE+1-len(too)))
        f=self.dir/"oversize.macho"
        f.write_bytes(too)
        r=subprocess.run([str(self.probe),str(f)],capture_output=True,text=True)
        self.assertEqual(r.returncode,65)

    def test_overlapping_segments_and_unmapped_executable_entry_denied(self):
        valid=program([string_command(0x0c,"/usr/lib/libSystem.B.dylib")])
        bad=bytearray(valid)
        # LC_MAIN entry offset beyond file-backed RX segment.
        struct.pack_into("<Q",bad,32+72+8,0x2000)
        self.denied(bad)
        second=struct.pack("<II16sQQQQIIII",0x19,72,
                           b"__COPY".ljust(16,bytes(1)),BASE,4096,
                           0,4096,1,1,0,0)
        self.denied(program([second]))
        # Two RX mappings backed by the same entry bytes are ambiguous,
        # regardless of whether their virtual address ranges overlap.
        alias=struct.pack("<II16sQQQQIIII",0x19,72,
                          b"__ALIAS".ljust(16,bytes(1)),BASE+4096,4096,
                          0,4096,5,5,0,0)
        self.denied(program([alias]))

    def test_deterministic_mutations_never_crash_host(self):
        rng=random.Random(0x4d414333)
        source=program([string_command(0x0c,"/usr/lib/libSystem.B.dylib")])
        for case in range(128):
            test=bytearray(source)
            for _ in range(1+rng.randrange(4)):
                index=rng.randrange(0,400)
                test[index]=rng.randrange(256)
            with self.subTest(case=case):
                r=self.run_scan(test)
                self.assertIn(r.returncode,(0,2),r.stdout+r.stderr)
                self.assertIn("native_guest=0 dylib_loading=0",r.stdout)


if __name__=="__main__":
    unittest.main()
