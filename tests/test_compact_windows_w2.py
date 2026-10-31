# SPDX-License-Identifier: AGPL-3.0-only
"""Execution and adversarial admission tests for a finite Windows AMD64 subset."""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / 'tests')]
from compact_windows_w2 import pe, fixtures, build, execute, qualify_reference, PREFERRED
from compact_windows_w1 import variants

class Section(C.Structure):
    _fields_ = [(n, C.c_uint32) for n in ('rva', 'size', 'raw', 'bytes', 'permissions')]
class Plan(C.Structure):
    _fields_ = [('preferred_base', C.c_uint64), ('base', C.c_uint64)] + [(n, C.c_uint32) for n in ('image_bytes', 'headers', 'entry', 'count', 'reloc_rva', 'reloc_bytes')] + [('sections', Section * 16)]
class Machine(C.Structure):
    _fields_ = [('plan', Plan), ('image', C.c_void_p), ('stack', C.c_void_p), ('stack_base', C.c_uint64), ('initial_sp', C.c_uint64), ('r', C.c_uint64 * 16), ('ip', C.c_uint64), ('flags', C.c_uint64), ('xmm', (C.c_ubyte * 16) * 16), ('instructions', C.c_uint32), ('exit_code', C.c_uint32), ('exited', C.c_int), ('status', C.c_int)]

class WindowsW2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.probe = build(cls.directory / 'probe', sanitize=True)
        library = cls.directory / 'runtime.so'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-O2', '-shared', '-fPIC', '-fsanitize=undefined', '-fno-sanitize-recover=all', *[str(ROOT / 'ryzova/compat/windows' / x) for x in ('loader.c', 'cpu.c')], '-o', str(library)], check=True)
        cls.lib = C.CDLL(str(library))
        cls.lib.cw_plan.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64, C.POINTER(Plan)]
        cls.lib.cw_load.argtypes = [C.c_void_p, C.c_size_t, C.c_uint64, C.c_void_p, C.c_size_t, C.POINTER(Machine)]
        cls.lib.cw_read.argtypes = [C.POINTER(Machine), C.c_uint64, C.c_void_p, C.c_size_t, C.c_uint]
        cls.lib.cw_write.argtypes = [C.POINTER(Machine), C.c_uint64, C.c_void_p, C.c_size_t]
        cls.lib.cw_run.argtypes = [C.POINTER(Machine), C.c_uint32]
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    def run_pe(self, blob, base=0, budget=1000):
        path = self.directory / 'case.exe';path.write_bytes(blob)
        return execute(self.probe, path, base, budget)
    def admitted(self, blob, base=0):
        plan = Plan();status = self.lib.cw_plan(blob, len(blob), base, C.byref(plan))
        return status, plan
    def loaded(self, blob, base=0):
        status, plan = self.admitted(blob, base);self.assertEqual(status, 0)
        arena = C.create_string_buffer(plan.image_bytes + 65536)
        machine = Machine()
        self.assertEqual(self.lib.cw_load(blob, len(blob), base, arena, len(arena), C.byref(machine)), 0)
        return machine, arena
    def mutate(self, offset, fmt, value, blob=None):
        data = bytearray(blob or pe(b'\xc3'))
        struct.pack_into('<' + fmt, data, offset, *(value if isinstance(value, tuple) else (value,)))
        return bytes(data)
    def denied(self, blob, base=0):
        status, _ = self.admitted(blob, base);self.assertNotEqual(status, 0)
        arena = C.create_string_buffer(b'A' * 131072);before = arena.raw;machine = Machine()
        self.assertNotEqual(self.lib.cw_load(blob, len(blob), base, arena, len(arena), C.byref(machine)), 0)
        self.assertEqual(arena.raw, before);self.assertFalse(machine.image);self.assertEqual(machine.instructions, 0)
    def test_full_unsigned_dword_exit_not_linux_byte_exit(self):
        result = self.run_pe(fixtures()['exit32']);self.assertEqual(result['status'], 0);self.assertEqual(result['exit_code'], 0xFEDCBA98);self.assertEqual(result['instructions'], 2)
    def test_all_six_w1_variants_are_denied_by_execution_admission(self):
        for name, blob in variants().items():
            with self.subTest(name=name): self.denied(blob)
    def test_windows_profile_fields_checked_independently(self):
        for offset, fmt, value in [(0x98+68,'H',2),(0x98+24,'Q',PREFERRED+1),(0x98+24,'Q',0x8000000000000000),(0x98+60,'I',0),(0x188+20,'I',0),(0x98+112+13*8,'II',(0x1000,8)),(0x84,'H',0xAA64),(0x98,'H',0x10B),(0x96,'H',0x2022),(0x96,'H',0)]:
            with self.subTest(offset=offset,value=value):self.denied(self.mutate(offset,fmt,value))
    def test_truncation_and_file_size_fail_before_arena_write(self):
        blob=pe(b'\xc3')
        for size in (0,1,63,64,0x80,0x98,0x187,511,len(blob)-1):self.denied(blob[:size])
        self.denied(blob+bytes(4*1024*1024))
    def test_all_unsupported_data_directories_fail_closed(self):
        for i in range(16):
            if i!=5:self.denied(self.mutate(0x98+112+i*8,'II',(0x1000,8)))
        self.denied(self.mutate(0x98+108,'I',17))
        self.denied(self.mutate(0x98+112+5*8,'II',(0x1000,0)))
    def test_header_alignment_and_overflow(self):
        for offset, value in [(60,0xFFFFFFF0),(0x98+32,512),(0x98+36,1024*128),(0x98+56,0xFFFFFFFF),(0x98+56,64*1024*1024),(0x98+60,513),(0x188+8,0xFFFFFFFF),(0x188+16,0xFFFFFFFF),(0x188+20,0xFFFFFE00)]:self.denied(self.mutate(offset,'I',value))
    def test_entry_must_be_in_backed_executable_virtual_bytes(self):
        for value in (0,0x100,0x1001,0x1100,0x2000):self.denied(self.mutate(0x98+16,'I',value))
        self.denied(self.mutate(0x188+36,'I',0x40000020))
    def test_wx_raw_overlap_and_page_overlap_are_denied(self):
        self.denied(self.mutate(0x188+36,'I',0xE0000020))
        blob=pe(b'\xc3',b'A')
        self.denied(self.mutate(0x188+40+12,'I',0x1000,blob))
        self.denied(self.mutate(0x188+40+20,'I',512,blob))
        self.denied(self.mutate(0x188+12,'I',0,blob))
    def test_relocation_consumed_at_two_actual_load_addresses(self):
        for base in (PREFERRED,PREFERRED+0x40000000,PREFERRED-0x40000000):
            result=self.run_pe(fixtures()['relocated'],base);self.assertEqual(result['status'],0);self.assertEqual(result['exit_code'],0x12345678);self.assertEqual(result['base'],base)
    def test_rebase_without_relocations_and_bad_load_addresses_denied(self):
        for base in (PREFERRED+65536,1,PREFERRED+1,0x8000000000000000,0xFFFFFFFFFFFF0000):self.denied(pe(b'\xc3'),base)
    def test_relocation_type_duplicates_bounds_and_self_patch_denied(self):
        blob=fixtures()['relocated'];raw=1536
        for offset,fmt,value in [(raw+4,'I',6),(raw+4,'I',0xFFFFFFFC),(raw,'I',0x2001),(raw+8,'H',0x3000),(raw+8,'H',0xAFFF),(raw+10,'H',0xA000),(0x98+112+5*8,'II',(0x3000,513)),(0x96,'H',0x23)]:
            self.denied(self.mutate(offset,fmt,value,blob),PREFERRED+65536)
        self.denied(pe(b'\xc3',struct.pack('<Q',PREFERRED),[(0x3000,10)]),PREFERRED+65536)
    def test_header_code_stack_guards_and_gap_permissions(self):
        machine,arena=self.loaded(pe(b'\xc3',b'A'));out=C.create_string_buffer(8)
        self.assertEqual(self.lib.cw_read(C.byref(machine),PREFERRED,out,2,1),0)
        self.assertNotEqual(self.lib.cw_write(C.byref(machine),PREFERRED,b'AA',2),0)
        self.assertNotEqual(self.lib.cw_write(C.byref(machine),PREFERRED+0x1000,b'A',1),0)
        self.assertNotEqual(self.lib.cw_read(C.byref(machine),PREFERRED,out,1,4),0)
        self.assertNotEqual(self.lib.cw_read(C.byref(machine),machine.stack_base,out,1,4),0)
        for at in (PREFERRED+0x1500,machine.stack_base-1,machine.stack_base+65536,0xFFFFFFFFFFFFFFFF):self.assertNotEqual(self.lib.cw_read(C.byref(machine),at,out,1,1),0)
        self.assertNotEqual(self.lib.cw_read(C.byref(machine),PREFERRED,out,1,0),0)
        self.assertTrue(arena)
    def test_bss_zero_fill_and_writable_data(self):
        machine,arena=self.loaded(pe(b'\xc3',b'A'));out=C.create_string_buffer(8)
        self.assertEqual(self.lib.cw_read(C.byref(machine),PREFERRED+0x2200,out,8,1),0);self.assertEqual(out.raw,bytes(8))
        self.assertEqual(self.lib.cw_write(C.byref(machine),PREFERRED+0x2200,b'12345678',8),0)
        self.assertEqual(self.lib.cw_read(C.byref(machine),PREFERRED+0x2200,out,8,1),0);self.assertEqual(out.raw,b'12345678');self.assertTrue(arena)
    def test_small_arena_and_uninitialized_machine_cannot_run(self):
        blob=pe(b'\xc3');arena=C.create_string_buffer(b'X'*10);machine=Machine()
        self.assertNotEqual(self.lib.cw_load(blob,len(blob),0,arena,len(arena),C.byref(machine)),0);self.assertEqual(arena.raw,b'X'*10+b'\0')
        self.assertNotEqual(self.lib.cw_run(C.byref(Machine()),100),0)
    def test_budget_syscall_privileged_and_unsupported_instructions_fail(self):
        result=self.run_pe(fixtures()['loop'],budget=31);self.assertEqual(result['status'],8);self.assertEqual(result['instructions'],31);self.assertFalse(result['exited'])
        for code in (b'\x0f\x05',b'\x0f\x34',b'\xf4',b'\xcc',b'\xf0\x90',b'\xf3\x0f\xb6\xc0',b'\x0f\x0b'):
            self.assertEqual(self.run_pe(pe(code))['status'],7)
    def test_code_cannot_write_text_execute_data_or_escape_return(self):
        for code in (b'\xc6\x05\xf9\xff\xff\xff\x90', b'\x48\xb8'+struct.pack('<Q',PREFERRED+0x2000)+b'\xff\xe0', b'\x48\xb8'+struct.pack('<Q',0xFFFFFFFFFFFFFFFF)+b'\xff\xe0'):
            result=self.run_pe(pe(code,b'\xc3'));self.assertNotEqual(result['status'],0);self.assertFalse(result['exited'])
    def test_win64_shadow_space_alignment_four_register_args_and_stack_arg(self):
        # Caller allocates shadow+fifth-arg space. Callee consumes RCX/RDX/R8/R9
        # and [rsp+40], and writes all four home slots inside the shadow space.
        caller=bytes.fromhex('4883ec28 b901000000 ba02000000 41b803000000 41b904000000 48c744242005000000')
        callee=bytes.fromhex('48894c2408 4889542410 4c89442418 4c894c2420 4889e0 83e00f 83f808 7515 89c8 01d0 4401c0 4401c8 03442428 c3 b8ffffffff c3')
        # branch displacement corrected to failure label (next instruction+13).
        callee=callee.replace(bytes.fromhex('7515'),bytes.fromhex('750e'))
        code=caller+b'\xe8'+struct.pack('<i',5)+bytes.fromhex('4883c428c3')+callee
        result=self.run_pe(pe(code));self.assertEqual(result['status'],0,result);self.assertEqual(result['exit_code'],15,result)
    def test_nonvolatile_gpr_and_xmm_state_survive_save_restore(self):
        code=bytes.fromhex('53 4883ec10 f30f7f3424 660feff6 f30f6f3424 4883c410 bb01000000 5b b825000000 c3')
        result=self.run_pe(pe(code));self.assertEqual(result['status'],0,result);self.assertTrue(result['nonvolatile_preserved']);self.assertEqual(result['exit_code'],37)
        self.assertEqual(self.run_pe(pe(bytes.fromhex('bb01000000c3')))['status'],9)
    def test_every_windows_nonvolatile_register_can_be_saved_and_restored(self):
        regs=(3,5,6,7,12,13,14,15)
        code=bytearray()
        for r in regs:code += (b'\x41' if r>=8 else b'')+bytes([0x50+(r&7)])
        code += bytes.fromhex('4881eca0000000')
        for r in range(6,16):
            disp=(r-6)*16
            mem=bytes([0x44|((r&7)<<3),0x24,disp]) if disp<128 else bytes([0x84|((r&7)<<3),0x24])+struct.pack('<I',disp)
            rex=b'\x44' if r>=8 else b''
            code += b'\xf3'+rex+b'\x0f\x7f'+mem
            code += b'\x66'+(b'\x45' if r>=8 else b'')+b'\x0f\xef'+bytes([0xC0|((r&7)<<3)|(r&7)])
            code += b'\xf3'+rex+b'\x0f\x6f'+mem
        for r in regs:code += (b'\x41' if r>=8 else b'')+bytes([0xB8+(r&7)])+struct.pack('<I',0)
        code += bytes.fromhex('4881c4a0000000')
        for r in reversed(regs):code += (b'\x41' if r>=8 else b'')+bytes([0x58+(r&7)])
        code += bytes.fromhex('b825000000c3')
        result=self.run_pe(pe(bytes(code)));self.assertEqual(result['status'],0,result);self.assertEqual(result['exit_code'],37)
        self.assertEqual(self.run_pe(pe(bytes.fromhex('66450fefff c3')))['status'],9)

    def test_register_width_high_bytes_flags_and_conditional_branch(self):
        for code,expected in [('48b8ffffffffffffffff b878563412 c3',0x12345678),('31c0 b47f c3',0x7F00),('31c0 b07f 0401 7106 b801000000c3 b802000000c3',1),('31c0 2d01000000 7306 b803000000c3 b804000000c3',3)]:
            result=self.run_pe(pe(bytes.fromhex(code)));self.assertEqual(result['status'],0,result);self.assertEqual(result['exit_code'],expected,result)
    def test_bounded_deterministic_mutation_corpus_has_no_loader_crash(self):
        rng=random.Random(0xC02);original=pe(b'\xb8\x25\0\0\0\xc3',b'A')
        for _ in range(400):
            blob=bytearray(original)
            for _ in range(rng.randint(1,4)):blob[rng.randrange(len(blob))]=rng.randrange(256)
            self.admitted(bytes(blob))
    def test_reference_comparison_rejects_wrong_source_image_commit_and_fake_result(self):
        image=self.directory/'reference.exe';image.write_bytes(pe(bytes.fromhex('b878563412c3')))
        receipt=self.directory/'reference.json';output=self.directory/'comparison.json'
        native={'schema':'compact-windows-w2-reference/v1','executable_sha256':hashlib.sha256(image.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256((ROOT/'tests/fixtures/windows_w2_reference.c').read_bytes()).hexdigest(),'source_commit':'a'*40,'native_reference_passed':True,'exit_code':0x12345678,'architecture':'X64','stdout':'','stderr':''}
        with patch.dict(os.environ,{'GITHUB_SHA':'a'*40}):
            receipt.write_text(json.dumps(native));self.assertTrue(qualify_reference(self.probe,image,receipt,output)['reference_match'])
            for key,value in [('source_commit','b'*40),('executable_sha256','0'*64),('source_sha256','0'*64),('exit_code',37),('architecture','Arm64'),('native_reference_passed',False),('stdout','forged')]:
                bad=dict(native);bad[key]=value;receipt.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):qualify_reference(self.probe,image,receipt,output)
            receipt.write_text(json.dumps(native));image.write_bytes(pe(bytes.fromhex('b825000000c3')))
            with self.assertRaises(ValueError):qualify_reference(self.probe,image,receipt,output)

if __name__=='__main__':unittest.main()
