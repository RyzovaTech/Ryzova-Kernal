# SPDX-License-Identifier: AGPL-3.0-only
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase9_busybox import FIXTURES, verify, inspect, commands


class BusyboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        c = ROOT / 'ryzova/compat/linux'
        cls.runner = cls.directory / 'runner'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                        '-fsanitize=undefined', '-fno-sanitize-recover=all',
                        *[str(c / (n + '.c')) for n in ('elf64', 'namespace', 'syscall', 'subset_vm', 'memory', 'process', 'cpu', 'process_probe')],
                        '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def vm(self, binary, *args):
        return subprocess.run([str(self.runner), str(binary), *args], capture_output=True, timeout=10)

    def assemble(self, body, capacity=4096):
        source = self.directory / 'probe.S'
        binary = self.directory / 'probe'
        source.write_text('.global _start\n.text\n_start:\nlea output(%rip),%r12\n' + body +
                          '\nmov %r12,%rdx\nlea output(%rip),%rsi\nsub %rsi,%rdx\nmov $1,%eax\nmov $1,%edi\nsyscall\nmov $60,%eax\nxor %edi,%edi\nsyscall\n.bss\n.align 16\noutput: .skip ' + str(capacity) + '\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['cc', '-nostdlib', '-static', '-no-pie', '-Wl,--build-id=none', str(source), '-o', str(binary)], check=True, capture_output=True)
        return binary

    def same(self, body):
        binary = self.assemble(body)
        linux = subprocess.run([str(binary)], capture_output=True, timeout=5)
        vm = self.vm(binary)
        self.assertEqual(linux.returncode, 0, linux.stderr)
        self.assertEqual(vm.returncode, 0, vm.stderr)
        self.assertEqual(vm.stdout, linux.stdout)

    def test_adc_sbb_multiply_flags_match_cpu(self):
        rng = random.Random(953)
        values = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
        values += [rng.getrandbits(64) for _ in range(8)]
        body = []
        for op in ('adc', 'sbb', 'imul'):
            for i, a in enumerate(values):
                for carry in (0, 1):
                    b = values[(i + carry + 3) % len(values)]
                    body += [f'movabs ${a},%rax', f'movabs ${b},%rbx', 'xor %edi,%edi', f'cmp ${carry},%edi',
                             f'{op} %rbx,%rax', 'mov %rax,(%r12)', 'setc 8(%r12)', 'seto 9(%r12)']
                    # Other IMUL flags are architecturally undefined.
                    if op != 'imul':
                        body += ['sete 10(%r12)', 'sets 11(%r12)', 'setp 12(%r12)']
                    body += ['add $16,%r12']
        self.same('\n'.join(body))

    def test_division_signed_unsigned_widths(self):
        body = []
        for op in ('div', 'idiv'):
            for a, b in ((12345, 7), (0, 1), (2**63 - 1, 31), (2**64 - 17, 7)):
                body += [f'movabs ${a},%rax', f'mov ${b},%rbx', 'cqo' if op == 'idiv' else 'xor %edx,%edx',
                         f'{op} %rbx', 'mov %rax,(%r12)', 'mov %rdx,8(%r12)', 'add $16,%r12']
        self.same('\n'.join(body))
        for setup in ('xor %ebx,%ebx', 'mov $1,%ebx\nmov $1,%edx'):
            vm = self.vm(self.assemble('xor %eax,%eax\nxor %edx,%edx\n' + setup + '\ndiv %rbx'))
            self.assertEqual(vm.returncode, 2)
            self.assertIn(b'status=6', vm.stderr)

    def test_rep_and_vector_copy_match_cpu(self):
        self.same('mov %r12,%rdi\nmov $0x12345678,%eax\nmov $8,%ecx\nrep stosl\n'
                  'movups (%r12),%xmm0\nmovups %xmm0,32(%r12)\n'
                  'mov %r12,%rsi\nlea 48(%r12),%rdi\nmov $16,%ecx\nrep movsb\nadd $64,%r12')
        vm = self.vm(self.assemble('mov %r12,%rdi\nmov $262144,%ecx\nrep stosb', capacity=300000))
        self.assertEqual(vm.returncode, 2)
        self.assertIn(b'status=4', vm.stderr)

    def test_bit_scan_defined_results_and_zero_flag_match_cpu(self):
        for op in ('bsf','bsr'):
            body=[]
            for suffix,src,dst,bits in (('w','%ax','%bx',16),('l','%eax','%ebx',32),('q','%rax','%rbx',64)):
                for value in (1,2,1<<(bits-1),(1<<(bits-1))|1):
                    body += [f'movabs ${value},%rax',f'{op}{suffix} {src},{dst}',
                             'mov %rbx,(%r12)','setz 8(%r12)','add $16,%r12']
                body += ['xor %eax,%eax',f'{op}{suffix} {src},{dst}','setz (%r12)','add $8,%r12']
            self.same('xor %ebx,%ebx\n'+'\n'.join(body))

    def test_virtual_segment_base_and_writev(self):
        # Only interpreted invocation: setting host FS would disrupt native libc startup/cleanup.
        binary = self.assemble('mov %r12,%rsi\nmov $0x1002,%edi\nmov $158,%eax\nsyscall\n'
                              'movq $123,%fs:0\nmov %fs:0,%rax\nmov %rax,8(%r12)\nadd $16,%r12')
        vm = self.vm(binary)
        self.assertEqual(vm.returncode, 0, vm.stderr)
        self.assertEqual(vm.stdout, (123).to_bytes(8, 'little') * 2)
        self.same('movq $0x6261,(%r12)\nlea 64(%r12),%rsi\nmov %r12,(%rsi)\nmovq $2,8(%rsi)\n'
                  'mov $20,%eax\nmov $1,%edi\nmov $1,%edx\nsyscall\n')

    def test_compare_exchange_byte_increment_and_vector_xor_match_cpu(self):
        self.same('movq $7,(%r12)\nmov $7,%eax\nmov $9,%ebx\nlock cmpxchg %rbx,(%r12)\n'
                  'mov %rax,8(%r12)\nsete 16(%r12)\nsetc 17(%r12)\n'
                  'mov $5,%eax\nlock cmpxchg %rbx,(%r12)\nmov %rax,24(%r12)\nsete 32(%r12)\nsetc 33(%r12)\n'
                  'movb $255,40(%r12)\nincb 40(%r12)\nsetc 41(%r12)\nsete 42(%r12)\n'
                  'pxor %xmm0,%xmm0\nmovaps %xmm0,48(%r12)\nxorps %xmm1,%xmm0\nxorpd %xmm0,%xmm1\nmovups %xmm0,64(%r12)\nmovups %xmm1,80(%r12)\nadd $96,%r12')
        for body in ('.byte 0xf0,0x48,0x09,0xc0', '.byte 0xf0,0x90',
                     'movaps 1(%r12),%xmm0'):
            r=self.vm(self.assemble(body))
            self.assertEqual(r.returncode,2)
            self.assertRegex(r.stderr,rb'status=(2|3) ')

    def test_full_multiply_pair_matches_cpu(self):
        body=[]
        for size,register in ((1,'bl'),(2,'bx'),(4,'ebx'),(8,'rbx')):
            bits=(1<<(size*8))-1;sign=1<<(size*8-1)
            for instruction in ('mul','imul'):
                for a,b in ((0,bits),(1,bits),(bits,bits),(sign,2),(sign,sign),(sign-1,sign+1),(123,97)):
                    body += [f'movabs ${a},%rax',f'movabs ${b},%rbx','mov $0x13579bdf,%edx',
                             f'{instruction} %{register}','mov %rax,(%r12)','mov %rdx,8(%r12)',
                             'setc 16(%r12)','seto 17(%r12)','add $24,%r12']
        self.same('\n'.join(body))

    @unittest.skipUnless(os.environ.get('COMPACT_BUSYBOX_DIR'), 'set COMPACT_BUSYBOX_DIR to verified fixture directory')
    def test_unmodified_official_applets_match_linux(self):
        directory = Path(os.environ['COMPACT_BUSYBOX_DIR'])
        cases = {'true': [()], 'echo': [(), ('hello',), ('-n', 'hello', 'world'), ('-e', 'a\\tb'), ('සිංහල',)],
                 'printf': [('%s\\n', 'hello'), ('%d %x\\n', '123', '255'), ('%d\\n', '-17'),
                            ('[%08x] %s\\n', '255', 'සිංහල'), ('%u\\n', '4294967295')]}
        for name, argument_sets in cases.items():
            binary = directory / ('busybox-' + name)
            verify(binary.read_bytes(), name)
            for args in argument_sets:
                with self.subTest(applet=name, args=args):
                    linux = subprocess.run([str(binary), *args], env={'FLEX_MODE': 'test'}, capture_output=True, timeout=5)
                    vm = self.vm(binary, *args)
                    self.assertEqual(linux.returncode, 0, linux.stderr)
                    self.assertEqual(vm.returncode, 0, vm.stderr)
                    self.assertEqual(vm.stdout, linux.stdout)

    def test_native_evidence_rejects_missing_results_and_hashes(self):
        commit = 'a' * 40
        lines = [digest + ' /tmp/bb-' + name for name, (_, digest) in FIXTURES.items()]
        lines += ['FLEX_BUSYBOX_BEGIN', 'BB_' + commit, '123 ff']
        for name in FIXTURES:
            lines += ['COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=799 syscalls=3', 'FLEX_BUSYBOX_' + name.upper() + '_OK']
        lines += ['FLEX_BUSYBOX_END', 'FLEX_BUSYBOX_DONE']
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(68, 79)]
        serial = ('\n'.join(lines) + '\n').encode()
        self.assertTrue(inspect(serial, commit)['passed'])
        for value in (b'BB_' + commit.encode(), b'123 ff', b'FLEX_BUSYBOX_TRUE_OK', FIXTURES['true'][1].encode(), b'RYZOVA_RUNTIME_STAGE_78', b'syscalls=3'):
            self.assertFalse(inspect(serial.replace(value, b'missing'), commit)['passed'])
        with self.assertRaises(ValueError):
            verify(b'wrong-binary', 'true')
        self.assertTrue(all(len(command) < 220 for command in commands(commit)))
