# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded guest PTY vs real host Linux PTY; raw mode only.

The native Ryzova OS PTY/terminal, real process job control, canonical
mode, signals and physical device qualifications remain separate gates.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CORE=ROOT/'ryzova/compat/linux'
SOURCES=[CORE/(x+'.c') for x in ('elf64','namespace','syscall','subset_vm','memory','process','cpu','jobs','jobs_probe')]

class GuestPtyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='ryz-clx06-')
        cls.root=Path(cls.temp.name)
        cls.runner=cls.root/'jobs_probe'
        cls.guest=cls.root/'pty.elf'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        *map(str,SOURCES),'-o',str(cls.runner)],
                       capture_output=True,check=True,timeout=120)
        subprocess.run(['cc','-nostdlib','-no-pie','-static',
                        str(ROOT/'tests/fixtures/compact_process_start.S'),
                        str(ROOT/'tests/fixtures/compact_pty.c'),
                        '-o',str(cls.guest)],capture_output=True,check=True,timeout=40)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_guest(self,mode):
        return subprocess.run([str(self.runner),str(self.guest),mode,'challenge'],
                              capture_output=True,timeout=25)

    def run_native(self,mode):
        return subprocess.run([str(self.guest),mode,'challenge'],
                              capture_output=True,timeout=25)

    def test_linux_differential_master_slave_unlock_raw_termios_winsize(self):
        host=self.run_native('raw')
        guest=self.run_guest('raw')
        self.assertEqual(host.returncode,0,host.stderr)
        self.assertEqual(guest.returncode,0,guest.stderr)
        self.assertEqual(host.stdout,b'FLEX_PTY_RAW_OK\n')
        self.assertEqual(guest.stdout,host.stdout)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',guest.stderr)

    def test_guest_locked_slave_and_bad_ioctl_denied_without_host_forward(self):
        result=self.run_guest('deny')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b'COMPACT_JOBS_RESULT status=0 exited=1 exit=0',result.stderr)

    def test_bounded_namespace_pty_implementation_retains_release_denials(self):
        source=(CORE/'syscall_pty.h').read_text()
        self.assertIn('RYZ_PTY_TOTAL_BYTES',source)
        self.assertIn('RYZ_NS_PTY_MASTER',source)
        self.assertIn('RYZ_NS_PTY_SLAVE',source)
        self.assertIn('pty->namespace_id!=p->ns.namespace_id',source)
        self.assertIn('return -95;',source)
        plan=__import__('json').loads((ROOT/'ryzova/compact/linux-v1-plan.json').read_text())
        req={r['id']:r for r in plan['requirements']}
        self.assertNotEqual(req['TTY-JOBS']['state'],'passed')
        self.assertNotEqual(req['INSTALL-RECOVERY']['state'],'passed')


if __name__=='__main__':
    unittest.main()
