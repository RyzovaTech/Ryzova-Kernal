# SPDX-License-Identifier: AGPL-3.0-only
"""CLX-02 root profile: real guest syscalls, restart and trust-boundary tests."""
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase9_process import FLAGS
from test_phase9_persistence import records, seal
from phase9_shell import DIGEST
import phase9_rootfs as gate


class RootFilesystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        core = ROOT / 'ryzova/compat/linux'
        cls.sources = [str(core / (n + '.c')) for n in
                       ('elf64', 'namespace', 'syscall', 'subset_vm', 'memory', 'process', 'cpu', 'jobs', 'jobs_probe')]
        cls.flags = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                     '-fsanitize=undefined', '-fno-sanitize-recover=all']
        cls.runner, cls.fixture = cls.directory / 'runner', cls.directory / 'fixture'
        subprocess.run([*cls.flags, *cls.sources, '-o', str(cls.runner)], check=True, capture_output=True)
        subprocess.run(['cc', *FLAGS, str(ROOT / 'tests/fixtures/compact_process_start.S'),
                        str(ROOT / 'tests/fixtures/compact_rootfs.c'), '-o', str(cls.fixture)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def guest(self, mode, *flags, root=True, runner=None, env=None):
        return subprocess.run([str(runner or self.runner), *(['-r'] if root else []),
                               *map(str, flags), str(self.fixture), mode, 'root-challenge'],
                              env=env, capture_output=True, timeout=20)

    def check(self, mode, *flags, **kwargs):
        result = self.guest(mode, *flags, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'FLEX_ROOTFS_OK {mode}\nroot-challenge\n'.encode())
        return result

    def test_full_root_tree_metadata_links_and_independent_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory) / 'first', Path(directory) / 'second'
            self.check('create', '-W', a)
            original = a.read_bytes()
            self.assertEqual(original[:8], b'FLEXFS4\n')
            self.assertEqual(a.stat().st_mode & 0o777, 0o600)
            self.check('reload', '-R', a, '-W', b)
            self.check('reload', '-R', b)
            self.assertEqual(a.read_bytes(), original)
            self.check('fresh')

    def test_cwd_dirfd_root_directory_and_cross_directory_rename(self):
        self.check('cwd')

    def test_fork_shares_environment_tree(self):
        self.check('fork')

    def test_guest_paths_and_links_cannot_acquire_host_authority(self):
        self.check('deny')

    def test_legacy_layout_and_snapshot_profile_cannot_be_silently_reinterpreted(self):
        with tempfile.TemporaryDirectory() as directory:
            legacy, root = Path(directory) / 'legacy', Path(directory) / 'root'
            self.check('legacy', '-W', legacy, root=False)
            self.assertEqual(legacy.read_bytes()[:8], b'FLEXFS2\n')
            self.check('legacy', '-R', legacy, root=False)
            self.check('fresh', '-W', root)
            for path, profile in ((legacy, True), (root, False)):
                result = self.guest('fresh', '-R', path, root=profile)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b'status=1 ', result.stderr)
                self.assertEqual(result.stdout, b'')

    def test_corrupt_topology_and_reserved_namespace_shadowing_fail_before_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            good, bad, out = (Path(directory) / n for n in ('good', 'bad', 'out'))
            self.check('create', '-W', good)
            data = good.read_bytes()
            offsets = records(data)
            etc = next(at for at in offsets if data[at+80:at+83] == b'etc')
            mutations = [(etc + 80, b'dev'), (etc + 4, struct.pack('<I', 2)),
                         (offsets[0] + 80, b'nope'), (etc + 12, struct.pack('<I', 4)),
                         (0, b'FLEXFS3\n')]
            for at, value in mutations:
                changed = bytearray(data)
                changed[at:at+len(value)] = value
                bad.write_bytes(seal(changed))
                result = self.guest('fresh', '-R', bad, '-W', out)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b'status=1 ', result.stderr)
                self.assertEqual(result.stdout, b'')
                self.assertFalse(out.exists())

    def test_export_never_overwrites_existing_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state'
            path.write_bytes(b'keep-original')
            result = self.guest('create', '-W', path)
            self.assertEqual(result.returncode, 65, result.stderr)
            self.assertEqual(path.read_bytes(), b'keep-original')

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'), 'set COMPACT_SHELL_DIR to pinned BusyBox fixture')
    def test_unmodified_busybox_early_project_file_probe(self):
        busybox = (ROOT / os.environ['COMPACT_SHELL_DIR'] / 'busybox').resolve()
        self.assertEqual(hashlib.sha256(busybox.read_bytes()).hexdigest(), DIGEST)
        script = self.directory / 'script'
        script.write_bytes(gate.SCRIPT)
        result = subprocess.run([str(self.runner), '-r', '-b', '4194304', '-x', '/busybox=' + str(busybox),
                                 '-i', str(script), str(busybox), 'ash', '/input'], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'int main(void){return 0;}\nFLEX_ROOTFS_BUSYBOX_OK\n')

    def test_native_evidence_requires_restart_challenges_failures_and_fixture_digests(self):
        commit, digest = 'a' * 40, 'b' * 64
        lines = [digest + '  /tmp/rf-elf', digest + '  /tmp/rf-script']
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in
                  range(gate.start(commit), gate.start(commit) + len(gate.commands(commit)) - 1)]
        lines += ['FLEX_ROOTFS_BEGIN']
        clean = 'COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        for mode in gate.CASES:
            lines += ['FLEX_ROOTFS_OK ' + mode, f'R_{mode}_{commit}', clean, f'FLEX_ROOTFS_{mode}_RUN_OK']
        for mode, marker in (('create', 'SAVE'), ('reload', 'RELOAD')):
            lines += ['FLEX_ROOTFS_OK ' + mode, 'R_saved_' + commit, clean, f'FLEX_ROOTFS_{marker}_OK']
        for marker in ('PROFILE', 'CORRUPT'):
            lines += ['COMPACT_LINUX_RESULT status=1 exited=0 exit=0 steps=0 syscalls=0', f'FLEX_ROOTFS_{marker}_DENIED']
        lines += ['int main(void){return 0;}', 'FLEX_ROOTFS_BUSYBOX_OK', clean,
                  'FLEX_ROOTFS_SHELL_RUN_OK', 'FLEX_ROOTFS_END', 'FLEX_ROOTFS_DONE']
        serial = ('\n'.join(lines) + '\n').encode()
        digests = {'rootfs.elf': digest, 'rootfs-script': digest}
        evidence = gate.inspect(serial, commit, digests)
        self.assertTrue(evidence['passed'])
        self.assertFalse(evidence['phase_complete'])
        for token in ('FLEX_ROOTFS_DONE', 'FLEX_ROOTFS_RELOAD_OK', 'R_deny_' + commit,
                      'FLEX_ROOTFS_BUSYBOX_OK', 'FLEX_ROOTFS_PROFILE_DENIED', digest):
            self.assertFalse(gate.inspect(serial.replace(token.encode(), b'MISSING'), commit, digests)['passed'])
        self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10', b'exit=1 steps=10', 1), commit, digests)['passed'])
        self.assertTrue(all(len(command) < 220 for command in gate.commands(commit)))

    def test_address_and_undefined_sanitizers(self):
        runner = self.directory / 'asan'
        subprocess.run([*self.flags, '-fsanitize=address,undefined', '-no-pie',
                        *self.sources, '-o', str(runner)], check=True, capture_output=True)
        env = dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN') == '1':
            env['ASAN_OPTIONS'] = 'detect_leaks=0:quarantine_size_mb=32'
        for mode in ('create', 'cwd', 'fork', 'deny', 'fresh'):
            self.check(mode, runner=runner, env=env)


if __name__ == '__main__':
    unittest.main()
