# SPDX-License-Identifier: AGPL-3.0-only
"""Real directory capabilities, independent guest lifetimes and negative authority tests."""
import hashlib
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase9_process import FLAGS
from phase9_shell import DIGEST


class MountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        core = ROOT / 'ryzova/compat/linux'
        cls.sources = [str(core / (n + '.c')) for n in
                       ('elf64', 'namespace', 'syscall', 'subset_vm', 'memory', 'process', 'cpu', 'jobs', 'jobs_probe')]
        cls.flags = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-fsanitize=undefined', '-fno-sanitize-recover=all']
        cls.runner, cls.fixture = cls.directory / 'runner', cls.directory / 'fixture'
        subprocess.run([*cls.flags, *cls.sources, '-o', str(cls.runner)], check=True, capture_output=True)
        subprocess.run(['cc', *FLAGS, str(ROOT / 'tests/fixtures/compact_process_start.S'),
                        str(ROOT / 'tests/fixtures/compact_mounts.c'), '-o', str(cls.fixture)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.backing = tempfile.TemporaryDirectory()
        self.addCleanup(self.backing.cleanup)
        self.path = Path(self.backing.name)

    def guest(self, mode, *flags, rights='rw', runner=None, env=None, preexec_fn=None):
        return subprocess.run([str(runner or self.runner), '-r', '-M', rights + ':/home/share=' + str(self.path),
                               *map(str, flags), str(self.fixture), mode, 'challenge'], capture_output=True,
                              timeout=25, env=env, preexec_fn=preexec_fn)

    def check(self, mode, *flags, expected=None, **kwargs):
        r = self.guest(mode, *flags, **kwargs)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, f'FLEX_MOUNT_OK {expected or mode}\nchallenge\n'.encode())
        return r

    def populate(self):
        self.check('create')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge')
        self.assertEqual((self.path / 'project/source.c').stat().st_mode & 0o777, 0o640)

    def test_project_operations_are_live_and_survive_independent_runtime_restart(self):
        self.populate()
        self.check('reload')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge!')
        self.check('check')

    def test_readonly_mount_and_initial_application_view_cannot_write(self):
        self.populate()
        self.check('readonly', rights='r')
        self.check('readonly', '-A', '@entry:1:0')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge')

    def test_runtime_narrowing_fork_and_reexec_never_restore_authority(self):
        self.populate()
        self.check('views')
        self.check('exec', '-x', '/worker', '-x', '/privileged', '-A', '/worker:1:0',
                   '-A', '/privileged:1:1', expected='again')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge')

    def test_revocation_invalidates_already_open_descriptors(self):
        self.populate()
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'token'
            token.write_text('1')
            self.check('revocation', '-M', 'rw:/var/admin=' + directory, '-K', token)
            self.assertEqual(token.read_text(), '0')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge')

    def test_hidden_mounts_are_filtered_from_parent_directory_listing(self):
        self.populate()
        self.check('hidden')

    def test_separate_mount_nodes_share_the_real_backend_not_a_cached_copy(self):
        self.populate()
        self.check('alias', '-M', 'rw:/var/peer=' + str(self.path))
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'challenge!')

    def test_traversal_links_root_rename_and_oversized_operations_are_denied(self):
        self.populate()
        self.check('denials')
        self.check('permissions')
        self.check('symlink-routes')
        self.check('dir-inodes')
        with tempfile.TemporaryDirectory() as outside:
            (Path(outside) / 'secret').write_text('host-only')
            (self.path / 'escape').symlink_to(outside, target_is_directory=True)
            (self.path / 'leaf').symlink_to(Path(outside) / 'secret')
            self.check('host-links')
            self.assertEqual((Path(outside) / 'secret').read_text(), 'host-only')
        large = self.path / 'large'
        large.write_bytes(b'X' * 65537)
        self.check('oversized')
        self.assertEqual(large.read_bytes(), b'X' * 65537)

    def test_snapshot_contains_no_external_file_data_or_reusable_mount_authority(self):
        state = self.path / 'guest-state'
        self.check('create', '-W', state)
        data = state.read_bytes()
        self.assertNotIn(b'challenge', data)
        r = subprocess.run([str(self.runner), '-r', '-R', str(state), str(self.fixture), 'absent', 'challenge'], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check('readonly', '-R', state, rights='r')

    def test_guest_fault_preserves_completed_live_writes_without_export(self):
        r = self.guest('fault', '-b', '2000')
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(b'status=4 ', r.stderr)
        self.assertEqual((self.path / 'completed').read_bytes(), b'challenge')

    def test_creation_quota_is_finite_and_failure_does_not_create_an_extra_file(self):
        self.check('quota')
        self.assertEqual(len(list(self.path.iterdir())), 32)
        self.assertFalse((self.path / 'full').exists())

    def test_description_duplication_closes_backend_handles_under_low_fd_limit(self):
        self.populate()
        def limit():
            resource.setrlimit(resource.RLIMIT_NOFILE, (48, 48))
        self.check('lifetime', preexec_fn=limit)

    def test_positioned_io_and_truncate_match_actual_backend_content(self):
        self.populate()
        self.check('eof')
        self.check('positioned')
        self.assertEqual((self.path / 'project/source.c').read_bytes(), b'c')

    def test_invalid_mounts_and_policy_inputs_fail_before_guest_mutation(self):
        for flags in (('-M', 'rw:/home/share/sub=' + str(self.path)),
                      ('-M', 'rw:/home/share=' + str(self.path)),
                      ('-M', 'rw:/dev/private=' + str(self.path)),
                      ('-A', '/missing:1:0'), ('-A', '@entry:1:2'),
                      ('-A', '@entry:16:0')):
            with self.subTest(flags=flags):
                r = self.guest('create', *flags)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(r.stdout, b'')
                self.assertFalse((self.path / 'project').exists())

    def test_address_undefined_and_leak_sanitizers(self):
        runner = self.directory / 'asan'
        subprocess.run([*self.flags, '-fsanitize=address,undefined', '-no-pie',
                        *self.sources, '-o', str(runner)], check=True, capture_output=True)
        env = dict(os.environ)
        if os.environ.get('COMPACT_DISABLE_LSAN') == '1':
            env['ASAN_OPTIONS'] = 'detect_leaks=0:quarantine_size_mb=32'
        self.check('create', runner=runner, env=env)
        self.check('views', runner=runner, env=env)
        self.check('lifetime', runner=runner, env=env)

    def test_callback_failures_oversized_replies_and_cleanup_are_atomic(self):
        source = ROOT / 'tests/fixtures/phase9_mount_contract_test.c'
        binary = self.directory / 'contract'
        subprocess.run([*self.flags, '-I', str(ROOT / 'ryzova/compat/linux'), *self.sources[:-1],
                        str(source), '-o', str(binary)], check=True, capture_output=True)
        target = self.path / 'file'
        target.write_bytes(b'original')
        r = subprocess.run([str(binary), str(self.path)], capture_output=True, timeout=20)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b'FS_CALLBACK_CONTRACT_OK\n')
        self.assertEqual(target.read_bytes(), b'original')

    def test_native_gate_rejects_missing_views_recovery_revocation_and_challenges(self):
        import phase9_mounts as gate
        commit, digest = 'a' * 40, 'b' * 64
        lines = [digest + '  /tmp/mt-elf', digest + '  /tmp/mt-script']
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(gate.start(commit), gate.start(commit)+len(gate.commands(commit))-1)]
        lines += ['FLEX_MOUNTS_BEGIN']
        clean = 'COMPACT_LINUX_RESULT status=0 exited=1 exit=0 steps=10 syscalls=10'
        for mode, marker, token in [('create','SAVE','saved'), ('absent','ABSENT_RUN','absent')]+[
            (mode,mode+'_RUN','saved') for mode in gate.CASES]+[
                ('again','EXEC_RUN','saved'), ('readonly','ENTRY_RUN','saved'), ('reload','RESTART_RUN','saved'),
                ('check','CHECK_RUN','saved'), ('quota','QUOTA_RUN','quota'), ('revocation','REVOKE_RUN','revoke')]:
            lines += ['FLEX_MOUNT_OK '+mode, f'Q_{token}_{commit}', clean, f'FLEX_MOUNT_{marker}_OK']
        lines += ['FLEX_MOUNT_HOST_DATA_OK', 'FLEX_MOUNT_LIMIT_OK', 'FLEX_MOUNT_RECOVERY_OK',
                  'COMPACT_LINUX_RESULT status=4 exited=0 exit=0 steps=2000 syscalls=5',
                  'int main(void){return 0;}', 'FLEX_MOUNT_BUSYBOX_OK', clean, 'FLEX_MOUNT_BUSYBOX_RUN_OK',
                  'FLEX_MOUNTS_END', 'FLEX_MOUNTS_DONE']
        serial = ('\n'.join(lines)+'\n').encode()
        digests = {'mounts.elf':digest, 'mounts-script':digest}
        self.assertTrue(gate.inspect(serial,commit,digests)['passed'])
        for token in ('FLEX_MOUNTS_DONE','FLEX_MOUNT_REVOKE_RUN_OK','FLEX_MOUNT_EXEC_RUN_OK',
                      'FLEX_MOUNT_RECOVERY_OK','FLEX_MOUNT_HOST_DATA_OK','Q_saved_'+commit,digest):
            self.assertFalse(gate.inspect(serial.replace(token.encode(),b'MISSING',1),commit,digests)['passed'])
        self.assertFalse(gate.inspect(serial.replace(b'exit=0 steps=10',b'exit=1 steps=10',1),commit,digests)['passed'])
        self.assertTrue(all(len(command)<220 for command in gate.commands(commit)))

    @unittest.skipUnless(os.environ.get('COMPACT_SHELL_DIR'), 'set COMPACT_SHELL_DIR to pinned BusyBox')
    def test_unmodified_busybox_project_runs_on_live_directory(self):
        from phase9_mounts import SCRIPT
        busybox = (ROOT / os.environ['COMPACT_SHELL_DIR'] / 'busybox').resolve()
        self.assertEqual(hashlib.sha256(busybox.read_bytes()).hexdigest(), DIGEST)
        script = self.directory / 'mount-script'
        script.write_bytes(SCRIPT)
        r = subprocess.run([str(self.runner), '-r', '-M', 'rw:/home/share=' + str(self.path), '-b', '4194304',
                            '-x', '/busybox=' + str(busybox), '-i', str(script), str(busybox), 'ash', '/input'],
                           capture_output=True, timeout=25)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b'int main(void){return 0;}\nFLEX_MOUNT_BUSYBOX_OK\n')
        self.assertEqual((self.path / 'shell/source.c').read_bytes(), b'int main(void){return 0;}\n')


if __name__ == '__main__':
    unittest.main()
