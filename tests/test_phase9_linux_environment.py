# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from phase9_linux_environment import commands, fixtures, inspect, payload
from phase6_native_9p import payload_for_commit
from phase9_compact_native import fixtures as legacy_fixtures


class LinuxEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        c = ROOT / 'ryzova/compat/linux'
        cls.sources = [str(c / n) for n in ('elf64.c', 'namespace.c', 'syscall.c', 'subset_vm.c')]
        cls.runner = cls.directory / 'runner'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', *cls.sources, str(c / 'subset_vm_probe.c'),
                        '-o', str(cls.runner)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_profile(self, elf, data):
        path = self.directory / 'guest'
        path.write_bytes(elf)
        source = self.directory / 'grant'
        source.write_bytes(data)
        return subprocess.run([str(self.runner), str(path), str(source)],
                              capture_output=True, timeout=5)

    def test_same_elf_matches_linux_reference_and_boundary_lengths(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            app = tmp / 'copy'
            app.write_bytes(fixtures()['copy'])
            app.chmod(0o700)
            for size in (0, 1, 255, 256, 257, 4096, 65536):
                with self.subTest(size=size):
                    data = bytes(i % 256 for i in range(size))
                    (tmp / 'input').write_bytes(data)
                    (tmp / 'output').write_bytes(b'old-output-to-truncate')
                    native = subprocess.run([str(app)], cwd=tmp, capture_output=True, timeout=5)
                    vm = self.run_profile(app.read_bytes(), data)
                    self.assertEqual(native.returncode, 0, native.stderr)
                    self.assertEqual(vm.returncode, 0, vm.stderr)
                    self.assertEqual(vm.stdout, data)
                    self.assertEqual((tmp / 'output').read_bytes(), vm.stdout)

    def test_denials_and_readonly_memory_are_linux_errors(self):
        for name in ('deny', 'traverse', 'readonly', 'rxwrite'):
            with self.subTest(name=name):
                result = self.run_profile(fixtures()[name], b'secret')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b'')

    def test_budgets_and_explicit_opt_in(self):
        self.assertEqual(self.run_profile(fixtures()['copy'], bytes(65537)).returncode, 65)
        loop = self.run_profile(legacy_fixtures('a' * 40)['loop'], b'')
        self.assertEqual(loop.returncode, 2)
        self.assertIn(b'steps=65536', loop.stderr)
        path = self.directory / 'without-grant'
        path.write_bytes(fixtures()['copy'])
        denied = subprocess.run([str(self.runner), str(path)], capture_output=True, timeout=5)
        self.assertEqual(denied.returncode, 2)
        self.assertIn(b'status=3', denied.stderr)

    def test_descriptor_quotas_isolation_and_output_reset(self):
        binary = self.directory / 'resource-tests'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                        '-fno-sanitize-recover=all', *self.sources,
                        str(ROOT / 'tests/phase9_linux_files_test.c'), '-o', str(binary)],
                       check=True, capture_output=True)
        result = subprocess.run([str(binary)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'FLEX_FILES_RESOURCE_TESTS_PASS', result.stdout)

    def test_evidence_rejects_echo_missing_denial_and_wrong_digest(self):
        commit = 'b' * 40
        lines = ['compact/linux api=1.0 profile=files-v1', 'linux-amd64-static-subset-v1',
                 'FLEX_API_READONLY_OK', 'FLEX_SECOND_OK', 'FLEX_ISOLATED_COPY_OK',
                 'FLEX_NO_GRANT_OK', 'FLEX_REMOTE_OK', 'RYZOVA_LINUX_ENV_DONE']
        lines += [f'FLEX_{name}_OK' for name in fixtures()]
        lines += [f'RYZOVA_RUNTIME_STAGE_{i}' for i in range(37, 37 + len(commands()) - 1)]
        lines += [hashlib.sha256(payload(commit)).hexdigest() + ' /tmp/o-copy',
                  hashlib.sha256(payload_for_commit(commit)).hexdigest() + ' /tmp/flex-remote']
        serial = ('\n'.join(lines) + '\n').encode()
        build = b'COMPACT_SERVICE_BUILD_OK\n'
        self.assertTrue(inspect(build, serial, commit)['passed'])
        for value in (b'FLEX_deny_OK', b'FLEX_rxwrite_OK', b'FLEX_API_READONLY_OK',
                      b'FLEX_ISOLATED_COPY_OK', b'FLEX_REMOTE_OK', b'RYZOVA_RUNTIME_STAGE_39'):
            self.assertFalse(inspect(build, serial.replace(value, b'missing'), commit)['passed'])
        self.assertFalse(inspect(b'echo COMPACT_SERVICE_BUILD_OK\n', serial, commit)['passed'])
        self.assertFalse(inspect(build, serial, 'c' * 40)['passed'])
        self.assertFalse(inspect(build, serial + b'panic: fault\n', commit)['passed'])


if __name__ == '__main__':
    unittest.main()
