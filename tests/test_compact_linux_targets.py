# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from compact_linux_targets import validate,LOCK
from compact_linux_target_profiles import elf_info,trace_metrics
class TargetLockTests(unittest.TestCase):
 def test_all_seven_frozen_targets_and_transitive_sources_are_locked(self):
  lock=json.loads(LOCK.read_text());self.assertEqual(validate(lock),[]);self.assertGreaterEqual(len(lock['sources']),14)
  for target in ('python','git','gcc','binutils','make','busybox','musl'):
   d=copy.deepcopy(lock);d['sources']=[s for s in d['sources'] if s['id']!=target];self.assertTrue(validate(d))
 def test_corrupt_digest_duplicate_or_moved_version_is_rejected(self):
  lock=json.loads(LOCK.read_text())
  for key,value in [('digest','x'*64),('archive','Python-3.99.tar.xz'),('urls',['http://example.com/source'])]:
   d=copy.deepcopy(lock);d['sources'][1][key]=value;self.assertTrue(validate(d))
  lock['sources'].append(lock['sources'][0]);self.assertTrue(validate(lock))
 def test_build_subprocess_pwd_matches_actual_make_directory(self):
  from compact_linux_targets import Build
  import os
  with tempfile.TemporaryDirectory() as d:
   b=Build(Path(d)/'out',d,2);cwd=Path(d)/'actual';cwd.mkdir()
   (cwd/'Makefile').write_text('all:\n\t@test "$(PWD)" = "$(CURDIR)"\n')
   b.run('pwd-proof',['make'],cwd,dict(os.environ,PWD='/incorrect-parent'))
 def test_toolchain_checkpoint_reuse_verifies_file_hashes(self):
  from compact_linux_targets import Build
  from unittest.mock import patch,Mock
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'out';driver=Path(d)/'driver';(driver/'litecross').mkdir(parents=True);(driver/'litecross/Makefile').write_text('all:\n')
   b=Build(out,driver,2);src={s['id']:Path(d)/s['id'] for s in b.lock['sources']}
   def fake(name,argv,cwd,env=None):
    if name=='cross-install':
     (b.cross/'bin').mkdir(parents=True);(b.cross/'bin/cc').write_bytes(b'compiled-test-compiler')
   b.run=Mock(side_effect=fake)
   with patch('compact_linux_targets.subprocess.check_output',return_value=b.lock['build_driver']['commit']):
    b.toolchain(src);b.run.reset_mock();b.toolchain(src);b.run.assert_not_called();self.assertEqual(b.reused_stages,['cross'])
    (b.cross/'bin/cc').write_bytes(b'corrupt');b.toolchain(src);self.assertTrue(b.run.called)
 def test_elf_admission_measurement_rejects_malformed_headers(self):
  with self.assertRaises(ValueError):elf_info(b'\x7fELF')
  import subprocess
  with tempfile.TemporaryDirectory() as d:
   source=Path(d)/'x.c';binary=Path(d)/'x';source.write_text('int main(void){return 0;}')
   subprocess.run(['cc',str(source),'-o',str(binary)],check=True,capture_output=True)
   info=elf_info(binary.read_bytes());self.assertEqual(info['bytes'],binary.stat().st_size);self.assertGreater(info['load_span_bytes'],0)
 def test_trace_metrics_keep_reference_scope_and_count_returned_bytes(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'trace';p.write_text('openat(AT_FDCWD, "f", 0) = 9\nread(9</f>, "a", 5) = 1\nwrite(7<TCP:[x]>, "ab", 2) = 2\nwrite(1</dev/null>, "no", 2) = -1 EPIPE\n')
   metrics=trace_metrics([p]);self.assertEqual(metrics['max_observed_fd'],9);self.assertEqual(metrics['returned_read_bytes'],1);self.assertEqual(metrics['returned_write_bytes'],2);self.assertEqual(metrics['returned_network_bytes'],2)
if __name__=='__main__':unittest.main()
