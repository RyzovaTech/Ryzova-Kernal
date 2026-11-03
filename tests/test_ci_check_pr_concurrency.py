# SPDX-License-Identifier: AGPL-3.0-only
import sys
import tempfile
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from ci_check_pr_concurrency import GROUP,CANCEL,verify


def write(root,name,lines):
    folder=Path(root)/".github"/"workflows"
    folder.mkdir(parents=True,exist_ok=True)
    (folder/name).write_text("\n".join(lines)+"\n",encoding="utf-8")


class CIQueuePolicyTests(unittest.TestCase):
    def test_all_repo_workflows_use_safe_policy(self):
        checked=verify(ROOT)
        self.assertGreaterEqual(len(checked),57)
        self.assertIn("phase4-baseline.yml",checked)
        self.assertIn("phase3-native-build.yml",checked)

    def test_safe_scope_and_manual_exception(self):
        with tempfile.TemporaryDirectory() as root:
            write(root,"a.yml",["name: A","on:","  pull_request:","concurrency:",
                "  "+GROUP,"  "+CANCEL,"jobs:"])
            write(root,"manual.yml",["name: M","on:","  workflow_dispatch:","jobs:"])
            self.assertEqual(verify(root),["a.yml"])

    def test_missing_global_or_unsafe_cancel_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for group,cancel in [
                ("group: global",CANCEL),
                (GROUP,"cancel-in-progress: true"),
                (GROUP,"cancel-in-progress: false"),
                ("group: "+chr(36)+"{{ github.ref }}",CANCEL)
            ]:
                write(root,"a.yml",["name: A","on:","  pull_request:",
                    "concurrency:","  "+group,"  "+cancel,"jobs:"])
                with self.assertRaises(ValueError):
                    verify(root)

    def test_duplicate_workflow_names_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for file in ("a.yml", "b.yml"):
                write(root, file, ["name: Same Workflow", "on:", "  pull_request:",
                    "concurrency:", "  " + GROUP, "  " + CANCEL, "jobs:"])
            with self.assertRaises(ValueError):
                verify(root)

    def test_no_concurrency_and_duplicate_concurrency_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            write(root,"a.yml",["name: A","on:","  pull_request:","jobs:"])
            with self.assertRaises(ValueError):
                verify(root)
            write(root,"a.yml",["name: A","on:","  pull_request:",
                "concurrency:","  "+GROUP,"  "+CANCEL,
                "concurrency:","  "+GROUP,"  "+CANCEL,"jobs:"])
            with self.assertRaises(ValueError):
                verify(root)


if __name__=="__main__":
    unittest.main()
