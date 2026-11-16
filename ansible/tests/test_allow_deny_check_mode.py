"""Contract: the allow-deny remediation must not fail under --check on a fresh host."""
import unittest
from pathlib import Path

import yaml

TASKS = (Path(__file__).resolve().parents[1] / "roles" / "cis_linux_common" / "tasks"
         / "mechanisms" / "allow_deny_restriction" / "remediation.yml")


def task(name_part):
    tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
    return next(t for t in tasks if name_part in t["name"])


class AllowDenyCheckModeTests(unittest.TestCase):
    def test_create_task_registers_its_result(self):
        self.assertEqual(task("Create authorized-users allow file")["register"],
                         "cis_linux_common_allow_file_created")

    def test_permission_task_skips_files_only_created_in_check_mode(self):
        conditions = task("Enforce allow file ownership and mode")["when"]
        self.assertIsInstance(conditions, list)
        self.assertIn("not (ansible_check_mode and cis_linux_common_allow_file_created is changed)",
                      conditions)
        self.assertIn("cis_linux_common_restriction_package in ansible_facts.packages", conditions)

    def test_permission_task_still_enforces_root_0600(self):
        module = task("Enforce allow file ownership and mode")["ansible.builtin.file"]
        self.assertEqual((module["owner"], module["group"], module["mode"]), ("root", "root", "0600"))


if __name__ == "__main__":
    unittest.main()
