"""Guard the shared fixed-file check-mode behavior on fresh hosts.

Remediation must never announce creation of a missing regular file during a
check run, must still plan directory creation, and must apply only the
per-violation action list built from the normalized scope plan.
"""

from pathlib import Path
import unittest

import yaml


TASKS = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
         "mechanisms/fixed_file_permissions/remediation.yml")


class FixedFileCheckModeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load(TASKS.read_text(encoding="utf-8"))
        cls.action_templates = [
            fact for task in cls.tasks
            for fact in [task.get("ansible.builtin.set_fact") or {}]
            if "cis_linux_common_fixed_file_actions_json" in fact][0][
                "cis_linux_common_fixed_file_actions_json"]
        cls.apply = next(task for task in cls.tasks
                         if "ansible.builtin.file" in task)

    def test_actions_template_gates_creation_on_check_mode_and_source(self):
        self.assertIn("ansible_check_mode", self.action_templates)
        self.assertIn("violation.source == 'literal'", self.action_templates)

    def test_apply_loops_over_actions_and_omits_non_failing_dimensions(self):
        file_params = self.apply["ansible.builtin.file"]
        self.assertEqual("{{ cis_linux_common_fixed_file_actions }}",
                         self.apply["loop"])
        for key in ("owner", "group", "mode"):
            self.assertIn("'OMIT'", file_params[key])
            self.assertIn("omit", file_params[key])
        self.assertTrue(file_params["follow"])

    def test_all_targets_are_stat_followed_to_match_stat_Lc(self):
        discover = yaml.safe_load((TASKS.parent / "discover.yml").read_text(
            encoding="utf-8"))
        stat_tasks = [task for task in discover if "ansible.builtin.stat" in task]
        self.assertEqual(2, len(stat_tasks))
        for task in stat_tasks:
            self.assertIs(True, task["ansible.builtin.stat"]["follow"])


if __name__ == "__main__":
    unittest.main()
