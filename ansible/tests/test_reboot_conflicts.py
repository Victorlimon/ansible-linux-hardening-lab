"""Regression checks for lab-only virtual time sync and Apport policy."""

from pathlib import Path
import re
import unittest

import yaml


ANSIBLE = Path(__file__).resolve().parents[1]
COMMON = ANSIBLE / "roles/cis_linux_common/tasks/sections/section_01_initial_setup/1_5_5_error_reporting"


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class RebootConflictsTest(unittest.TestCase):
    def test_lab_exceptions_are_local_only_for_both_platforms(self):
        """Time-sync and sudo-password LAB exceptions stay false only in the
        local inventory; role defaults remain true/enforcing for production."""
        for group in ("debian_12", "ubuntu_2404"):
            local_path = ANSIBLE / f"inventories/local/group_vars/{group}.yml"
            local = read_yaml(local_path)
            defaults = read_yaml(ANSIBLE / f"roles/cis_{group}/defaults/main.yml")
            text = local_path.read_text(encoding="utf-8")
            for suffix in (
                "2_3_1_1_single_daemon",
                "2_3_2_1_timesyncd_config",
                "2_3_2_2_timesyncd_enabled",
                "5_2_4_sudo_password",
            ):
                key = f"cis_{group}_{suffix}"
                with self.subTest(key=key):
                    self.assertIs(False, local[key], key)
                    self.assertIs(True, defaults[key], key)
            # Comments must label the exception explicitly (EXCEPTION, never a
            # claimed PASS/compliance for the skipped controls).
            with self.subTest(group=group):
                self.assertIn("EXCEPCIÓN", text)
                self.assertIn("LAB EXCEPTION", text)

    def test_virtual_host_time_exception_is_local_only(self):
        local = read_yaml(ANSIBLE / "inventories/local/group_vars/debian_12.yml")
        defaults = read_yaml(ANSIBLE / "roles/cis_debian_12/defaults/main.yml")
        for suffix in (
            "2_3_1_1_single_daemon",
            "2_3_2_1_timesyncd_config",
            "2_3_2_2_timesyncd_enabled",
        ):
            key = f"cis_debian_12_{suffix}"
            self.assertFalse(local[key], key)
            self.assertTrue(defaults[key], key)

    def test_apport_remediation_is_local_only_and_persistent(self):
        key = "cis_ubuntu_2404_1_5_5_error_reporting_remediate"
        local = read_yaml(ANSIBLE / "inventories/local/group_vars/ubuntu_2404.yml")
        defaults = read_yaml(ANSIBLE / "roles/cis_ubuntu_2404/defaults/main.yml")
        self.assertTrue(local[key])
        self.assertFalse(defaults[key])
        tasks = read_yaml(COMMON / "remediation.yml")
        setting = next(task["ansible.builtin.lineinfile"] for task in tasks
                       if "ansible.builtin.lineinfile" in task)
        self.assertEqual("/etc/default/apport", setting["path"])
        self.assertEqual("enabled=0", setting["line"])
        self.assertFalse(setting["create"])
        self.assertTrue(any("mechanisms/service_disabled/remediation.yml" in str(task)
                            for task in tasks))

    def test_apport_verification_rejects_enabled_and_newline_values(self):
        verify = read_yaml(COMMON / "verification.yml")
        self.assertTrue(any("mechanisms/service_disabled/verification.yml" in str(task)
                            for task in verify))
        condition = next(task["ansible.builtin.assert"]["that"][0]
                         for task in verify if "ansible.builtin.assert" in task)
        self.assertIn("last | default('')", condition)
        pattern = r"(?m)^[ \t]*enabled[ \t]*=[ \t]*([^ \t#\r\n]+)"
        self.assertIn(pattern, condition)
        self.assertEqual(["1", "0"], re.findall(pattern, "enabled=1\nenabled=0\n"))
        self.assertEqual([], re.findall(pattern, "enabled=\n2\n"))


if __name__ == "__main__":
    unittest.main()
