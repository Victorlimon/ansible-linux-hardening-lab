"""CIS 5.1.4 AllowUsers must come from inventory and fail closed."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTROL = "tasks/sections/section_05_access_control/5_1_4_sshd_access/remediation.yml"
PLATFORMS = ("debian_12", "ubuntu_2404")


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class SshdAllowUsersPolicyTest(unittest.TestCase):
    def test_adapters_map_the_inventory_list_without_hardcoded_accounts(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                adapter = read_yaml(ROOT / f"roles/cis_{platform}" / CONTROL)
                value = adapter[0]["vars"]["cis_linux_common_sshd_allow_users"]
                self.assertEqual(f"{{{{ cis_{platform}_sshd_allow_users }}}}", value)

    def test_role_defaults_leave_the_list_empty(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                defaults = read_yaml(ROOT / f"roles/cis_{platform}/defaults/main.yml")
                self.assertEqual([], defaults[f"cis_{platform}_sshd_allow_users"])

    def test_common_remediation_asserts_before_writing_sshd_config(self):
        tasks = read_yaml(ROOT / "roles/cis_linux_common" / CONTROL)
        modules = [next(key for key in task if key.startswith("ansible.builtin.")) for task in tasks]
        self.assertEqual(["ansible.builtin.assert", "ansible.builtin.lineinfile",
                          "ansible.builtin.systemd"], modules)
        conditions = " ".join(tasks[0]["ansible.builtin.assert"]["that"])
        self.assertIn("length > 0", conditions)
        self.assertIn("ansible_user in cis_linux_common_sshd_allow_users", conditions)
        self.assertIn("is not string", conditions)
        line = tasks[1]["ansible.builtin.lineinfile"]
        self.assertIn("join(' ')", line["line"])
        self.assertIn("sshd -t", line["validate"])
        self.assertEqual("cis_linux_common_sshd_allow_users_line is changed", tasks[2]["when"])

    def test_lab_inventory_keeps_the_connection_user_allowed(self):
        hosts = read_yaml(ROOT / "inventories/local/hosts.yml")
        connection_user = hosts["all"]["vars"]["ansible_user"]
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                local = read_yaml(ROOT / f"inventories/local/group_vars/{platform}.yml")
                self.assertIn(connection_user, local[f"cis_{platform}_sshd_allow_users"])


if __name__ == "__main__":
    unittest.main()
