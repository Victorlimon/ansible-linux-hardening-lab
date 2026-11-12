"""Regressions for the lab-only section 2 remediation and rpcbind units."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RPCBIND = ROOT / "roles/cis_linux_common/tasks/sections/section_02_services/2_1_12_rpcbind"


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


# Controls the lab full profile keeps disabled because they can cut SSH or
# sudo access, need a secret, or do not apply to the lab VMs:
# 1.1.2.5.x /var/tmp partition, 1.4.1 GRUB password, 1.7.x GDM,
# 3.3.7 rp_filter (two NICs), 5.4.1.1/5.4.1.5/5.4.1.6 password aging
# (expires the existing vagrant password and blocks SSH and sudo).
LAB_EXCLUDED_CONTROL_PREFIXES = (
    "1_1_2_5_", "1_4_1_", "1_7_", "3_3_7_", "5_4_1_1_", "5_4_1_5_", "5_4_1_6_",
)


class Section2LabGatesTest(unittest.TestCase):
    def test_lab_profile_keeps_access_breaking_remediations_disabled(self):
        for platform in ("debian_12", "ubuntu_2404"):
            with self.subTest(platform=platform):
                local = read_yaml(ROOT / f"inventories/local/group_vars/{platform}.yml")
                prefix = f"cis_{platform}_"
                enabled = {key for key, value in local.items()
                           if key.endswith("_remediate") and value is True}
                self.assertTrue(enabled, "lab profile enables no remediation")
                excluded = {key for key in enabled
                            if key[len(prefix):].startswith(LAB_EXCLUDED_CONTROL_PREFIXES)}
                self.assertEqual(set(), excluded)

    def test_lab_enabled_remediations_stay_opt_in_in_role_defaults(self):
        for platform in ("debian_12", "ubuntu_2404"):
            with self.subTest(platform=platform):
                local = read_yaml(ROOT / f"inventories/local/group_vars/{platform}.yml")
                defaults = read_yaml(ROOT / f"roles/cis_{platform}/defaults/main.yml")
                enabled_by_default = {key for key, value in local.items()
                                      if key.endswith("_remediate") and value is True
                                      and defaults.get(key) is True}
                self.assertEqual(set(), enabled_by_default)

    def test_rpcbind_remediation_covers_socket_before_service(self):
        remediation = read_yaml(RPCBIND / "remediation.yml")
        task = remediation[1]
        self.assertEqual(["rpcbind.socket", "rpcbind.service"], task["loop"])
        self.assertEqual({"name": "{{ item }}", "state": "stopped",
                          "enabled": False, "masked": True}, task["ansible.builtin.systemd"])

    def test_rpcbind_verification_rejects_enabled_or_active_units(self):
        audit = read_yaml(RPCBIND / "audit.yml")
        verify = read_yaml(RPCBIND / "verification.yml")
        self.assertEqual(["is-enabled", "is-active"], audit[1]["loop"])
        self.assertEqual(["is-enabled", "is-active"], verify[1]["loop"])
        self.assertEqual(["systemctl", "{{ item }}", "rpcbind.socket", "rpcbind.service"],
                         verify[1]["ansible.builtin.command"]["argv"])
        condition = verify[2]["ansible.builtin.assert"]["that"][0]
        audit_condition = audit[2]["ansible.builtin.debug"]["msg"]["classification"]
        self.assertIn("map('length') | list == [2, 2]", condition)
        self.assertIn("select('match', '^enabled')", condition)
        self.assertIn("select('equalto', 'active')", condition)
        self.assertIn("'rpcbind' not in ansible_facts.packages", condition)
        self.assertIn("map('length') | list == [2, 2]", audit_condition)
        self.assertIn("select('match', '^enabled')", audit_condition)
        self.assertIn("select('equalto', 'active')", audit_condition)
        self.assertIn("failed_when", verify[1])


if __name__ == "__main__":
    unittest.main()
