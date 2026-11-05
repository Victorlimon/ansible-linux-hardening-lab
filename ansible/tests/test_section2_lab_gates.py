"""Regressions for the lab-only section 2 remediation and rpcbind units."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RPCBIND = ROOT / "roles/cis_linux_common/tasks/sections/section_02_services/2_1_12_rpcbind"


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class Section2LabGatesTest(unittest.TestCase):
    def test_only_requested_lab_remediations_are_enabled(self):
        expected = {
            "debian_12": {"cis_debian_12_2_1_12_rpcbind_remediate"},
            "ubuntu_2404": {
                "cis_ubuntu_2404_2_2_4_telnet_client_remediate",
                "cis_ubuntu_2404_2_2_6_ftp_client_remediate",
                # Apport re-enables fs.suid_dumpable=2 at boot and contradicts
                # CIS 1.5.3; disabling it is a deliberate lab-only remediation
                # gate (proven by test_reboot_conflicts.py). Role defaults stay
                # enforcing and the remediation stays opt-in.
                "cis_ubuntu_2404_1_5_5_error_reporting_remediate",
            },
        }
        for platform, keys in expected.items():
            with self.subTest(platform=platform):
                local = read_yaml(ROOT / f"inventories/local/group_vars/{platform}.yml")
                defaults = read_yaml(ROOT / f"roles/cis_{platform}/defaults/main.yml")
                for key in keys:
                    self.assertTrue(local[key], key)
                    self.assertFalse(defaults[key], key)
                other = {key for key, value in local.items()
                         if key.endswith("_remediate") and value and key not in keys}
                self.assertEqual(set(), other)

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
