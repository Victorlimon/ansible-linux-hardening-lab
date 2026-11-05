"""Regression tests for CIS 5.1.2 private SSH host-key permissions."""

from pathlib import Path
import unittest

import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"


class SshPrivateHostKeyPermissionsTest(unittest.TestCase):
    def test_adapter_accepts_mode_it_remediates_to(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            for phase in ("audit", "remediation", "verification"):
                with self.subTest(platform=platform, phase=phase):
                    path = (
                        ROLES / platform / "tasks/sections/section_05_access_control"
                        / "5_1_2_ssh_private_host_key_permissions" / f"{phase}.yml"
                    )
                    task = yaml.safe_load(path.read_text(encoding="utf-8"))[0]
                    contract = task["vars"]
                    self.assertEqual("root", contract["cis_linux_common_fixed_file_owner"])
                    self.assertEqual("root", contract["cis_linux_common_fixed_file_group"])
                    self.assertEqual("0600", contract["cis_linux_common_fixed_file_remediation_mode"])
                    self.assertEqual("0600", contract["cis_linux_common_fixed_file_max_mode"])
                    for legacy in ("allowed_owner_digits", "allowed_group_digits",
                                   "allowed_other_digits"):
                        self.assertNotIn(f"cis_linux_common_fixed_file_{legacy}", contract)

    def test_common_section_covers_every_discovered_private_key(self):
        common = (ROLES / "cis_linux_common/tasks/sections/"
                  "section_05_access_control/5_1_2_ssh_private_host_key_permissions")
        for phase in ("audit", "remediation", "verification"):
            with self.subTest(phase=phase):
                doc = yaml.safe_load((common / f"{phase}.yml").read_text(encoding="utf-8"))
                include = doc[0]["ansible.builtin.include_tasks"]
                self.assertEqual(
                    "mechanisms/fixed_file_permissions/%s.yml" % phase,
                    include["file"])
                search = doc[0]["vars"]["cis_linux_common_fixed_file_search"]
                self.assertEqual("/etc/ssh", search["paths"])
                self.assertEqual("ssh_host_*_key", search["patterns"])


if __name__ == "__main__":
    unittest.main()
