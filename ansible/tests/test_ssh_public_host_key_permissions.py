"""Regression checks for CIS 5.1.3 and fixed-file adapter contracts."""

from pathlib import Path
import unittest

import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"
PLATFORMS = ("cis_debian_12", "cis_ubuntu_2404")
PHASES = ("audit", "remediation", "verification")


def adapter_contract(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    collected = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("vars"), dict):
                collected.append(node["vars"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    walk(doc)
    merged = {}
    for entry in collected:
        merged.update(entry)
    return merged


class SshPublicHostKeyPermissionsTest(unittest.TestCase):
    def test_public_key_contract_matches_cis_0133_mask(self):
        for platform in PLATFORMS:
            for phase in PHASES:
                with self.subTest(platform=platform, phase=phase):
                    path = (ROLES / platform / "tasks/sections/section_05_access_control"
                            / "5_1_3_ssh_public_host_key_permissions" / f"{phase}.yml")
                    contract = adapter_contract(path)
                    self.assertEqual("0644", contract["cis_linux_common_fixed_file_remediation_mode"])
                    self.assertEqual("0644", contract["cis_linux_common_fixed_file_max_mode"])
                    self.assertEqual("root", contract["cis_linux_common_fixed_file_owner"])
                    self.assertEqual("root", contract["cis_linux_common_fixed_file_group"])

    def test_common_section_covers_every_discovered_public_key(self):
        common = (ROLES / "cis_linux_common/tasks/sections/"
                  "section_05_access_control/5_1_3_ssh_public_host_key_permissions")
        for phase in ("audit", "remediation", "verification"):
            with self.subTest(phase=phase):
                doc = yaml.safe_load((common / f"{phase}.yml").read_text(encoding="utf-8"))
                include = doc[0]["ansible.builtin.include_tasks"]
                self.assertEqual(
                    "mechanisms/fixed_file_permissions/%s.yml" % phase,
                    include["file"])
                search = doc[0]["vars"]["cis_linux_common_fixed_file_search"]
                self.assertEqual("/etc/ssh", search["paths"])
                self.assertEqual("ssh_host_*_key.pub", search["patterns"])


if __name__ == "__main__":
    unittest.main()
