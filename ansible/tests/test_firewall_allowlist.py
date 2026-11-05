"""Static safety contract for the opt-in Ubuntu UFW allowlist route."""

from pathlib import Path
import re
import unittest

import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"
UBUNTU = ROLES / "cis_ubuntu_2404"
COMMON = ROLES / "cis_linux_common"


def tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class FirewallAllowlistTest(unittest.TestCase):
    def test_inventory_profile_is_not_ignored(self):
        profile = tasks(Path(__file__).resolve().parents[1] /
                        "inventories/local/group_vars/ubuntu_2404.yml")
        section = tasks(COMMON / "tasks/sections/section_04_firewall/"
                        "4_2_6_ufw_rules_for_open_ports/remediation.yml")
        payload = str(section)
        self.assertTrue(profile["cis_ufw_ssh_allowed_sources"])
        self.assertEqual([], profile["cis_ufw_allowed_in_rules"])
        self.assertIn("cis_ufw_ssh_allowed_sources", payload)
        self.assertIn("cis_ufw_allowed_in_rules", payload)
        self.assertIn("cis_ufw_allowed_in_rules | type_debug == 'list'", payload)
        service_rule = next(task for task in section if task.get("name") ==
                            "Common UFW rule | Allow reviewed published services")
        self.assertEqual("{{ cis_ufw_allowed_in_rules }}", service_rule["loop"])

    def test_validation_precedes_every_ufw_mutation(self):
        section = tasks(COMMON / "tasks/sections/section_04_firewall/"
                        "4_2_6_ufw_rules_for_open_ports/remediation.yml")
        validation = [i for i, task in enumerate(section)
                      if "ansible.builtin.assert" in task]
        mutations = [i for i, task in enumerate(section)
                     if "community.general.ufw" in task]
        self.assertTrue(validation)
        self.assertTrue(mutations)
        self.assertLess(max(validation), min(mutations))
        validation_text = str(section[:min(mutations)])
        for field in ("cis_ufw_ssh_allowed_sources", "cis_ufw_allowed_in_rules",
                      "from_ip", "port", "proto"):
            self.assertIn(field, validation_text)

    def test_debian_nftables_remains_unmodified(self):
        debian = tasks(ROLES / "cis_debian_12/tasks/main.yml")
        self.assertFalse(any(task.get("ansible.builtin.import_tasks", "").endswith(
            "4_2_6_ufw_rules_for_open_ports/remediation.yml") for task in debian))

    def test_ssh_sources_are_cidr_only_and_global_allow_is_removed(self):
        section = tasks(COMMON / "tasks/sections/section_04_firewall/"
                        "4_2_6_ufw_rules_for_open_ports/remediation.yml")
        pattern = next(task["vars"]["cis_ufw_ipv4_cidr_pattern"]
                       for task in section if "vars" in task)
        for value in ("192.168.56.0/24", "10.0.2.2/32"):
            self.assertIsNotNone(re.fullmatch(pattern, value))
        for value in ("any", "10.0.2.2", "999.0.2.2/32", "10.0.2.2/33",
                      "10.0.2.2/32; ufw disable"):
            self.assertIsNone(re.fullmatch(pattern, value))
        validations = [expression for task in section
                       if "ansible.builtin.assert" in task
                       for expression in task["ansible.builtin.assert"]["that"]]
        self.assertIn("item.port | int != cis_ufw_ssh_port | int", validations)
        self.assertIsNotNone(re.fullmatch(pattern, "10.1.2.3/0"))
        self.assertIn("item is not match('^.*/0$')", validations)
        mutations = [task["community.general.ufw"] for task in section
                     if "community.general.ufw" in task]
        self.assertEqual(3, len(mutations))
        self.assertTrue(all("from_ip" in rule for rule in mutations))
        self.assertEqual("{{ item }}", mutations[0]["from_ip"])
        self.assertEqual("{{ item.from_ip }}", mutations[1]["from_ip"])
        self.assertEqual({
            "rule": "allow", "direction": "in",
            "port": "{{ cis_ufw_ssh_port | string }}",
            "proto": "tcp", "from_ip": "any", "delete": True,
        }, mutations[2])
        self.assertFalse(any(rule.get("state") == "reset" for rule in mutations))
        saved_rules = section[-2]
        self.assertEqual(["ufw", "show", "added"],
                         saved_rules["ansible.builtin.command"]["argv"])
        self.assertFalse(saved_rules["changed_when"])
        self.assertFalse(saved_rules["check_mode"])
        self.assertEqual("cis_ufw_saved_rules", saved_rules["register"])
        self.assertIn("cis_ufw_saved_rules.stdout_lines", section[-1]["when"])
        self.assertIn("cis_ufw_ssh_port", section[-1]["when"])

    def test_ufw_route_is_disabled_for_nftables(self):
        adapter = tasks(UBUNTU / "tasks/sections/section_04_firewall/"
                        "4_2_6_ufw_rules_for_open_ports/remediation.yml")
        self.assertEqual("cis_firewall == 'ufw'", adapter[0]["when"])

    def test_default_deny_prepares_approved_rules_before_activation(self):
        section = tasks(COMMON / "tasks/sections/section_04_firewall/"
                        "4_2_7_ufw_default_deny/remediation.yml")
        self.assertEqual(
            "sections/section_04_firewall/4_2_6_ufw_rules_for_open_ports/remediation.yml",
            section[0]["ansible.builtin.import_tasks"],
        )
        self.assertEqual("mechanisms/ufw_policy/remediation.yml",
                         section[1]["ansible.builtin.import_tasks"])
        self.assertEqual("enabled", section[2]["community.general.ufw"]["state"])
        policy = tasks(COMMON / "tasks/mechanisms/ufw_policy/remediation.yml")
        self.assertFalse(any(task.get("community.general.ufw", {}).get("state") ==
                             "enabled" for task in policy))

    def test_default_deny_standalone_requires_ufw_route(self):
        adapter = tasks(UBUNTU / "tasks/sections/section_04_firewall/"
                        "4_2_7_ufw_default_deny/remediation.yml")
        self.assertEqual("cis_firewall == 'ufw'", adapter[0]["when"])


if __name__ == "__main__":
    unittest.main()
