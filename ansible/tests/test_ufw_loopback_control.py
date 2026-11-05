"""CIS 4.2.4 must preserve loopback and reject spoofed loopback sources."""

from pathlib import Path
import re
import unittest

import yaml


CONTROL = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
           "sections/section_04_firewall/4_2_4_ufw_loopback_traffic")


def tasks(mode):
    return yaml.safe_load((CONTROL / f"{mode}.yml").read_text(encoding="utf-8"))


class UfwLoopbackControlTest(unittest.TestCase):
    def test_remediation_keeps_allow_lo_and_adds_both_source_denies(self):
        remediation = tasks("remediation")
        self.assertEqual("mechanisms/ufw_policy/remediation.yml",
                         remediation[0]["ansible.builtin.import_tasks"])
        deny = remediation[1]["community.general.ufw"]
        self.assertEqual({"rule": "deny", "direction": "in",
                          "from_ip": "{{ item }}"}, deny)
        self.assertEqual(["127.0.0.0/8", "::1"], remediation[1]["loop"])
        self.assertFalse(any(task.get("community.general.ufw", {}).get("state") ==
                             "reset" for task in remediation))

    def test_audit_checks_both_denies_and_before_rules(self):
        audit = tasks("audit")
        self.assertEqual("/etc/ufw/before.rules",
                         audit[1]["ansible.builtin.slurp"]["src"])
        condition = audit[2]["ansible.builtin.set_fact"][
            "cis_linux_common_ufw_loopback_compliant"]
        for marker in ("cis_linux_common_ufw_loopback_ipv4_deny",
                       "cis_linux_common_ufw_loopback_ipv6_deny",
                       "cis_linux_common_ufw_loopback_input_allow",
                       "cis_linux_common_ufw_loopback_output_allow"):
            self.assertIn(marker, condition)
        patterns = audit[2]["vars"]
        status = "Anywhere                   DENY IN     127.0.0.0/8\n" \
                 "Anywhere (v6)              DENY IN     ::1\n"
        before = "-A ufw-before-input -i lo -j ACCEPT\n" \
                 "-A ufw-before-output -o lo -j ACCEPT\n"
        for key, value in (("ipv4_deny", status), ("ipv6_deny", status),
                           ("input_allow", before), ("output_allow", before)):
            self.assertRegex(value, re.compile(patterns[
                f"cis_linux_common_ufw_loopback_{key}"]))

    def test_verification_asserts_audit_result(self):
        verification = tasks("verification")
        self.assertEqual("sections/section_04_firewall/"
                         "4_2_4_ufw_loopback_traffic/audit.yml",
                         verification[0]["ansible.builtin.import_tasks"])
        self.assertIn("cis_linux_common_ufw_loopback_compliant",
                      verification[1]["ansible.builtin.assert"]["that"])


if __name__ == "__main__":
    unittest.main()
