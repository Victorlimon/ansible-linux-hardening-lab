"""Regressions for CIS 4.1.1 firewall selection verification."""

from pathlib import Path
import unittest

from jinja2 import Environment
import yaml


VERIFY = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
          "mechanisms/firewall_single_utility/verification.yml")
AUDIT = VERIFY.with_name("audit.yml")


class SingleFirewallUtilityTest(unittest.TestCase):
    def test_audit_reports_only_enabled_and_active_utilities(self):
        audit = yaml.safe_load(AUDIT.read_text(encoding="utf-8"))
        self.assertEqual([], audit[3]["ansible.builtin.set_fact"][
            "cis_linux_common_active_firewall_utilities"])
        selected = audit[4]
        self.assertEqual([
            "cis_linux_common_firewall_utility_paths.results[item].stat.exists",
            "cis_linux_common_firewall_enabled.results[item].rc | default(1) == 0",
            "cis_linux_common_firewall_active.results[item].rc | default(1) == 0",
        ], selected["when"])
        self.assertIn("cis_linux_common_firewall_utilities[item].name", selected["ansible.builtin.set_fact"][
            "cis_linux_common_active_firewall_utilities"])
        report = audit[-1]["ansible.builtin.debug"]["msg"]
        self.assertEqual("{{ cis_linux_common_active_firewall_utilities }}",
                         report["active_utilities"])
        self.assertIn("cis_linux_common_active_firewall_utilities | length == 1",
                      report["classification"])

    def test_both_modes_use_systemctl_status_without_mutation(self):
        for path in (AUDIT, VERIFY):
            with self.subTest(path=path):
                tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
                for index, verb in ((1, "is-enabled"), (2, "is-active")):
                    task = tasks[index]
                    self.assertEqual(["systemctl", verb, "--quiet",
                                      "{{ item.0.service }}"],
                                     task["ansible.builtin.command"]["argv"])
                    self.assertFalse(task["changed_when"])
                    self.assertFalse(task["failed_when"])
                    self.assertFalse(task["check_mode"])
                    self.assertEqual("item.1.stat.exists", task["when"])

    def test_only_installed_enabled_and_active_utility_counts(self):
        verify = yaml.safe_load(VERIFY.read_text(encoding="utf-8"))
        assertion = verify[-1]
        count_template = assertion["vars"]["cis_linux_common_active_firewall_count"]
        self.assertEqual("cis_linux_common_active_firewall_count | int == 1",
                         assertion["ansible.builtin.assert"]["that"][0])

        utilities = [
            {"name": "ufw", "service": "ufw", "path": "/usr/sbin/ufw"},
            {"name": "nftables", "service": "nftables", "path": "/usr/sbin/nft"},
            {"name": "iptables", "service": "iptables", "path": "/usr/sbin/iptables"},
        ]
        paths = {"results": [{"stat": {"exists": True}} for _ in utilities]}
        cases = (
            ((0, 1, 1), (0, 1, 1), 1),
            ((1, 1, 1), (0, 1, 1), 0),
            ((0, 1, 1), (1, 1, 1), 0),
            ((0, 0, 1), (0, 0, 1), 2),
        )
        for enabled, active, expected in cases:
            with self.subTest(enabled=enabled, active=active):
                actual = Environment().from_string(count_template).render(
                    cis_linux_common_firewall_utilities=utilities,
                    cis_linux_common_firewall_utility_paths=paths,
                    cis_linux_common_firewall_enabled={
                        "results": [{"rc": rc} for rc in enabled]},
                    cis_linux_common_firewall_active={
                        "results": [{"rc": rc} for rc in active]},
                )
                self.assertEqual(expected, int(actual.strip()))


if __name__ == "__main__":
    unittest.main()
