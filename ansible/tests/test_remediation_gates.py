"""Static routing regressions; never connect to hosts or execute role tasks.

Run with: python -m unittest discover -s ansible/tests -v
Requires PyYAML. These checks do not replace Ansible runtime verification.
"""

from functools import lru_cache
from pathlib import Path
import re
import unittest

import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"
PLATFORMS = ("cis_ubuntu_2404", "cis_debian_12")
UNROUTED = {
    f"sections/section_04_firewall/{control}/remediation.yml"
    for control in (
        "4_4_1_1_iptables_installed",
        "4_4_1_2_nftables_not_in_use",
        "4_4_1_3_ufw_not_in_use",
    )
}


@lru_cache(maxsize=None)
def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def routes(role):
    """Enumerate static remediation imports; reject dynamic routing drift."""
    for task in read_yaml(ROLES / role / "tasks/main.yml"):
        source = task.get("ansible.builtin.import_tasks")
        if source and source.endswith("/remediation.yml"):
            yield task, source, role + "_" + Path(source).parent.name
        include = task.get("ansible.builtin.include_tasks")
        if include and include["file"].endswith("/remediation.yml"):
            raise AssertionError("Remediation routing must use explicit per-control imports")


def control_gate(role, task, control):
    return control + " | bool"


def selected(role, task, control, values):
    """Evaluate the deliberately narrow route predicate grammar, fail on drift.

    This is a static truth-table helper, NOT an Ansible/Jinja implementation.
    Exact gate presence is checked separately, so an unrecognized predicate
    cannot accidentally produce a passing exclusion assertion.
    """
    results = []
    for expression in task.get("when", []):
        if expression == f"{role}_execution_mode == 'remediation'":
            results.append(values[role + "_execution_mode"] == "remediation")
        elif expression == control_gate(role, task, control):
            results.append(values[control])
        elif re.fullmatch(r"[a-z0-9_]+ \| bool", expression):
            results.append(values[expression.split()[0]])
        else:
            raise AssertionError(f"Unsupported routing predicate: {expression}")
    return all(results)


class RemediationGatesTest(unittest.TestCase):
    def test_each_ssh_control_tag_selects_only_its_own_route(self):
        for role in PLATFORMS:
            defaults = read_yaml(ROLES / role / "defaults/main.yml")
            values = {key: True for key in defaults}
            values[role + "_execution_mode"] = "remediation"
            for number in (1, 2, 3, 5, 6, 7, 8, 9, 10, 11):
                tag = f"cis_5_1_{number}"
                matches = [(task, source, control) for task, source, control in routes(role)
                           if tag in task.get("tags", [])]
                with self.subTest(role=role, tag=tag):
                    self.assertEqual(1, len(matches), "SSH tag must never fan out")
                    task, source, control = matches[0]
                    self.assertTrue(Path(source).parent.name.startswith(f"5_1_{number}_"))
                    self.assertTrue(selected(role, task, control, values))
                    self.assertFalse(selected(role, task, control, values | {control: False}))
                    self.assertFalse(selected(role, task, control,
                                              values | {role + "_remediation_enabled": False}))
                    self.assertIn(control + " | bool", task["when"])

    def test_combined_ssh_tags_remain_gated_by_master_and_canary(self):
        tags = {"cis_5_1_1", "cis_5_1_2", "cis_5_1_3", "cis_5_1_5", "cis_5_1_6",
                "cis_5_1_7", "cis_5_1_8", "cis_5_1_9", "cis_5_1_10", "cis_5_1_11"}
        for role in PLATFORMS:
            values = {key: True for key in read_yaml(ROLES / role / "defaults/main.yml")}
            values[role + "_execution_mode"] = "remediation"
            matches = [(task, control) for task, _, control in routes(role)
                       if tags.intersection(task.get("tags", []))]
            self.assertEqual(10, len(matches), role)
            for task, control in matches:
                self.assertTrue(selected(role, task, control, values))
                self.assertFalse(selected(role, task, control,
                                          values | {role + "_remediation_enabled": False}))
                if role == "cis_debian_12":
                    self.assertIn(role + "_canary_confirmed | bool", task["when"])
                    self.assertFalse(selected(role, task, control,
                                              values | {role + "_canary_confirmed": False}))

    def test_inventory_covers_every_active_remediation_file(self):
        for role in PLATFORMS:
            actual = {
                p.relative_to(ROLES / role / "tasks").as_posix()
                for p in (ROLES / role / "tasks").rglob("remediation.yml")
            }
            routed = {source for _, source, _ in routes(role)}
            self.assertEqual(actual - UNROUTED, routed, role)
            self.assertFalse(routed & UNROUTED, role)

    def test_every_route_requires_mode_master_and_declared_control_gates(self):
        for role in PLATFORMS:
            defaults = read_yaml(ROLES / role / "defaults/main.yml")
            for task, source, control in routes(role):
                with self.subTest(role=role, source=source):
                    self.assertIn(control, defaults)
                    required = [f"{role}_execution_mode == 'remediation'",
                                role + "_remediation_enabled | bool",
                                control_gate(role, task, control)]
                    if control + "_remediate" in defaults:
                        required.append(control + "_remediate | bool")
                    self.assertIsInstance(task.get("when"), list)
                    for predicate in required:
                        self.assertIn(predicate, task["when"])

    def test_negative_gates_exclude_all_routes_and_positive_gates_allow_them(self):
        for role in PLATFORMS:
            defaults = read_yaml(ROLES / role / "defaults/main.yml")
            for task, source, control in routes(role):
                with self.subTest(role=role, source=source):
                    values = {key: True for key in defaults}
                    values[role + "_execution_mode"] = "remediation"
                    self.assertTrue(selected(role, task, control, values))
                    gates = [role + "_remediation_enabled", control]
                    if control + "_remediate" in defaults:
                        gates.append(control + "_remediate")
                    for gate in gates:
                        with self.subTest(gate=gate):
                            self.assertFalse(selected(role, task, control, values | {gate: False}))
                    for mode in ("audit", "verification"):
                        self.assertFalse(selected(role, task, control,
                                                  values | {role + "_execution_mode": mode}))

    def test_seven_unsafe_controls_remain_opt_in(self):
        for role in PLATFORMS:
            defaults = read_yaml(ROLES / role / "defaults/main.yml")
            unsafe = [control for _, _, control in routes(role)
                      if re.match(re.escape(role) + r"_(2_2_[1-6]_|5_4_3_1_)", control)]
            self.assertEqual(7, len(unsafe))
            for control in unsafe:
                self.assertIs(defaults[control + "_remediate"], False)

    def test_fixed_cron_tags_still_reach_their_routes(self):
        for role in PLATFORMS:
            for number in range(2, 8):
                tag = f"cis_2_4_1_{number}"
                matches = [(task, source) for task, source, _ in routes(role)
                           if Path(source).parent.name.startswith(f"2_4_1_{number}_")]
                self.assertEqual(1, len(matches), (role, tag))
                task, source = matches[0]
                for child in read_yaml(ROLES / role / "tasks" / source):
                    self.assertIn(tag, task.get("tags", []) + child.get("tags", []))


if __name__ == "__main__":
    unittest.main()
