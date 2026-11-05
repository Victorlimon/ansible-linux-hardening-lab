"""Regression for enabled, active oneshot services such as UFW."""

from pathlib import Path
import unittest

from jinja2 import Environment
import yaml


MECHANISM = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
             "mechanisms/service_enabled")


class ServiceEnabledOneshotTest(unittest.TestCase):
    def test_audit_and_verification_use_systemctl_exit_codes(self):
        for mode in ("audit", "verification"):
            with self.subTest(mode=mode):
                tasks = yaml.safe_load((MECHANISM / f"{mode}.yml").read_text(
                    encoding="utf-8"))
                self.assertIn("ansible.builtin.package_facts", tasks[0])
                for index, verb in ((1, "is-enabled"), (2, "is-active")):
                    task = tasks[index]
                    self.assertEqual(["systemctl", verb, "--quiet",
                                      "{{ cis_linux_common_service_name }}"],
                                     task["ansible.builtin.command"]["argv"])
                    self.assertFalse(task["changed_when"])
                    self.assertFalse(task["failed_when"])
                    self.assertFalse(task["check_mode"])
                    self.assertEqual("cis_linux_common_service_package in ansible_facts.packages",
                                     task["when"])
                payload = str(tasks[-1])
                self.assertIn("cis_linux_common_service_enabled.rc", payload)
                self.assertIn("cis_linux_common_service_active.rc", payload)
                self.assertNotIn("ansible_facts.services", payload)

    def test_oneshot_active_exited_counts_as_pass(self):
        audit = yaml.safe_load((MECHANISM / "audit.yml").read_text(encoding="utf-8"))
        classification = audit[-1]["ansible.builtin.debug"]["msg"]["classification"]
        verify = yaml.safe_load((MECHANISM / "verification.yml").read_text(
            encoding="utf-8"))
        condition = verify[-1]["ansible.builtin.assert"]["that"][0]
        env = Environment()
        for installed, enabled, active, expected in (
                (False, 1, 1, "NOT_APPLICABLE"),
                (True, 0, 0, "PASS"),
                (True, 0, 1, "FAIL"),
                (True, 1, 0, "FAIL")):
            with self.subTest(installed=installed, enabled=enabled, active=active):
                context = {
                    "cis_linux_common_service_package": "ufw",
                    "ansible_facts": {"packages": {"ufw": [{}]} if installed else {}},
                    "cis_linux_common_service_enabled": {"rc": enabled},
                    "cis_linux_common_service_active": {"rc": active},
                }
                self.assertEqual(expected, env.from_string(classification).render(
                    **context).strip())
                self.assertEqual(expected != "FAIL", bool(env.compile_expression(
                    condition)(**context)))


if __name__ == "__main__":
    unittest.main()
