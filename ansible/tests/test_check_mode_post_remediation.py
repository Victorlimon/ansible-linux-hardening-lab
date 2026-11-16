"""Contract: post-remediation assertions must not run in --check mode.

In check mode commands such as pam-auth-update are only simulated, so asserting
the remediated state fails on any host that still needs the change. The
independent verify/ playbooks and real runs keep asserting it.
"""
import unittest
from pathlib import Path

import yaml

TASKS = Path(__file__).resolve().parents[1] / "roles" / "cis_linux_common" / "tasks"
# Post-state assertions named differently from "Verify the remediated ...".
EXTRA_POST_STATE = {
    "6_3_1_aide_installed": "Verify AIDE install and initialization",
    "6_3_3_aide_crypto": "Verify sha512 rules for the audit tools",
}


def post_remediation_asserts():
    for path in sorted(TASKS.glob("**/remediation.yml")):
        extra = EXTRA_POST_STATE.get(path.parent.name)
        for task in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
            name = task.get("name", "")
            if "ansible.builtin.assert" in task and (
                    "Verify the remediated" in name or (extra and extra in name)):
                yield path.parent.name, task


def conditions(task):
    when = task.get("when", [])
    return when if isinstance(when, list) else [when]


class CheckModePostRemediationTests(unittest.TestCase):
    def test_known_post_remediation_asserts_are_found(self):
        found = {name for name, _ in post_remediation_asserts()}
        self.assertTrue({"pam_faillock_stack", "pam_pwhistory_stack", "pwquality_parameter",
                         "faillock_parameter", "login_defs_parameter",
                         "6_3_1_aide_installed", "6_3_3_aide_crypto"} <= found)

    def test_every_post_remediation_assert_skips_check_mode(self):
        for name, task in post_remediation_asserts():
            with self.subTest(mechanism=name):
                self.assertIn("not ansible_check_mode", conditions(task))


if __name__ == "__main__":
    unittest.main()
