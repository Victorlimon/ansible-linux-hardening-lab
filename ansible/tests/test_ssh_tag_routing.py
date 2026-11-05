"""Exercise real Ansible routing against debug-only localhost stand-ins.

Run with: python -m unittest discover -s ansible/tests -v
Requires ansible-playbook on PATH; otherwise these runtime tests are skipped.
No original remediation body, inventory, connection, or handler is executed.
This proves route selection, not SSH remediation behavior on a target host.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

from test_remediation_gates import PLATFORMS, ROLES, read_yaml


ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")
SSH_TAGS = tuple(f"cis_5_1_{number}" for number in (1, 2, 3, 5, 6, 7, 8, 9, 10, 11))


@unittest.skipUnless(ANSIBLE_PLAYBOOK, "ansible-playbook unavailable; runtime proof pending")
class SshTagRoutingRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="ssh-routing-test-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.playbooks = {}
        self.controls = {}
        self.values = {}
        for role in PLATFORMS:
            main = read_yaml(ROLES / role / "tasks/main.yml")
            tasks = [deepcopy(task) for task in main if "ansible.builtin.assert" in task]
            self.controls[role] = {}
            for task in main:
                source = task.get("ansible.builtin.import_tasks", "")
                if not source.endswith("/remediation.yml"):
                    continue
                matching = set(SSH_TAGS).intersection(task.get("tags", []))
                if not matching:
                    continue
                self.assertEqual(1, len(matching), "A control route has multiple SSH tags")
                tag = matching.pop()
                control = role + "_" + Path(source).parent.name
                self.controls[role][tag] = control
                stub = self.root / role / source
                stub.parent.mkdir(parents=True, exist_ok=True)
                stub.write_text(yaml.safe_dump([{
                    "name": "Record selected control without executing remediation",
                    "ansible.builtin.debug": {"msg": "SSH_ROUTE=" + tag},
                }]), encoding="utf-8")
                route = deepcopy(task)
                route["ansible.builtin.import_tasks"] = str(stub)
                tasks.append(route)
            self.assertEqual(set(SSH_TAGS), set(self.controls[role]))
            defaults = read_yaml(ROLES / role / "defaults/main.yml")
            values = {key: True for key, value in defaults.items() if isinstance(value, bool)}
            values.update({
                role + "_execution_mode": "remediation",
                role + "_remediation_enabled": True,
                "ansible_facts": {
                    "distribution": "Ubuntu" if role == "cis_ubuntu_2404" else "Debian",
                    "distribution_version": "24.04" if role == "cis_ubuntu_2404" else "12",
                    "distribution_major_version": "24" if role == "cis_ubuntu_2404" else "12",
                    "architecture": "x86_64",
                },
            })
            self.values[role] = values
            playbook = self.root / (role + ".yml")
            playbook.write_text(yaml.safe_dump([{
                "name": "Controller-only SSH routing regression",
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "become": False, "tasks": tasks,
            }]), encoding="utf-8")
            self.playbooks[role] = playbook
        self.config = self.root / "ansible.cfg"
        self.config.write_text("[defaults]\nstdout_callback=default\nretry_files_enabled=False\n",
                               encoding="utf-8")

    def run_case(self, role, tags, expected, overrides=None, rejected=None):
        variables = self.root / "vars.json"
        variables.write_text(json.dumps(self.values[role] | (overrides or {})), encoding="utf-8")
        environment = os.environ.copy()
        environment.update({"ANSIBLE_CONFIG": str(self.config), "ANSIBLE_NOCOLOR": "1",
                            "ANSIBLE_DEPRECATION_WARNINGS": "True"})
        result = subprocess.run(
            [ANSIBLE_PLAYBOOK, str(self.playbooks[role]), "-i", "localhost,", "-c", "local",
             "--tags", ",".join(tags), "-e", "@" + str(variables)],
            cwd=self.root, env=environment, capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        if rejected:
            self.assertNotEqual(0, result.returncode, output)
            failure = re.search(r"fatal: \[localhost\]: FAILED! =>\s*(\{)", output)
            self.assertIsNotNone(failure, output)
            result_data, _ = json.JSONDecoder().raw_decode(output[failure.start(1):])
            self.assertEqual(rejected, result_data.get("assertion"), output)
            self.assertIs(result_data.get("evaluated_to"), False, output)
            self.assertIs(result_data.get("changed"), False, output)
            self.assertNotIn("SSH_ROUTE=", output)
        else:
            self.assertEqual(0, result.returncode, output)
        self.assertNotIn("[DEPRECATION WARNING]", output)
        observed = re.findall(r'"msg": "SSH_ROUTE=(cis_5_1_\d+)"', output)
        self.assertCountEqual(expected, observed, output)

    def test_individual_tags_and_disabled_controls(self):
        for role in PLATFORMS:
            for tag in SSH_TAGS:
                with self.subTest(role=role, tag=tag):
                    self.run_case(role, [tag], [tag])
                    self.run_case(role, [tag], [], {self.controls[role][tag]: False})

    def test_combined_tags_and_master_gate(self):
        for role in PLATFORMS:
            with self.subTest(role=role):
                self.run_case(role, SSH_TAGS[:2], SSH_TAGS[:2])
                self.run_case(role, SSH_TAGS, SSH_TAGS)
                self.run_case(role, ["sshd"], SSH_TAGS)
                self.run_case(role, SSH_TAGS, [], {role + "_remediation_enabled": False})
                self.run_case(role, ["all"], [], rejected=(
                    f"not ({role}_remediation_enabled | bool) or 'all' not in ansible_run_tags"))
                self.run_case(role, ["all"], [], {role + "_remediation_enabled": False})

    def test_audit_verification_and_debian_canary_cannot_remediate(self):
        for role in PLATFORMS:
            for mode in ("audit", "verification"):
                with self.subTest(role=role, mode=mode):
                    self.run_case(role, SSH_TAGS, [], {
                        role + "_execution_mode": mode, role + "_remediation_enabled": False,
                    })
        self.run_case("cis_debian_12", SSH_TAGS, [],
                      {"cis_debian_12_canary_confirmed": False}, rejected=(
                          "not (cis_debian_12_remediation_enabled | bool) or "
                          "cis_debian_12_canary_confirmed | bool"))


if __name__ == "__main__":
    unittest.main()
