"""Static guardrails for the isolated controller profile; never executes Ansible."""

from pathlib import Path
import posixpath
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class ControllerProfileTests(unittest.TestCase):
    def test_inventory_is_localhost_only(self):
        inventory = yaml.safe_load(
            (ROOT / "inventories/ansible_control/hosts.yml").read_text(encoding="utf-8")
        )
        hosts = inventory["all"]["children"]["ansible_control"]["hosts"]
        self.assertEqual(list(hosts), ["localhost"])
        self.assertEqual(hosts["localhost"]["ansible_host"], "127.0.0.1")
        self.assertEqual(hosts["localhost"]["ansible_connection"], "local")

    def test_playbook_guards_before_role(self):
        plays = yaml.safe_load(
            (ROOT / "playbooks/hardening/ansible_control_ubuntu_2404.yml").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(len(plays), 1)
        play = plays[0]
        self.assertEqual(play["hosts"], "localhost")
        self.assertEqual(play["connection"], "local")
        self.assertFalse(play["gather_facts"])
        self.assertEqual(play["roles"], ["ansible_control_ubuntu_2404"])
        guards = str(play["pre_tasks"])
        for required in ("ansible-control", "127.0.0.1", "Ubuntu", "24.04", "systemd"):
            self.assertIn(required, guards)

    def test_role_does_not_change_access_lifelines_or_wazuh(self):
        role = ROOT / "roles/ansible_control_ubuntu_2404"
        tasks = yaml.safe_load((role / "tasks/main.yml").read_text(encoding="utf-8"))
        handlers = yaml.safe_load((role / "handlers/main.yml").read_text(encoding="utf-8"))
        self.assertTrue(tasks)
        self.assertTrue(handlers)
        text = "\n".join(
            path.read_text(encoding="utf-8") for path in (role / "tasks").glob("*.yml")
        ).lower()
        for forbidden in ("/etc/ssh", "/etc/pam", "/etc/sudoers", "ufw", "nftables", "wazuh"):
            self.assertNotIn(forbidden, text)

    def test_runner_pins_version_and_enables_protected_log(self):
        runner = (ROOT / "scripts/run_ansible_control_hardening.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("ANSIBLE_PLAYBOOK_BIN", runner)
        self.assertIn("[core 2.21.2]", runner)
        self.assertIn("sudo \"$ANSIBLE_PLAYBOOK_BIN\" --version", runner)
        self.assertIn('sudo env ANSIBLE_LOG_PATH="$log_file"', runner)
        self.assertIn("-i inventories/ansible_control/hosts.yml", runner)
        self.assertNotIn("sudo ansible-playbook", runner)

    def test_runner_rejects_unsafe_existing_log_paths_before_mutation(self):
        runner = (ROOT / "scripts/run_ansible_control_hardening.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("sudo test -L /var", runner)
        self.assertIn("sudo test -L /var/log", runner)
        self.assertLess(runner.index('sudo test -L "$log_dir"'), runner.index('sudo install -d -o root -g root -m 0700 "$log_dir"'))
        self.assertLess(runner.index('sudo test -L "$log_file"'), runner.index('sudo install -o root -g root -m 0600 /dev/null "$log_file"'))
        self.assertIn("Existing Ansible log directory must be root:root 0700", runner)
        self.assertIn("Existing Ansible log file must be regular and root:root 0600", runner)
        self.assertNotIn("sudo chown root:root /var/log/ansible-control/ansible.log", runner)
        self.assertNotIn("sudo chmod 0600 /var/log/ansible-control/ansible.log", runner)

    def test_critical_policy_is_explicit_and_preflighted_first(self):
        role = ROOT / "roles/ansible_control_ubuntu_2404"
        defaults = yaml.safe_load((role / "defaults/main.yml").read_text(encoding="utf-8"))
        self.assertFalse(defaults["controller_critical_enabled"])
        self.assertFalse(defaults["controller_policy_approved"])
        self.assertEqual(defaults["controller_private_paths"], [])
        example = yaml.safe_load(
            (ROOT / "inventories/ansible_control/policy.example.yml").read_text(
                encoding="utf-8"
            )
        )
        self.assertFalse(example["controller_policy_approved"])
        main_tasks = yaml.safe_load((role / "tasks/main.yml").read_text(encoding="utf-8"))
        self.assertEqual(main_tasks[0]["ansible.builtin.import_tasks"], "log_preflight.yml")
        self.assertEqual(main_tasks[1]["ansible.builtin.import_tasks"], "critical_preflight.yml")
        self.assertEqual(main_tasks[-1]["ansible.builtin.import_tasks"], "critical_permissions.yml")
        preflight = yaml.safe_load(
            (role / "tasks/critical_preflight.yml").read_text(encoding="utf-8")
        )
        preflight_text = str(preflight)
        for expected in ("controller_policy_approved", "controller_repository_path", "controller_private_paths", "islnk", "pw_name", "gr_name", "item.stat.mode"):
            self.assertIn(expected, preflight_text)
        permissions = yaml.safe_load(
            (role / "tasks/critical_permissions.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(len(permissions), 1)
        for task in permissions:
            params = task["ansible.builtin.file"]
            self.assertIn("mode", params)
            self.assertNotIn("owner", params)
            self.assertNotIn("group", params)

    def test_critical_stage_cannot_chmod_arbitrary_privileged_paths(self):
        role = ROOT / "roles/ansible_control_ubuntu_2404"
        preflight = yaml.safe_load(
            (role / "tasks/critical_preflight.yml").read_text(encoding="utf-8")
        )
        guards = preflight[0]["ansible.builtin.assert"]["that"]
        self.assertIn(
            "controller_repository_path == (role_path | dirname | dirname | realpath)",
            guards,
        )
        self.assertIn(
            "controller_repository_path == (controller_repository_path | realpath)",
            guards,
        )
        self.assertIn(
            "controller_repository_path is match('^/(home|opt|srv)/[^/]+')",
            guards,
        )
        role_path = "/srv/institution/ansible/roles/ansible_control_ubuntu_2404"
        checkout = posixpath.dirname(posixpath.dirname(role_path))

        def allowed_repository_path(candidate):
            return (
                candidate == checkout
                and candidate == posixpath.normpath(candidate)
                and re.match(r"^/(home|opt|srv)/[^/]+", candidate) is not None
            )

        self.assertTrue(allowed_repository_path(checkout))
        for dangerous in ("/", "/./", "//", "/etc", "/etc/passwd", "/srv/institution/ansible/../.."):
            with self.subTest(path=dangerous):
                self.assertFalse(allowed_repository_path(dangerous))
        permission_text = (role / "tasks/critical_permissions.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("controller_private_paths", permission_text)
        self.assertNotIn("item.path", permission_text)

    def test_role_rejects_unsafe_log_before_mutation(self):
        role = ROOT / "roles/ansible_control_ubuntu_2404"
        checks = yaml.safe_load((role / "tasks/log_preflight.yml").read_text(encoding="utf-8"))
        text = str(checks)
        for required in ("follow", "islnk", "isreg", "isdir", "0700", "0600"):
            self.assertIn(required, text)

    def test_critical_runner_requires_private_approved_policy(self):
        runner = (ROOT / "scripts/run_ansible_control_hardening.sh").read_text(
            encoding="utf-8"
        )
        for expected in ("--critical", "0:0:600", "0:0:400", "controller_critical_enabled=true"):
            self.assertIn(expected, runner)

    def test_umask_only_applies_to_interactive_shells(self):
        tasks = yaml.safe_load(
            (ROOT / "roles/ansible_control_ubuntu_2404/tasks/main.yml").read_text(
                encoding="utf-8"
            )
        )
        umask_task = next(
            task for task in tasks
            if task.get("ansible.builtin.copy", {}).get("dest")
            == "/etc/profile.d/90-ansible-control-umask.sh"
        )
        content = umask_task["ansible.builtin.copy"]["content"]
        self.assertIn("case $- in", content)
        self.assertIn("*i*) umask 027 ;;", content)


if __name__ == "__main__":
    unittest.main()
