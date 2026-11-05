"""Regression tests for the CIS logging choice and UFW sysctl precedence."""

from pathlib import Path
import base64
import re
import unittest

from jinja2 import Environment
import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"


def tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class LoggingSysctlConsistencyTest(unittest.TestCase):
    def test_journald_profile_does_not_start_rsyslog_later(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            with self.subTest(platform=platform):
                defaults = tasks(ROLES / platform / "defaults/main.yml")
                self.assertEqual("journald", defaults["cis_linux_common_logging_system"])
                self.assertTrue(defaults[f"{platform}_6_1_1_4_single_logging_system"])
                self.assertTrue(defaults[f"{platform}_6_1_1_1_journald_enabled"])
                self.assertTrue(defaults[f"{platform}_6_1_2_3_compress"])
                for control in range(1, 9):
                    selector = next(
                        key for key in defaults
                        if key.startswith(f"{platform}_6_1_3_{control}_")
                    )
                    self.assertFalse(defaults[selector], selector)

    def test_logging_control_requires_selected_system_running(self):
        control = ROLES / "cis_linux_common/tasks/sections/section_06_logging/6_1_1_4_single_logging_system"
        audit = tasks(control / "audit.yml")
        verification = tasks(control / "verification.yml")
        self.assertIn("['journald', 'rsyslog']",
                      str(audit[1]["ansible.builtin.assert"]["that"]))
        conditions = verification[1]["ansible.builtin.assert"]["that"]
        self.assertIn("cis_linux_common_logging_selected_running", conditions)
        self.assertIn("not cis_linux_common_logging_competing_running", conditions)
        facts = audit[2]["ansible.builtin.set_fact"]

        def compliant(system, running):
            services = {name: {"state": "running"} for name in running}
            context = {"cis_linux_common_logging_system": system,
                       "ansible_facts": {"services": services}}
            selected = Environment().from_string(
                facts["cis_linux_common_logging_selected_running"]
            ).render(**context).strip() == "True"
            competing = Environment().from_string(
                facts["cis_linux_common_logging_competing_running"]
            ).render(**context).strip() == "True"
            return selected and not competing

        self.assertFalse(compliant("journald", set()))
        self.assertFalse(compliant("rsyslog", set()))
        self.assertTrue(compliant("journald", {"systemd-journald.service"}))
        self.assertFalse(compliant("journald", {"systemd-journald.service", "rsyslog.service"}))
        self.assertTrue(compliant("rsyslog", {"systemd-journald.service", "rsyslog.service"}))
        self.assertFalse(compliant("rsyslog", {"rsyslog.service", "syslog-ng.service"}))

        remediation = tasks(control / "remediation.yml")
        self.assertTrue(any("cis_linux_common_logging_system == 'rsyslog'" in str(task.get("when", ""))
                            and "ansible.builtin.systemd" in task for task in remediation))
        journald_gate = next(task for task in remediation
                             if "journald is selected but not running" in str(task))
        rsyslog_start = next(task for task in remediation
                             if task.get("ansible.builtin.systemd", {}).get("name") == "rsyslog.service")
        self.assertIn("not ansible_check_mode", journald_gate["when"])
        self.assertIn("not ansible_check_mode or 'rsyslog.service' in ansible_facts.services",
                      rsyslog_start["when"])

    def test_ufw_installation_reconciles_existing_cis_sysctl(self):
        installer = tasks(ROLES / "cis_ubuntu_2404/tasks/sections/section_04_firewall/4_2_1_ufw_installed/remediation.yml")
        self.assertIn("4_2_1_ufw_installed/remediation.yml", str(installer[0]))
        self.assertEqual("sections/section_03_network/3_3_9_log_martians/remediation.yml",
                         installer[1]["ansible.builtin.import_tasks"])
        self.assertIn("cis_firewall == 'ufw'", installer[1]["when"])
        self.assertIn("cis_ubuntu_2404_3_3_9_log_martians | bool", installer[1]["when"])
        self.assertIn("not ansible_check_mode or 'ufw' in ansible_facts.packages",
                      installer[1]["when"])
        may_reconcile = Environment().compile_expression(installer[1]["when"][-1])
        self.assertTrue(may_reconcile(ansible_check_mode=False,
                                      ansible_facts={"packages": {}}))
        self.assertFalse(may_reconcile(ansible_check_mode=True,
                                       ansible_facts={"packages": {}}))
        self.assertTrue(may_reconcile(ansible_check_mode=True,
                                      ansible_facts={"packages": {"ufw": ["installed"]}}))

    def test_ufw_override_is_inspected_and_corrected_after_sysctl(self):
        mechanism = ROLES / "cis_linux_common/tasks/mechanisms/sysctl_parameter"
        remediation = tasks(mechanism / "remediation.yml")
        inspector = next(i for i, task in enumerate(remediation)
                         if "inspect.yml" in str(task))
        sysctl = next(i for i, task in enumerate(remediation)
                      if "ansible.posix.sysctl" in task)
        ufw = next(i for i, task in enumerate(remediation)
                   if "ansible.builtin.lineinfile" in task)
        self.assertLess(inspector, sysctl)
        self.assertLess(sysctl, ufw)
        override = remediation[ufw]
        self.assertEqual("{{ cis_linux_common_sysctl_ufw_path }}",
                         override["ansible.builtin.lineinfile"]["path"])
        self.assertIn("cis_linux_common_sysctl_ufw_path | length > 0",
                      str(override["when"]))

        expression = override["ansible.builtin.lineinfile"]["regexp"]
        rendered = Environment().from_string(expression).render(
            cis_linux_common_sysctl_parameter="net.ipv4.conf.all.log_martians"
        ).strip()
        self.assertRegex("net/ipv4/conf/all/log_martians=0", rendered)
        self.assertRegex("net.ipv4.conf.all.log_martians = 0", rendered)
        self.assertNotRegex("# net/ipv4/conf/all/log_martians=0", rendered)

        inspection_tasks = tasks(mechanism / "inspect.yml")
        selected = next(i for i, task in enumerate(inspection_tasks)
                        if task.get("name", "").endswith("Select the UFW sysctl path"))
        whitelist = next(i for i, task in enumerate(inspection_tasks)
                         if task.get("name", "").endswith("Reject unapproved UFW sysctl path"))
        file_stat = next(i for i, task in enumerate(inspection_tasks)
                         if task.get("name", "").endswith("Inspect the selected UFW sysctl file"))
        regular = next(i for i, task in enumerate(inspection_tasks)
                       if task.get("name", "").endswith("Validate the selected UFW sysctl file"))
        file_slurp = next(i for i, task in enumerate(inspection_tasks)
                          if task.get("name", "").endswith("Read the selected UFW sysctl file"))
        self.assertLess(selected, whitelist)
        self.assertLess(whitelist, file_stat)
        self.assertLess(file_stat, regular)
        self.assertLess(regular, file_slurp)
        allowed = Environment().compile_expression(
            inspection_tasks[whitelist]["ansible.builtin.assert"]["that"])
        self.assertTrue(allowed(cis_linux_common_sysctl_ufw_path="/etc/ufw/sysctl.conf"))
        self.assertFalse(allowed(cis_linux_common_sysctl_ufw_path="/etc/private/secret"))
        constraints = inspection_tasks[regular]["ansible.builtin.assert"]["that"]
        self.assertIn("stat.isreg", str(constraints))
        self.assertIn("stat.islnk", str(constraints))
        candidates = next(task for task in inspection_tasks
                          if task.get("name", "").endswith("Derive persistent configuration candidates"))
        extract_paths = candidates["ansible.builtin.set_fact"]["cis_linux_common_sysctl_ufw_paths"]
        environment = Environment()
        environment.filters["b64decode"] = lambda data: base64.b64decode(data).decode("utf-8")
        environment.filters["regex_findall"] = lambda data, pattern: re.findall(pattern, data)
        defaults = "IPT_SYSCTL=/etc/ufw/sysctl.conf\nIPT_SYSCTL=/etc/private/secret\n"
        paths = yaml.safe_load(environment.from_string(extract_paths).render(
            cis_linux_common_sysctl_ufw_defaults_stat={"stat": {"exists": True}},
            cis_linux_common_sysctl_ufw_defaults_slurp={
                "content": base64.b64encode(defaults.encode("utf-8")).decode("ascii")
            },
        ))
        self.assertEqual(["/etc/ufw/sysctl.conf", "/etc/private/secret"], paths)
        path_selection = inspection_tasks[selected]["ansible.builtin.set_fact"]["cis_linux_common_sysctl_ufw_path"]
        self.assertEqual("/etc/private/secret", Environment().from_string(path_selection).render(
            cis_linux_common_sysctl_ufw_paths=paths
        ).strip())
        empty_last = defaults + "IPT_SYSCTL=\n"
        empty_paths = yaml.safe_load(environment.from_string(extract_paths).render(
            cis_linux_common_sysctl_ufw_defaults_stat={"stat": {"exists": True}},
            cis_linux_common_sysctl_ufw_defaults_slurp={
                "content": base64.b64encode(empty_last.encode("utf-8")).decode("ascii")
            },
        ))
        self.assertEqual("", Environment().from_string(path_selection).render(
            cis_linux_common_sysctl_ufw_paths=empty_paths
        ).strip())
        command = next(task for task in inspection_tasks
                       if "ansible.builtin.command" in task)
        self.assertFalse(command["check_mode"])
        inspection_text = (mechanism / "inspect.yml").read_text(encoding="utf-8")
        self.assertIn("cis_linux_common_sysctl_parameter | replace('.', '[./]')",
                      inspection_text)
        self.assertIn("cis_linux_common_sysctl_ufw_values | last", inspection_text)

    def test_ufw_sysctl_value_stops_at_line_end(self):
        inspection_tasks = tasks(
            ROLES / "cis_linux_common/tasks/mechanisms/sysctl_parameter/inspect.yml"
        )
        derivation = next(
            task for task in inspection_tasks
            if task.get("name", "").endswith("Derive UFW override values")
        )
        expression = derivation["ansible.builtin.set_fact"]["cis_linux_common_sysctl_ufw_values"]
        environment = Environment()
        environment.filters["b64decode"] = lambda data: base64.b64decode(data).decode("utf-8")
        environment.filters["regex_findall"] = lambda data, pattern: re.findall(pattern, data)
        content = "net/ipv4/tcp_syncookies=1\nnet/ipv4/conf/all/log_martians=1\n"
        values = yaml.safe_load(environment.from_string(expression).render(
            cis_linux_common_sysctl_parameter="net.ipv4.tcp_syncookies",
            cis_linux_common_sysctl_ufw_file_stat={"stat": {"exists": True}},
            cis_linux_common_sysctl_ufw_file_slurp={
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii")
            },
        ))
        self.assertEqual(["1"], values)
        effective = next(
            task for task in inspection_tasks
            if task.get("name", "").endswith("Select the effective persistent value")
        )["ansible.builtin.set_fact"]["cis_linux_common_sysctl_persistent_value"]
        self.assertEqual("1", environment.from_string(effective).render(
            cis_linux_common_sysctl_ufw_values=values,
            cis_linux_common_sysctl_systemd_values=["0"],
        ).strip())


if __name__ == "__main__":
    unittest.main()
