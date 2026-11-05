"""Benchmark-alignment guards for the controls previously checked against
the wrong unit/package/parameter: CIS 2.1.9 (nfs-server.service unit),
2.1.10 (ypserv package), 2.1.20 (xserver-common package-only audit),
2.1.21 (loopback-only inet_interfaces + exim4 NOT_APPLICABLE route),
5.4.2.4 (`passwd -S root` P/L status instead of /etc/securetty), and the
6.2.2.3 <-> 6.2.2.4 parameter swap in auditd.conf.
"""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "roles/cis_linux_common/tasks"
DEBIAN = ROOT / "roles/cis_debian_12/tasks"
UBUNTU = ROOT / "roles/cis_ubuntu_2404/tasks"
LEDGER = ROOT / "cis/catalog/control-ledger.yml"

PHASES = ("audit.yml", "remediation.yml", "verification.yml")


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def wrapper_vars(path):
    tasks = read_yaml(path)
    collected = {}
    for task in tasks:
        if isinstance(task.get("ansible.builtin.import_role"), dict):
            collected.update(task.get("vars") or {})
    return collected


def mechanism_paths(path):
    return [task.get("ansible.builtin.import_tasks") for task in read_yaml(path)
            if isinstance(task.get("ansible.builtin.import_tasks"), str)]


def delegation_vars(path, mechanism):
    for task in read_yaml(path):
        imported = task.get("ansible.builtin.import_tasks")
        if isinstance(imported, str) and imported.endswith(mechanism):
            return task.get("vars", {})
    return {}


class ServiceDisabledGatesTest(unittest.TestCase):
    """2.1.9/2.1.10: the package and unit names the benchmark audits."""

    def test_nfs_uses_benchmark_package_and_unit(self):
        for base in (DEBIAN, UBUNTU):
            for phase in PHASES:
                with self.subTest(phase=phase, role=base.parts[-2]):
                    vars_ = wrapper_vars(
                        base / "sections/section_02_services/2_1_9_nfs_server" / phase)
                    # CIS Debian 12 v1.1.0 2.1.9 audits dpkg nfs-kernel-server
                    # and systemctl {is-enabled,is-active} nfs-server.service.
                    self.assertEqual("nfs-kernel-server",
                                     vars_["cis_linux_common_service_package"])
                    self.assertEqual("nfs-server.service",
                                     vars_["cis_linux_common_service_name"])

    def test_nis_gates_on_ypserv_package(self):
        for base in (DEBIAN, UBUNTU):
            for phase in PHASES:
                with self.subTest(phase=phase, role=base.parts[-2]):
                    vars_ = wrapper_vars(
                        base / "sections/section_02_services/2_1_10_nis_server" / phase)
                    # CIS Debian 12 v1.1.0 2.1.10 audits dpkg ypserv (not the
                    # `nis` meta-package), so a ypserv-only install is caught.
                    self.assertEqual("ypserv", vars_["cis_linux_common_service_package"])
                    self.assertEqual("ypserv.service",
                                     vars_["cis_linux_common_service_name"])


class XWindowPackageOnlyTest(unittest.TestCase):
    """2.1.20: the benchmark audits `dpkg-query -s xserver-common` only."""

    def test_common_delegates_to_package_absent(self):
        for phase in PHASES:
            imported = mechanism_paths(
                COMMON / "sections/section_02_services/2_1_20_x_window" / phase)
            with self.subTest(phase=phase):
                self.assertEqual(1, len(imported))
                self.assertTrue(imported[0].endswith(f"mechanisms/package_absent/{phase}"))

    def test_wrappers_gate_xserver_common_and_drop_service_vars(self):
        for base in (DEBIAN, UBUNTU):
            for phase in PHASES:
                with self.subTest(phase=phase, role=base.parts[-2]):
                    vars_ = wrapper_vars(
                        base / "sections/section_02_services/2_1_20_x_window" / phase)
                    self.assertEqual("xserver-common", vars_["cis_linux_common_package_name"])
                    self.assertNotIn("cis_linux_common_service_package", vars_)
                    self.assertNotIn("cis_linux_common_service_name", vars_)

    def test_routing_tags_and_ledger_follow_the_mechanism(self):
        for role in ("cis_debian_12", "cis_ubuntu_2404"):
            text = (ROOT / f"roles/{role}/tasks/main.yml").read_text(encoding="utf-8")
            for line in text.splitlines():
                if "cis_2_1_20" in line and "tags:" in line:
                    with self.subTest(role=role):
                        self.assertIn("package_absent", line)
                        self.assertNotIn("service_disabled", line)
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if '"control":"2.1.20"' in line:
                self.assertIn('"backend":"cis_linux_common.package_absent"', line)


class MtaLocalOnlyRouteTest(unittest.TestCase):
    """2.1.21: loopback-only is required and exim4 hosts are NOT_APPLICABLE."""

    LOOPBACK_RE = (
        r"(?i)^\s*inet_interfaces\s*=\s*"
        r"(loopback-only|127\.0\.0\.1|\[::1\]|::1|localhost)"
        r"(\s*,\s*(loopback-only|127\.0\.0\.1|\[::1\]|::1|localhost))*\s*$"
    )

    def test_audit_regexp_requires_loopback_values(self):
        vars_ = delegation_vars(
            COMMON / "sections/section_02_services/2_1_21_mta_local_only/audit.yml",
            "config_line/audit.yml")
        self.assertEqual(self.LOOPBACK_RE, vars_["cis_linux_common_config_line_regexp"])
        self.assertEqual("inet_interfaces = loopback-only", vars_["cis_linux_common_config_line"])
        self.assertEqual("/etc/postfix/main.cf", vars_["cis_linux_common_config_line_path"])

    def test_regexp_accepts_only_loopback_settings(self):
        # The benchmark audit FAILs an MTA bound to non-loopback interfaces;
        # the old '^inet_interfaces\s*=' regexp PASSed `inet_interfaces = all`.
        compliant = [
            "inet_interfaces = loopback-only",
            "inet_interfaces = localhost",
            "inet_interfaces = 127.0.0.1",
            "inet_interfaces = ::1, 127.0.0.1",
            "  inet_interfaces=loopback-only  ",
        ]
        non_compliant = [
            "inet_interfaces = all",
            "inet_interfaces = 0.0.0.0",
            "inet_interfaces = all, localhost",
            "inet_interfaces = loopback-only, 0.0.0.0",
        ]
        for line in compliant:
            with self.subTest(accept=line):
                self.assertTrue(re.search(self.LOOPBACK_RE, line, re.M))
        for line in non_compliant:
            with self.subTest(reject=line):
                self.assertIsNone(re.search(self.LOOPBACK_RE, line, re.M))

    def test_exim4_route_is_not_applicable_and_absent_mta_passes(self):
        tasks = read_yaml(
            COMMON / "sections/section_02_services/2_1_21_mta_local_only/audit.yml")
        text = str(tasks)
        # Benchmark remediation note: designed around postfix; exim4 hosts
        # must consult the installed MTA documentation -> NOT_APPLICABLE.
        self.assertIn("NOT_APPLICABLE", text)
        self.assertIn("exim4-base", text)
        self.assertIn("PASS", text)  # no MTA installed -> benchmark passing branch

    def test_remediation_replaces_bad_value_and_restarts_postfix(self):
        tasks = read_yaml(
            COMMON / "sections/section_02_services/2_1_21_mta_local_only/remediation.yml")
        vars_ = delegation_vars(
            COMMON / "sections/section_02_services/2_1_21_mta_local_only/remediation.yml",
            "config_line/remediation.yml")
        self.assertTrue(re.search(vars_["cis_linux_common_config_line_regexp"],
                                  "inet_interfaces = all", re.M))
        self.assertEqual("inet_interfaces = loopback-only", vars_["cis_linux_common_config_line"])
        # The benchmark remediation restarts postfix so the listening sockets
        # converge; the restart is gated on a previously non-loopback value.
        restart = [task for task in tasks
                   if isinstance(task.get("ansible.builtin.systemd"), dict)
                   and task["ansible.builtin.systemd"].get("state") == "restarted"]
        self.assertEqual(1, len(restart))
        self.assertEqual("postfix", restart[0]["ansible.builtin.systemd"]["name"])
        self.assertIn("not ansible_check_mode", restart[0]["when"])

    def test_wrappers_no_longer_supply_the_loose_regexp(self):
        for base in (DEBIAN, UBUNTU):
            for phase in PHASES:
                with self.subTest(phase=phase, role=base.parts[-2]):
                    vars_ = wrapper_vars(
                        base / "sections/section_02_services/2_1_21_mta_local_only" / phase)
                    self.assertNotIn("cis_linux_common_config_line_regexp", vars_)
                    self.assertNotIn("cis_linux_common_config_line", vars_)


class RootAccountStatusTest(unittest.TestCase):
    """5.4.2.4: passwd -S root with P/L status, not /etc/securetty."""

    STATUS_RE = "^(P|L)"

    def test_wrappers_run_benchmark_command(self):
        for base in (DEBIAN, UBUNTU):
            for phase in PHASES:
                with self.subTest(phase=phase, role=base.parts[-2]):
                    vars_ = wrapper_vars(
                        base / "sections/section_05_access_control/5_4_2_4_root_access_controlled"
                        / phase)
                    self.assertEqual("passwd -S root", vars_["cis_linux_common_account_command"])
                    self.assertEqual(self.STATUS_RE,
                                     vars_["cis_linux_common_account_status_regex"])
                    self.assertNotIn("securetty",
                                     vars_["cis_linux_common_account_command"])

    def test_status_token_semantics(self):
        # Mirror the mechanism's classification expression.
        for stdout, expected_pass in (
            ("root P 2026-01-01 0 99999 7 -1", True),
            ("root LK 2026-01-01 0 99999 7 -1", True),
            ("root L 2025-10-23 0 99999 7 -1", True),
            ("root NP 2026-01-01 0 99999 7 -1", False),
            ("root PS 2026-01-01", True),  # password set (never expired variant)
            ("", False),
            ("root", False),
        ):
            with self.subTest(stdout=stdout):
                token = (stdout.strip().split() + ["", ""])[1]
                self.assertEqual(bool(re.match(self.STATUS_RE, token)), expected_pass)

    def test_mechanism_escalates_and_branches_on_the_regex(self):
        for phase in ("audit.yml", "verification.yml"):
            text = (COMMON / "mechanisms/account_integrity" / phase).read_text(
                encoding="utf-8")
            with self.subTest(phase=phase):
                self.assertIn("become: true", text)
                self.assertIn("cis_linux_common_account_status_regex", text)

    def test_other_account_consumers_keep_empty_output_contract(self):
        # No other account_integrity wrapper may define the status regex, so
        # the 19 untouched consumers keep the empty-means-compliant semantics.
        for section in ("section_05_access_control", "section_07_maintenance"):
            for role in (DEBIAN, UBUNTU):
                for control in (role / "sections" / section).glob("*/audit.yml"):
                    if control.parent.name == "5_4_2_4_root_access_controlled":
                        continue
                    vars_ = wrapper_vars(control)
                    if "cis_linux_common_account_command" in vars_:
                        self.assertNotIn("cis_linux_common_account_status_regex", vars_,
                                         str(control))


class AuditdConfParameterMappingTest(unittest.TestCase):
    """6.2.2.3 owns disk_full_action/disk_error_action; 6.2.2.4 owns
    space_left_action/admin_space_left_action (benchmark v1.1.0/v1.0.0)."""

    SPACE_RE = r"^\s*space_left_action\s*=\s*(email|exec|single|halt)\b"
    ADMIN_RE = r"^\s*admin_space_left_action\s*=\s*(single|halt)\b"

    def test_6_2_2_3_checks_disk_actions_not_space_actions(self):
        for phase in PHASES:
            path = COMMON / "sections/section_06_logging/6_2_2_3_auditd_full_action" / phase
            text = str(read_yaml(path))
            with self.subTest(phase=phase):
                self.assertIn("disk_full_action", text)
                self.assertIn("disk_error_action", text)
                self.assertNotIn("space_left_action", text)
                self.assertNotIn("action_mail_acct", text)

    def test_6_2_2_3_value_sets_match_the_benchmark_greps(self):
        full = delegation_vars(
            COMMON / "sections/section_06_logging/6_2_2_3_auditd_full_action/audit.yml",
            "config_line/audit.yml")["cis_linux_common_config_line_regexp"]
        error = read_yaml(
            COMMON / "sections/section_06_logging/6_2_2_3_auditd_full_action/audit.yml"
        )[1]["vars"]["cis_linux_common_config_line_regexp"]
        self.assertEqual(r"(?i)^\s*disk_full_action\s*=\s*(halt|single)\b", full)
        self.assertEqual(r"(?i)^\s*disk_error_action\s*=\s*(syslog|single|halt)\b", error)
        # The real lab drift (SUSPEND) must now FAIL where it PASSed before.
        self.assertIsNone(re.search(full, "disk_full_action = SUSPEND", re.M))
        self.assertIsNone(re.search(error, "disk_error_action = suspend", re.M))
        self.assertTrue(re.search(full, "disk_full_action = halt", re.M))
        self.assertTrue(re.search(full, "Disk_Full_Action = SINGLE", re.M))
        self.assertTrue(re.search(error, "disk_error_action = syslog", re.M))
        self.assertTrue(re.search(error, "disk_error_action = halt", re.M))

    def test_6_2_2_3_remediation_replaces_noncompliant_values(self):
        tasks = read_yaml(
            COMMON / "sections/section_06_logging/6_2_2_3_auditd_full_action/remediation.yml")
        lines = [task["vars"]["cis_linux_common_config_line"] for task in tasks]
        self.assertEqual(["disk_full_action = halt", "disk_error_action = halt"], lines)
        for task in tasks:
            rx = task["vars"]["cis_linux_common_config_line_regexp"]
            self.assertTrue(re.search(rx, "disk_full_action = SUSPEND", re.M)
                            or re.search(rx, "disk_error_action = SUSPEND", re.M))

    def test_6_2_2_4_accepts_the_benchmark_value_sets(self):
        vars_ = delegation_vars(
            COMMON / "sections/section_06_logging/6_2_2_4_audit_space_warnings/audit.yml",
            "config_line/audit.yml")
        self.assertEqual(self.SPACE_RE, vars_["cis_linux_common_config_line_regexp"])
        tasks = read_yaml(
            COMMON / "sections/section_06_logging/6_2_2_4_audit_space_warnings/audit.yml")
        self.assertEqual(self.ADMIN_RE, tasks[1]["vars"]["cis_linux_common_config_line_regexp"])
        text = str(tasks)
        self.assertNotIn("disk_full_action", text)
        self.assertNotIn("disk_error_action", text)
        for line in ("space_left_action = email", "space_left_action = exec",
                     "space_left_action = single", "space_left_action = halt"):
            self.assertTrue(re.search(self.SPACE_RE, line, re.M), line)
        for line in ("space_left_action = suspend", "space_left_action = ignore",
                     "space_left_action = syslog"):
            self.assertIsNone(re.search(self.SPACE_RE, line, re.M), line)
        for line in ("admin_space_left_action = single", "admin_space_left_action = halt"):
            self.assertTrue(re.search(self.ADMIN_RE, line, re.M), line)
        for line in ("admin_space_left_action = email", "admin_space_left_action = suspend"):
            self.assertIsNone(re.search(self.ADMIN_RE, line, re.M), line)

    def test_6_2_2_4_remediation_targets_stay_benchmark_examples(self):
        tasks = read_yaml(
            COMMON / "sections/section_06_logging/6_2_2_4_audit_space_warnings/remediation.yml")
        lines = [task["vars"]["cis_linux_common_config_line"] for task in tasks]
        self.assertEqual(["space_left_action = email", "admin_space_left_action = halt"], lines)
        # Broad matchers so an existing non-compliant line is replaced in place.
        self.assertTrue(re.search(tasks[0]["vars"]["cis_linux_common_config_line_regexp"],
                                  "space_left_action = suspend", re.M))


class LedgerBackendStabilityTest(unittest.TestCase):
    """Only 2.1.20 changed backend; the rest keep their catalogued mechanism."""

    EXPECTED = {
        '"control":"2.1.9"': "cis_linux_common.service_disabled",
        '"control":"2.1.10"': "cis_linux_common.service_disabled",
        '"control":"2.1.21"': "cis_linux_common.config_line",
        '"control":"5.4.2.4"': "cis_linux_common.account_integrity",
        '"control":"6.2.2.3"': "cis_linux_common.config_line",
        '"control":"6.2.2.4"': "cis_linux_common.config_line",
    }

    def test_ledger_backends_unchanged_except_2_1_20(self):
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            for token, backend in self.EXPECTED.items():
                if token in line and '"control":"' in line:
                    self.assertIn(f'"backend":"{backend}"', line, token)


if __name__ == "__main__":
    unittest.main()
