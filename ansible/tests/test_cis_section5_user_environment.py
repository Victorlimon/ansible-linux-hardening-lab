"""Focused source-contract tests for CIS 5.4 user-account environment
controls: the login.defs shadow-password-suite family (5.4.1.1 PASS_MAX_DAYS,
5.4.1.3 PASS_WARN_AGE, 5.4.1.4 ENCRYPT_METHOD via the shared
mechanisms/login_defs_parameter), the Manual 5.4.1.2 PASS_MIN_DAYS (stays on
manual_observation, audit+verification only, no remediation route), and the
shell-corpus controls 5.4.3.2 TMOUT / 5.4.3.3 default umask (shared
mechanisms/script_line). These tests validate repository contracts only:
the bounded benchmark value sets, in-place lineinfile replacement against
shadow-utils first-occurrence semantics, read-only /etc/shadow probes, the
benchmark TMOUT/umask regex translations, the script_line accumulator reset
that makes remediation's double inspection deterministic, and tag/ledger
consistency. Guest behaviour is verified separately by the verify playbooks.

Run inside ansible-control:
    /home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover \
        -s ansible/tests -p 'test_cis_section5_user_environment.py' -v
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ansible" / "roles" / "cis_linux_common" / "tasks"
LOGINDEFS = COMMON / "mechanisms" / "login_defs_parameter"
SCRIPTLINE = COMMON / "mechanisms" / "script_line"
SECTIONS = COMMON / "sections" / "section_05_access_control"
DEBIAN = ROOT / "ansible" / "roles" / "cis_debian_12"
UBUNTU = ROOT / "ansible" / "roles" / "cis_ubuntu_2404"
LEDGER = ROOT / "ansible" / "cis" / "catalog" / "control-ledger.yml"
DEBIAN_MAIN = DEBIAN / "tasks" / "main.yml"
UBUNTU_MAIN = UBUNTU / "tasks" / "main.yml"

LOGINDEFS_CONTROLS = {
    "5_4_1_1_pass_max_days": "5.4.1.1",
    "5_4_1_3_pass_warn_age": "5.4.1.3",
    "5_4_1_4_encrypt_method": "5.4.1.4",
}
SCRIPT_CONTROLS = {
    "5_4_3_2_shell_timeout": "5.4.3.2",
    "5_4_3_3_default_umask": "5.4.3.3",
}
MODES = ("audit", "remediation", "verification")


def load_tasks(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def delegation(path, mechanism_dir, mode):
    tasks = load_tasks(path)
    assert len(tasks) == 1, path
    task = tasks[0]
    assert str(task["ansible.builtin.import_tasks"]).endswith(
        f"{mechanism_dir}/{mode}.yml"), path
    return task["vars"]


class LoginDefsFamilyContractTest(unittest.TestCase):
    def test_modes_carry_identical_vars(self):
        for ctl in LOGINDEFS_CONTROLS:
            base = None
            for mode in MODES:
                vars_ = delegation(SECTIONS / ctl / f"{mode}.yml",
                                   "mechanisms/login_defs_parameter", mode)
                if base is None:
                    base = vars_
                else:
                    self.assertEqual(base, vars_, f"{ctl}/{mode} drift")

    def test_pass_max_days_value_set(self):
        vars_ = delegation(
            SECTIONS / "5_4_1_1_pass_max_days" / "audit.yml",
            "mechanisms/login_defs_parameter", "audit")
        self.assertEqual(vars_["cis_linux_common_logindefs_param"],
                         "PASS_MAX_DAYS")
        self.assertEqual(vars_["cis_linux_common_logindefs_line"],
                         "PASS_MAX_DAYS 365")
        rx = vars_["cis_linux_common_logindefs_value_regex"]
        for ok in ("PASS_MAX_DAYS 1", "PASS_MAX_DAYS\t90",
                   "PASS_MAX_DAYS   365", "PASS_MAX_DAYS 360",
                   "PASS_MAX_DAYS 100"):
            self.assertRegex(ok, rx)
        for bad in ("PASS_MAX_DAYS 99999", "PASS_MAX_DAYS 0",
                    "PASS_MAX_DAYS 366", "PASS_MAX_DAYS 1000",
                    "PASS_MAX_DAYS -1"):
            self.assertNotRegex(bad, rx)
        # the lineinfile regexp must match ANY active value line so the
        # first-occurrence-wins parse of shadow-utils cannot be defeated by
        # an appended line
        line_rx = vars_["cis_linux_common_logindefs_line_regexp"]
        self.assertRegex("PASS_MAX_DAYS\t99999", line_rx)
        self.assertNotRegex("  # PASS_MAX_DAYS 99999",
                            vars_["cis_linux_common_logindefs_active_regex"])
        self.assertIn("chage --maxdays 365",
                      vars_["cis_linux_common_logindefs_shadow_fix_cmd"])
        self.assertIn("$5 > 365 || $5 < 1",
                      vars_["cis_linux_common_logindefs_shadow_cmd"])

    def test_pass_warn_age_value_set(self):
        vars_ = delegation(
            SECTIONS / "5_4_1_3_pass_warn_age" / "audit.yml",
            "mechanisms/login_defs_parameter", "audit")
        rx = vars_["cis_linux_common_logindefs_value_regex"]
        for ok in ("PASS_WARN_AGE 7", "PASS_WARN_AGE\t9",
                   "PASS_WARN_AGE   14", "PASS_WARN_AGE 365"):
            self.assertRegex(ok, rx)
        for bad in ("PASS_WARN_AGE 6", "PASS_WARN_AGE 0",
                    "PASS_WARN_AGE -1"):
            self.assertNotRegex(bad, rx)
        self.assertIn("chage --warndays 7",
                      vars_["cis_linux_common_logindefs_shadow_fix_cmd"])

    def test_encrypt_method_accepts_sha512_or_yescrypt(self):
        vars_ = delegation(
            SECTIONS / "5_4_1_4_encrypt_method" / "audit.yml",
            "mechanisms/login_defs_parameter", "audit")
        rx = vars_["cis_linux_common_logindefs_value_regex"]
        for ok in ("ENCRYPT_METHOD SHA512", "ENCRYPT_METHOD\tYESCRYPT",
                   "ENCRYPT_METHOD yescrypt"):
            self.assertRegex(ok, rx)
        for bad in ("ENCRYPT_METHOD MD5", "ENCRYPT_METHOD BCRYPT",
                    "ENCRYPT_METHOD SHA256"):
            self.assertNotRegex(bad, rx)
        self.assertEqual(vars_["cis_linux_common_logindefs_shadow_cmd"], "")
        self.assertEqual(vars_["cis_linux_common_logindefs_shadow_fix_cmd"],
                         "")

    def test_remediation_is_guarded_and_fail_closed(self):
        tasks = load_tasks(LOGINDEFS / "remediation.yml")
        names = [next(iter(task)) + ":" + task.get("name", "") for task in tasks]
        joined = "\n".join(names)
        self.assertIn("Fail closed on blocked evidence", joined)
        fail_task = [t for t in tasks
                     if "Fail closed" in t.get("name", "")][0]
        self.assertTrue(any("active_lines" in str(cond)
                            for cond in fail_task["when"]))
        fix = [t for t in tasks
               if "Align existing accounts" in t.get("name", "")][0]
        self.assertIn("cis_linux_common_logindefs_shadow_violations | length > 0",
                      str(fix["when"]))
        inspect = LOGINDEFS / "inspect.yml"
        text = inspect.read_text(encoding="utf-8")
        self.assertIn("changed_when: false", text)


class ManualMinDaysTest(unittest.TestCase):
    def test_stays_on_manual_observation(self):
        for mode in ("audit", "verification"):
            tasks = load_tasks(SECTIONS / "5_4_1_2_min_password_days"
                               / f"{mode}.yml")
            self.assertTrue(str(tasks[0]["ansible.builtin.import_tasks"])
                            .endswith(f"mechanisms/manual_observation/{mode}.yml"))
        self.assertFalse((SECTIONS / "5_4_1_2_min_password_days"
                          / "remediation.yml").exists())

    def test_wrappers_pass_manual_path(self):
        for role in (DEBIAN, UBUNTU):
            for mode in ("audit", "verification"):
                path = (role / "tasks" / "sections" / "section_05_access_control"
                        / "5_4_1_2_min_password_days" / f"{mode}.yml")
                vars_ = load_tasks(path)[0]["vars"]
                self.assertEqual(vars_["cis_linux_common_manual_path"],
                                 "/etc/login.defs")
                self.assertNotIn("cis_linux_common_config_line_path", vars_)

    def test_no_remediation_include_anywhere(self):
        for main in (DEBIAN_MAIN, UBUNTU_MAIN):
            text = main.read_text(encoding="utf-8")
            self.assertNotIn("5_4_1_2_min_password_days/remediation.yml",
                             text)


class ScriptLineMechanismTest(unittest.TestCase):
    def test_accumulators_are_reset(self):
        tasks = load_tasks(SCRIPTLINE / "inspect.yml")
        names = [task.get("name", "") for task in tasks]
        reset_idx = next(i for i, n in enumerate(names)
                         if "Reset the per-inspection accumulators" in n)
        scan_idx = next(i for i, n in enumerate(names)
                        if "Discover profile.d shell files" in n)
        self.assertLess(reset_idx, scan_idx)
        reset = tasks[reset_idx]["ansible.builtin.set_fact"]
        for key in ("cis_linux_common_script_corpus",
                    "cis_linux_common_script_required_hits",
                    "cis_linux_common_script_or_files",
                    "cis_linux_common_script_forbidden_files"):
            self.assertIn(key, reset)

    def test_extra_files_are_not_forbidden_scanned(self):
        text = (SCRIPTLINE / "inspect.yml").read_text(encoding="utf-8")
        self.assertIn("cis_linux_common_script_forbidden_corpus", text)
        self.assertIn("rejectattr('path', 'in',\n                      "
                      "cis_linux_common_script_extra_files", text)

    def test_tmout_control_translates_the_benchmark_script(self):
        vars_ = delegation(SECTIONS / "5_4_3_2_shell_timeout" / "audit.yml",
                           "mechanisms/script_line", "audit")
        required = vars_["cis_linux_common_script_required_regexps"]
        self.assertEqual(len(required), 3)
        good = vars_["cis_linux_common_script_managed_content"]
        self.assertEqual(good, "TMOUT=900\nreadonly TMOUT\nexport TMOUT\n")
        for rx in required:
            self.assertRegex(good, rx)
        single = "readonly TMOUT=900 ; export TMOUT\n"
        for rx in required:
            self.assertRegex(single, rx)
        forbidden = vars_["cis_linux_common_script_forbidden_regexps"][0]
        for bad in ("TMOUT=901", "TMOUT=0", "TMOUT=3600", "TMOUT=1000",
                    "export TMOUT=1800"):
            self.assertRegex(bad, forbidden)
        self.assertNotRegex("TMOUT=900", forbidden)
        self.assertNotRegex("# TMOUT=901", forbidden)
        self.assertEqual(vars_["cis_linux_common_script_managed_path"],
                         "/etc/profile.d/50-tmout.sh")
        self.assertEqual(vars_["cis_linux_common_script_extra_files"], [])

    def test_umask_control_precedence_inputs(self):
        vars_ = delegation(SECTIONS / "5_4_3_3_default_umask" / "audit.yml",
                           "mechanisms/script_line", "audit")
        required = vars_["cis_linux_common_script_required_regexps"]
        self.assertEqual(len(required), 1)
        good = vars_["cis_linux_common_script_managed_content"]
        self.assertEqual(good, "umask 027\n")
        self.assertRegex("umask 027", required[0])
        self.assertRegex("umask 027 # site note", required[0])
        self.assertRegex("umask 077", required[0])
        self.assertRegex("umask u=rwx,g=rx,o=", required[0])
        self.assertNotRegex("umask 022", required[0])
        forbidden = vars_["cis_linux_common_script_forbidden_regexps"][0]
        for bad in ("umask 022", "umask 002", "umask 000", "umask 0000",
                    "umask 006", "umask u=rwx,g=rwx,o=rwx"):
            self.assertRegex(bad, forbidden)
        self.assertNotRegex("umask 027", forbidden)
        # a bare "umask 0" is neither compliant nor forbidden for the
        # benchmark greps; it still yields no compliant file, so the
        # classification fails closed
        self.assertNotRegex("umask 0", forbidden)
        self.assertNotRegex("umask 0", required[0])
        or_rx = vars_["cis_linux_common_script_or_regexps"][0]
        self.assertRegex("session optional pam_umask.so umask=027", or_rx)
        self.assertNotRegex("session optional pam_umask.so", or_rx)
        self.assertEqual(vars_["cis_linux_common_script_extra_files"],
                         ["/etc/login.defs", "/etc/pam.d/postlogin",
                          "/etc/default/login"])
        self.assertEqual(vars_["cis_linux_common_script_managed_path"],
                         "/etc/profile.d/50-systemwide_umask.sh")
        # the packaged login.defs UMASK 022 would match the forbidden scan
        # if login.defs were not an excluded lower-precedence location
        self.assertRegex("UMASK\t\t022", forbidden)


class PlatformWiringTest(unittest.TestCase):
    def test_wrappers_no_longer_pass_config_line_inputs(self):
        for role in (DEBIAN, UBUNTU):
            for ctl in list(LOGINDEFS_CONTROLS) + list(SCRIPT_CONTROLS):
                for path in (role / "tasks" / "sections"
                             / "section_05_access_control" / ctl).glob("*.yml"):
                    vars_ = load_tasks(path)[0]["vars"]
                    self.assertNotIn("cis_linux_common_config_line_path",
                                     vars_, path)

    def test_main_tags_match_the_new_backends(self):
        expectations = {
            "cis_5_4_1_1": "login_defs_parameter",
            "cis_5_4_1_2": "manual_observation",
            "cis_5_4_1_3": "login_defs_parameter",
            "cis_5_4_1_4": "login_defs_parameter",
            "cis_5_4_3_2": "script_line",
            "cis_5_4_3_3": "script_line",
        }
        for main in (DEBIAN_MAIN, UBUNTU_MAIN):
            text = main.read_text(encoding="utf-8")
            for control_tag, backend in expectations.items():
                for m in re.finditer(rf"\b{control_tag}, (\w+)", text):
                    self.assertEqual(m.group(1), backend,
                                     f"{main.name}: {control_tag}")

    def test_ledger_backends(self):
        text = LEDGER.read_text(encoding="utf-8")
        for ctl_map in (LOGINDEFS_CONTROLS, SCRIPT_CONTROLS):
            for control in ctl_map.values():
                pattern = (rf'"control":"{control}"'
                           r'.*?"backend":"cis_linux_common\.(\w+)"')
                backends = set(re.findall(pattern, text))
                self.assertTrue(backends, control)
        for control, backend in (("5.4.1.1", "login_defs_parameter"),
                                 ("5.4.1.2", "manual_observation"),
                                 ("5.4.1.3", "login_defs_parameter"),
                                 ("5.4.1.4", "login_defs_parameter"),
                                 ("5.4.3.2", "script_line"),
                                 ("5.4.3.3", "script_line")):
            pattern = (rf'"control":"{control}"'
                       r'.*?"backend":"cis_linux_common\.(\w+)"')
            self.assertEqual(set(re.findall(pattern, text)), {backend},
                             control)
        # 5.4.1.2 must not have a remediation route (manual: two modes)
        self.assertNotIn('"control":"5.4.1.2","memberships":{"raw":'
                         '["level_2_server","level_2_workstation"],'
                         '"expanded":["level_2_server","level_2_workstation"]}'
                         ',"disposition":"manual","applicability":"always"'
                         ',"route":{"mode":"remediation"', text)


if __name__ == "__main__":
    unittest.main()
