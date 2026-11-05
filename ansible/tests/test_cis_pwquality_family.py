"""Focused source-contract tests for the CIS pwquality family (5.3.3.2.x).

Covers the seven automated controls 5.3.3.2.1 difok, .2 minlen, .4
maxrepeat, .5 maxsequence, .6 dictcheck, .7 enforcing and .8
enforce_for_root, all routed through the shared
mechanisms/pwquality_parameter inspection, plus the rule that 5.3.3.2.3
(complexity, Manual) stays on manual_observation. These tests validate the
repository contracts only: the exact benchmark bounded value sets, the
forbidden-inline pam_pwquality.so argument regexes, duplicate-line and
unreadable-corpus fail-closed semantics, the set_fact split that fixed the
same-task crash, and the ledger/tag consistency of the migrated backend.
Guest behaviour is verified separately by the verify playbooks.

Run inside ansible-control:
    /home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover \
        -s ansible/tests -p 'test_cis_pwquality_family.py' -v
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ansible" / "roles" / "cis_linux_common" / "tasks"
PARAM = COMMON / "mechanisms" / "pwquality_parameter"
SECTIONS = COMMON / "sections" / "section_05_access_control"
DEBIAN = ROOT / "ansible" / "roles" / "cis_debian_12"
UBUNTU = ROOT / "ansible" / "roles" / "cis_ubuntu_2404"
LEDGER = ROOT / "ansible" / "cis" / "catalog" / "control-ledger.yml"
DEBIAN_MAIN = DEBIAN / "tasks" / "main.yml"
UBUNTU_MAIN = UBUNTU / "tasks" / "main.yml"

MODES = ("audit", "remediation", "verification")

# control dir -> (param, kind, canonical line, managed drop-in name)
EXPECTED = {
    "5_3_3_2_1_pwquality_difok": (
        "difok", "numeric_min", "difok = 2",
        "/etc/security/pwquality.conf.d/50-pwdifok.conf"),
    "5_3_3_2_2_pwquality_minlen": (
        "minlen", "numeric_min", "minlen = 14",
        "/etc/security/pwquality.conf.d/50-pwlength.conf"),
    "5_3_3_2_4_pwquality_maxrepeat": (
        "maxrepeat", "numeric_max", "maxrepeat = 3",
        "/etc/security/pwquality.conf.d/50-pwrepeat.conf"),
    "5_3_3_2_5_pwquality_maxsequence": (
        "maxsequence", "numeric_max", "maxsequence = 3",
        "/etc/security/pwquality.conf.d/50-pwmaxsequence.conf"),
    "5_3_3_2_6_pwquality_dictcheck": (
        "dictcheck", "not_zero", "dictcheck = 1",
        "/etc/security/pwquality.conf.d/50-pwdictcheck.conf"),
    "5_3_3_2_7_pwquality_enforcing": (
        "enforcing", "not_zero", "enforcing = 1",
        "/etc/security/pwquality.conf.d/50-pwenforcing.conf"),
    "5_3_3_2_8_pwquality_enforce_root": (
        "enforce_for_root", "flag", "enforce_for_root",
        "/etc/security/pwquality.conf.d/50-pwroot.conf"),
}


def load_tasks(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def delegation_vars(path):
    tasks = load_tasks(path)
    assert len(tasks) == 1, path
    task = tasks[0]
    import_tasks = task["ansible.builtin.import_tasks"]
    assert str(import_tasks).endswith("mechanisms/pwquality_parameter/"
                                      "audit.yml") or \
        str(import_tasks).startswith("mechanisms/pwquality_parameter/")
    return task["vars"]


class ControlVarsContractTest(unittest.TestCase):
    def test_three_modes_carry_identical_vars(self):
        for ctl in EXPECTED:
            base = None
            for mode in MODES:
                vars_ = delegation_vars(SECTIONS / ctl / f"{mode}.yml")
                if base is None:
                    base = vars_
                else:
                    self.assertEqual(base, vars_, f"{ctl}/{mode} vars drift")

    def test_benchmark_params_and_managed_files(self):
        for ctl, (param, kind, line, managed) in EXPECTED.items():
            vars_ = delegation_vars(SECTIONS / ctl / "audit.yml")
            self.assertEqual(vars_["cis_linux_common_pwq_param"], param)
            self.assertEqual(vars_["cis_linux_common_pwq_kind"], kind)
            self.assertEqual(vars_["cis_linux_common_pwq_line"], line)
            self.assertEqual(
                vars_["cis_linux_common_pwq_managed_path"], managed)
            self.assertEqual(
                vars_["cis_linux_common_pwq_name_regex"],
                f"(?mi)^[ \\t]*{param}\\b.*$")

    def test_numeric_value_sets_match_the_benchmark_greps(self):
        difok = delegation_vars(
            SECTIONS / "5_3_3_2_1_pwquality_difok" / "audit.yml")
        for ok in ("difok = 2", "difok = 9", "difok=10", "difok = 100"):
            self.assertRegex(ok, difok["cis_linux_common_pwq_value_regex"])
        for bad in ("difok = 1", "difok = 0", "difok 2 = 3"):
            self.assertNotRegex(bad, difok["cis_linux_common_pwq_value_regex"])

        minlen = delegation_vars(
            SECTIONS / "5_3_3_2_2_pwquality_minlen" / "audit.yml")
        for ok in ("minlen = 14", "minlen = 19", "minlen=20", "minlen = 99",
                   "minlen = 100", "minlen = 9999"):
            self.assertRegex(ok, minlen["cis_linux_common_pwq_value_regex"])
        for bad in ("minlen = 13", "minlen = 8", "minlen = 0"):
            self.assertNotRegex(bad, minlen["cis_linux_common_pwq_value_regex"])

        for ctl in ("5_3_3_2_4_pwquality_maxrepeat",
                    "5_3_3_2_5_pwquality_maxsequence"):
            vars_ = delegation_vars(SECTIONS / ctl / "audit.yml")
            rx = vars_["cis_linux_common_pwq_value_regex"]
            for ok in ("maxrepeat = 1", "maxrepeat = 2", "maxrepeat=3"):
                self.assertRegex(ok.replace("maxrepeat",
                                            vars_["cis_linux_common_pwq_param"]),
                                 rx)
            for bad in ("maxrepeat = 0", "maxrepeat = 4", "maxrepeat = 10",
                        "maxrepeat = 100"):
                self.assertNotRegex(
                    bad.replace("maxrepeat",
                                vars_["cis_linux_common_pwq_param"]), rx)

    def test_not_zero_controls_forbid_only_zero(self):
        for ctl in ("5_3_3_2_6_pwquality_dictcheck",
                    "5_3_3_2_7_pwquality_enforcing"):
            vars_ = delegation_vars(SECTIONS / ctl / "audit.yml")
            forbidden = vars_["cis_linux_common_pwq_forbidden_regex"]
            param = vars_["cis_linux_common_pwq_param"]
            self.assertRegex(f"{param} = 0", forbidden)
            self.assertRegex(f"{param} =0", forbidden)
            for ok in (f"{param} = 1", f"{param} = 2", f"{param} = 01"):
                self.assertNotRegex(ok, forbidden)
            self.assertEqual(
                vars_["cis_linux_common_pwq_inline_bad_regex"]
                .count("password"), 1, "inline forbidden arg must be scanned")

    def test_enforce_for_root_flag_semantics(self):
        vars_ = delegation_vars(
            SECTIONS / "5_3_3_2_8_pwquality_enforce_root" / "audit.yml")
        self.assertRegex("enforce_for_root",
                         vars_["cis_linux_common_pwq_value_regex"])
        self.assertRegex("enforce_for_root   ",
                         vars_["cis_linux_common_pwq_value_regex"])
        self.assertNotRegex("enforce_for_root = 1",
                            vars_["cis_linux_common_pwq_value_regex"])
        for bad in ("enforce_for_root = 0", "enforce_for_root=false",
                    "enforce_for_root = No"):
            self.assertRegex(bad, vars_["cis_linux_common_pwq_forbidden_regex"])

    def test_inline_override_regexes_carry_benchmark_value_sets(self):
        difok_inline = delegation_vars(
            SECTIONS / "5_3_3_2_1_pwquality_difok" / "audit.yml")[
            "cis_linux_common_pwq_inline_bad_regex"]
        hit = ("password requisite pam_pwquality.so retry=3 difok = 1")
        self.assertRegex(hit, difok_inline)
        self.assertRegex(
            "password requisite pam_pwquality.so difok=0", difok_inline)
        self.assertNotRegex(
            "password requisite pam_pwquality.so difok = 2", difok_inline)
        minlen_inline = delegation_vars(
            SECTIONS / "5_3_3_2_2_pwquality_minlen" / "audit.yml")[
            "cis_linux_common_pwq_inline_bad_regex"]
        self.assertRegex("password requisite pam_pwquality.so minlen=13",
                         minlen_inline)
        self.assertNotRegex("password requisite pam_pwquality.so minlen=14",
                            minlen_inline)


class MechanismSemanticsTest(unittest.TestCase):
    def test_evaluated_before_action_split(self):
        tasks = load_tasks(PARAM / "evaluate.yml")
        ok_tasks = [i for i, task in enumerate(tasks)
                    if "cis_linux_common_pwq_parameter_ok" in
                    task.get("ansible.builtin.set_fact", {})]
        action_tasks = [i for i, task in enumerate(tasks)
                        if "cis_linux_common_pwq_action" in
                        task.get("ansible.builtin.set_fact", {})]
        self.assertEqual(len(ok_tasks), 1)
        self.assertEqual(len(action_tasks), 1)
        # The action must be a separate, LATER task: one shared set_fact
        # would read parameter_ok while it is still undefined (the recorded
        # same-task crash).
        self.assertLess(ok_tasks[0], action_tasks[0])
        action_body = yaml.safe_dump(tasks[action_tasks[0]])
        self.assertIn("cis_linux_common_pwq_parameter_ok", action_body)

    def test_fail_closed_evidence_in_remediation(self):
        tasks = load_tasks(PARAM / "remediation.yml")
        names = "\n".join(task.get("name", "") for task in tasks)
        text = (PARAM / "remediation.yml").read_text(encoding="utf-8")
        self.assertIn("Fail closed on blocked evidence", names)
        self.assertIn("inline_override_files", text)
        self.assertIn("unreadable_files", text)
        # remediation re-inspects and re-evaluates after writing
        for fragment in ("Inspect the corpus before remediation",
                         "Inspect the corpus after remediation",
                         "Compute pre-remediation evidence",
                         "Compute post-remediation evidence"):
            self.assertIn(fragment, names)

    def test_no_task_writes_into_pam_d(self):
        mutable = {"ansible.builtin.lineinfile", "ansible.builtin.copy",
                   "ansible.builtin.replace", "ansible.builtin.template"}
        for task in load_tasks(PARAM / "remediation.yml"):
            for module, args in task.items():
                if module in mutable and isinstance(args, dict):
                    target = str(args.get("path", args.get("dest", "")))
                    self.assertFalse(target.startswith("/etc/pam.d"),
                                     f"pwquality remediation writes {target}")

    def test_complexity_control_stays_manual(self):
        for mode, mechanism in (("audit", "manual_observation"),
                                ("verification", "manual_observation")):
            tasks = load_tasks(SECTIONS / "5_3_3_2_3_pwquality_complexity"
                               / f"{mode}.yml")
            self.assertTrue(
                str(tasks[0]["ansible.builtin.import_tasks"])
                .endswith(f"mechanisms/{mechanism}/{mode}.yml"))
        self.assertFalse((SECTIONS / "5_3_3_2_3_pwquality_complexity"
                          / "remediation.yml").exists())


class PlatformWiringTest(unittest.TestCase):
    def test_wrappers_supply_the_corpus_inputs(self):
        for role, platform in ((DEBIAN, "debian_12"), (UBUNTU, "ubuntu_2404")):
            for ctl, (param, _k, _l, _m) in EXPECTED.items():
                for mode in MODES:
                    path = (role / "tasks" / "sections"
                            / "section_05_access_control" / ctl
                            / f"{mode}.yml")
                    tasks = load_tasks(path)
                    vars_ = tasks[0]["vars"]
                    self.assertEqual(
                        vars_["cis_linux_common_pwq_main_file"],
                        "/etc/security/pwquality.conf")
                    self.assertEqual(
                        vars_["cis_linux_common_pwq_conf_d"],
                        "/etc/security/pwquality.conf.d")
                    self.assertEqual(
                        vars_["cis_linux_common_pwq_package"],
                        "libpam-pwquality")
                    self.assertEqual(vars_["cis_linux_common_platform"],
                                     platform)

    def test_main_tags_route_through_the_shared_mechanism(self):
        for main in (DEBIAN_MAIN, UBUNTU_MAIN):
            text = main.read_text(encoding="utf-8")
            for control_tag in ("cis_5_3_3_2_1", "cis_5_3_3_2_2",
                                "cis_5_3_3_2_4", "cis_5_3_3_2_5",
                                "cis_5_3_3_2_6", "cis_5_3_3_2_7",
                                "cis_5_3_3_2_8"):
                for m in re.finditer(rf"\b{control_tag}, (\w+)", text):
                    self.assertEqual(m.group(1), "pwquality_parameter",
                                     f"{main.name}: {control_tag}")

    def test_ledger_backends_are_pwquality_parameter(self):
        text = LEDGER.read_text(encoding="utf-8")
        for control in ("5.3.3.2.1", "5.3.3.2.2", "5.3.3.2.4", "5.3.3.2.5",
                        "5.3.3.2.6", "5.3.3.2.7", "5.3.3.2.8"):
            pattern = (rf'"control":"{control}"'
                       r'.*?"backend":"cis_linux_common\.(\w+)"')
            backends = set(re.findall(pattern, text))
            self.assertEqual(backends, {"pwquality_parameter"}, control)
        pattern = (r'"control":"5.3.3.2.3".*?"backend":"cis_linux_common'
                   r'(\.\w+)"')
        self.assertEqual(set(re.findall(pattern, text)),
                         {".manual_observation"})


if __name__ == "__main__":
    unittest.main()
