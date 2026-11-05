"""Focused source-contract tests for the CIS pam_pwhistory family.

Covers controls 5.3.2.4 (pam-auth-update profile stack) and 5.3.3.3.1-.3
(the remember/enforce_for_root/use_authtok arguments of the same canonical
line). These tests validate the repository contracts only: the exact
benchmark profile content, rendered-stack ordering and strictness regexes,
inline-variant rejection, fail-closed scanning, idempotent command guards,
and the rule that no task writes directly into /etc/pam.d. Guest behaviour
is verified separately by the verify playbooks.

Run inside ansible-control:
    /home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover \
        -s ansible/tests -p 'test_cis_pam_pwhistory_family.py' -v
"""

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ansible" / "roles" / "cis_linux_common" / "tasks"
STACK = COMMON / "mechanisms" / "pam_pwhistory_stack"
PARAM = COMMON / "mechanisms" / "pwhistory_parameter"
SECTIONS = COMMON / "sections" / "section_05_access_control"
DEBIAN = ROOT / "ansible" / "roles" / "cis_debian_12"
UBUNTU = ROOT / "ansible" / "roles" / "cis_ubuntu_2404"

PWHISTORY_PROFILE = (
    "Name: pwhistory password history checking\n"
    "Default: yes\n"
    "Priority: 1024\n"
    "Password-Type: Primary\n"
    "Password:\n"
    " requisite pam_pwhistory.so remember=24 enforce_for_root "
    "try_first_pass use_authtok\n"
)
CANONICAL = ("password requisite pam_pwhistory.so remember=24 "
             "enforce_for_root try_first_pass use_authtok")


def load_tasks(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def task_by_fragment(tasks, fragment):
    matches = [task for task in tasks if fragment in task.get("name", "")]
    if not matches:
        raise AssertionError(f"no task matching {fragment!r}")
    return matches


class StackProfileContractTest(unittest.TestCase):
    def test_profile_matches_benchmark(self):
        tasks = load_tasks(STACK / "remediation.yml")
        copies = task_by_fragment(tasks, "pam-auth-update profile")
        self.assertEqual(len(copies), 1)
        copy = copies[0]["ansible.builtin.copy"]
        self.assertEqual(copy["dest"], "/usr/share/pam-configs/pwhistory")
        self.assertEqual(copy["content"], PWHISTORY_PROFILE)
        self.assertEqual(copy["owner"], "root")
        self.assertEqual(copy["group"], "root")
        self.assertEqual(copy["mode"], "0644")

    def test_no_direct_pam_d_writes(self):
        mutable = {"ansible.builtin.lineinfile", "ansible.builtin.copy",
                   "ansible.builtin.template", "ansible.builtin.blockinfile",
                   "ansible.builtin.replace", "ansible.builtin.assemble"}
        for path in (STACK / "remediation.yml", PARAM / "remediation.yml"):
            for task in load_tasks(path):
                for module, args in task.items():
                    if module in mutable and isinstance(args, dict):
                        target = str(args.get("dest", args.get("path", "")))
                        self.assertFalse(
                            target.startswith("/etc/pam.d"),
                            f"{path.name} writes {target} directly",
                        )

    def test_pam_auth_update_is_guarded(self):
        tasks = load_tasks(STACK / "remediation.yml")
        commands = [task for task in task_by_fragment(tasks, "pam-auth-update")
                    if "ansible.builtin.command" in task]
        self.assertEqual(len(commands), 1)
        command = commands[0]
        argv = command["ansible.builtin.command"]["argv"]
        for token in ("pam-auth-update", "--enable", "pwhistory"):
            self.assertIn(token, argv)
        self.assertIn("cis_linux_common_pwhistory_pam_auth_update_force", argv,
                      "--force must stay behind the explicit operator gate")
        self.assertEqual(command["environment"], {"DEBIAN_FRONTEND": "noninteractive"})
        self.assertIs(command["changed_when"], True)
        joined = yaml.dump(command["when"])
        self.assertIn("cis_linux_common_pwhistory_stack_ok", joined)
        self.assertIn("pwhistory_profile.changed", joined)

    def test_remediation_and_verification_reinspect_stack(self):
        for name in ("remediation.yml", "verification.yml"):
            text = (STACK / name).read_text(encoding="utf-8")
            self.assertIn("mechanisms/pam_pwhistory_stack/inspect.yml", text)
        remediation = (STACK / "remediation.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(
            remediation.count("mechanisms/pam_pwhistory_stack/inspect.yml"), 2,
            "remediation must re-evaluate the stack after pam-auth-update",
        )

    def test_parameter_remediation_owns_only_the_profile(self):
        # The 5.3.3.3.x remediations must not duplicate the profile content:
        # they import the 5.3.2.4 stack remediation (single ownership) and
        # then evaluate their own parameter evidence.
        text = (PARAM / "remediation.yml").read_text(encoding="utf-8")
        self.assertIn("mechanisms/pam_pwhistory_stack/remediation.yml", text)
        self.assertIn("mechanisms/pwhistory_parameter/evaluate.yml", text)
        self.assertNotIn("pam_pwhistory_parameter", text)
        self.assertNotIn("ansible.builtin.copy", text)
        for name in ("audit.yml", "verification.yml"):
            body = (PARAM / name).read_text(encoding="utf-8")
            self.assertIn("mechanisms/pam_pwhistory_stack/inspect.yml", body)
            self.assertIn("pwhistory_parameter/evaluate.yml", body)


class StackEvidenceRegexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tasks = load_tasks(STACK / "inspect.yml")
        evidence = next(task for task in tasks
                        if "stack evidence" in task.get("name", ""))
        facts = evidence["ansible.builtin.set_fact"]
        cls.canonical = re.compile(cls._extract(
            facts["cis_linux_common_pwhistory_canonical_count"]))
        cls.total = re.compile(cls._extract(
            facts["cis_linux_common_pwhistory_line_total"]))
        signature = facts["cis_linux_common_pwhistory_password_signature"]
        cls.token = re.compile(next(
            item for item in re.findall(r"'([^']*)'", signature)
            if item.startswith("pam_pwquality")))
        override = next(task for task in tasks
                        if "non-canonical pam_pwhistory" in task.get("name", ""))
        cls.override = re.compile(
            override["vars"]["cis_linux_common_pwhistory_override_regex"])

    @staticmethod
    def _extract(text):
        quoted = re.findall(r"'([^']*)'", text)
        return next(item for item in quoted if "\\" in item)

    def test_canonical_regex_accepts_rendered_forms(self):
        self.assertTrue(self.canonical.match(CANONICAL))
        wide = ("password\trequisite\t\t\tpam_pwhistory.so remember=24 "
                "enforce_for_root try_first_pass use_authtok")
        self.assertTrue(self.canonical.match(wide))

    def test_canonical_regex_rejects_variants(self):
        for bad in (
            "password required pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so remember=10 enforce_for_root "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so enforce_for_root remember=24 "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so remember=24 enforce_for_root use_authtok",
            "password requisite pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok silent",
            "password requisite pam_pwhistory.soremember=24 enforce_for_root "
            "try_first_pass use_authtok",
        ):
            self.assertIsNone(self.canonical.match(bad), bad)

    def test_total_counts_password_module_lines(self):
        self.assertTrue(self.total.match("password requisite pam_pwhistory.so x"))
        self.assertIsNone(self.total.match("auth required pam_faillock.so"))
        self.assertIsNone(self.total.match("# password requisite pam_pwhistory.so"))

    def test_signature_classifies_password_lines(self):
        cases = {
            "password requisite pam_pwquality.so retry=3": "pam_pwquality.so",
            CANONICAL: "pam_pwhistory.so",
            "password [success=1 default=ignore] pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt": "pam_unix.so",
        }
        for line, expected in cases.items():
            self.assertEqual(self.token.findall(line)[-1], expected, line)

    def test_override_regex_rejects_variant_lines(self):
        bad = [
            "password required pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so remember=10 enforce_for_root "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so enforce_for_root remember=24 "
            "try_first_pass use_authtok",
            " requisite pam_pwhistory.so remember=24 enforce_for_root use_authtok",
            " requisite pam_pwhistory.so remember=50 enforce_for_root "
            "try_first_pass use_authtok",
        ]
        for line in bad:
            self.assertTrue(self.override.search(line + "\n"), line)

    def test_override_regex_accepts_canonical_and_unrelated_lines(self):
        good = [
            CANONICAL,
            "password\trequisite\t\t\tpam_pwhistory.so remember=24 "
            "enforce_for_root try_first_pass use_authtok",
            " requisite pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok",
            "# password requisite pam_pwhistory.so remember=10 was removed",
            "password requisite pam_pwquality.so retry=3",
            "password [success=1 default=ignore] pam_unix.so obscure use_authtok "
            "try_first_pass yescrypt",
            "auth required pam_faillock.so preauth deny=5",
        ]
        for line in good:
            self.assertIsNone(self.override.search(line + "\n"), line)

    def test_override_regex_is_line_bounded(self):
        multiline = (CANONICAL + "\n"
                     "reordered remember=24 enforce_for_root is prose\n")
        self.assertIsNone(self.override.search(multiline))

    def test_fail_safe_scan_guards(self):
        inspect_text = (STACK / "inspect.yml").read_text(encoding="utf-8")
        self.assertIn("failed_when: false", inspect_text)
        self.assertIn("skip_missing=true", inspect_text)
        self.assertIn("default('', true)", inspect_text)
        self.assertIn("difference(cis_linux_common_pwhistory_read_files)",
                      inspect_text.replace("\n         ", " "))

    def test_stack_verdict_requires_exact_lines_and_order(self):
        tasks = load_tasks(STACK / "inspect.yml")
        verdict = next(task for task in tasks if "stack verdict" in task["name"])
        joined = " ".join(str(verdict["ansible.builtin.set_fact"][
            "cis_linux_common_pwhistory_stack_ok"]).split())
        for guard in (
            "cis_linux_common_pwhistory_unreadable_files | length == 0",
            "cis_linux_common_pwhistory_override_files | length == 0",
            "cis_linux_common_pwhistory_canonical_count == 1",
            "cis_linux_common_pwhistory_line_total == 1",
            "cis_linux_common_pwhistory_unix_password_count >= 1",
            "cis_linux_common_pwhistory_password_signature == "
            "['pam_pwquality.so', 'pam_pwhistory.so', 'pam_unix.so']",
        ):
            self.assertIn(guard, joined)


class ParameterEvidenceTest(unittest.TestCase):
    CONTROLS = {
        "5_3_3_3_1_pwhistory_remember": ("remember", r"\bremember=\d+\b"),
        "5_3_3_3_2_pwhistory_enforce_root": ("enforce_for_root", r"\benforce_for_root\b"),
        "5_3_3_3_3_pwhistory_use_authtok": ("use_authtok", r"\buse_authtok\b"),
    }

    def test_section_wires_parameters_to_canonical_line(self):
        for control, (param, name_regex) in self.CONTROLS.items():
            for mode in ("audit.yml", "remediation.yml", "verification.yml"):
                vars_ = load_tasks(SECTIONS / control / mode)[0]["vars"]
                self.assertEqual(vars_["cis_linux_common_pwhistory_param"], param)
                self.assertEqual(
                    vars_["cis_linux_common_pwhistory_name_regex"], name_regex)
                self.assertEqual(
                    vars_["cis_linux_common_pwhistory_value_regex"],
                    r"^\s*password\s+requisite\s+pam_pwhistory\.so\s+remember=24"
                    r"\s+enforce_for_root\s+try_first_pass\s+use_authtok\s*$")

    def test_parameter_regexes_bound_the_canonical_line(self):
        value = re.compile(
            r"^\s*password\s+requisite\s+pam_pwhistory\.so\s+remember=24"
            r"\s+enforce_for_root\s+try_first_pass\s+use_authtok\s*$")
        self.assertTrue(value.match(CANONICAL))
        self.assertTrue(value.match(
            "password\trequisite\tpam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok "))
        for bad in (
            "password requisite pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass",
            "# password requisite pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok",
            "password requisite pam_pwhistory.so remember=24 enforce_for_root "
            "try_first_pass use_authtok debug",
        ):
            self.assertIsNone(value.match(bad), bad)
        remembered = re.compile(r"\bremember=\d+\b")
        self.assertTrue(remembered.search(CANONICAL))
        self.assertIsNone(remembered.search(
            "password requisite pam_pwhistory.so enforce_for_root use_authtok"))

    def test_parameter_verdict_is_fail_closed(self):
        tasks = load_tasks(PARAM / "evaluate.yml")
        verdict = next(task for task in tasks
                       if "parameter verdict" in task["name"])
        joined = " ".join(str(verdict["ansible.builtin.set_fact"][
            "cis_linux_common_pwhistory_parameter_ok"]).split())
        for guard in (
            "cis_linux_common_pwhistory_unreadable_files | length == 0",
            "cis_linux_common_pwhistory_override_files | length == 0",
            "cis_linux_common_pwhistory_line_total == 1",
            "cis_linux_common_pwhistory_param_named_count == 1",
            "cis_linux_common_pwhistory_param_compliant_count == 1",
        ):
            self.assertIn(guard, joined)


class RoutingContractTest(unittest.TestCase):
    def test_section_files_route_dedicated_mechanisms(self):
        mapping = {
            "5_3_2_4_pam_pwhistory": "mechanisms/pam_pwhistory_stack",
            "5_3_3_3_1_pwhistory_remember": "mechanisms/pwhistory_parameter",
            "5_3_3_3_2_pwhistory_enforce_root": "mechanisms/pwhistory_parameter",
            "5_3_3_3_3_pwhistory_use_authtok": "mechanisms/pwhistory_parameter",
        }
        for control, mechanism in mapping.items():
            for mode in ("audit.yml", "remediation.yml", "verification.yml"):
                tasks = load_tasks(SECTIONS / control / mode)
                imported = tasks[0]["ansible.builtin.import_tasks"]
                self.assertTrue(imported.startswith(mechanism), imported)

    def test_platform_wrappers_pass_pwhistory_variables(self):
        for role, benchmark in ((DEBIAN, "CIS Debian Linux 12 Benchmark v1.1.0"),
                                (UBUNTU, "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0")):
            for control in ("5_3_2_4_pam_pwhistory", "5_3_3_3_1_pwhistory_remember",
                            "5_3_3_3_2_pwhistory_enforce_root",
                            "5_3_3_3_3_pwhistory_use_authtok"):
                for mode in ("audit.yml", "remediation.yml", "verification.yml"):
                    tasks = load_tasks(
                        role / "tasks" / "sections" / "section_05_access_control" / control / mode)
                    vars_ = tasks[0]["vars"]
                    self.assertEqual(vars_["cis_linux_common_benchmark"], benchmark)
                    self.assertNotIn("cis_linux_common_config_line_path", vars_)
                    self.assertNotIn("cis_linux_common_config_line_package", vars_)
                    self.assertEqual(
                        vars_["cis_linux_common_pwhistory_package"], "libpam-modules")

    def test_gates_and_selectors_preserved(self):
        for role, prefix in ((DEBIAN, "cis_debian_12"), (UBUNTU, "cis_ubuntu_2404")):
            defaults = yaml.safe_load((role / "defaults" / "main.yml").read_text(encoding="utf-8"))
            for control in ("5_3_2_4_pam_pwhistory", "5_3_3_3_1_pwhistory_remember",
                            "5_3_3_3_2_pwhistory_enforce_root",
                            "5_3_3_3_3_pwhistory_use_authtok"):
                self.assertIs(defaults[f"{prefix}_{control}"], True)
                self.assertIs(defaults[f"{prefix}_{control}_remediate"], False)
            main = (role / "tasks" / "main.yml").read_text(encoding="utf-8")
            for control in ("5_3_2_4", "5_3_3_3_1", "5_3_3_3_2", "5_3_3_3_3"):
                tag_lines = [line for line in main.splitlines() if f"cis_{control}," in line]
                self.assertTrue(tag_lines, control)
                for line in tag_lines:
                    self.assertIn("gated_unsafe", line)

    def test_ledger_generator_routes_family(self):
        text = (ROOT / "ansible" / "scripts" / "generate_ledger.py").read_text(encoding="utf-8")
        for rule in ('("5.3.2.4", "pam_pwhistory_stack")',
                    ('("5.3.3.3.1", "pwhistory_parameter")'),
                    ('("5.3.3.3.2", "pwhistory_parameter")'),
                    ('("5.3.3.3.3", "pwhistory_parameter")')):
            self.assertIn(rule, text)
        self.assertLess(text.index('"5.3.2.4", "pam_pwhistory_stack"'),
                        text.index('("5.3.", "config_line")'))

    def test_generated_ledger_artifacts_route_family(self):
        # The generator source is not enough: the committed artifacts must
        # carry the dedicated PAM backends, otherwise runtime routing tables
        # still point the family at config_line.
        catalog = ROOT / "ansible" / "cis" / "catalog"
        with (catalog / "control-ledger.yml").open(encoding="utf-8") as handle:
            ledger = json.load(handle)
        expected_backend = {
            "5.3.2.4": "cis_linux_common.pam_pwhistory_stack",
            "5.3.3.3.1": "cis_linux_common.pwhistory_parameter",
            "5.3.3.3.2": "cis_linux_common.pwhistory_parameter",
            "5.3.3.3.3": "cis_linux_common.pwhistory_parameter",
        }
        seen = {}
        for route in ledger["controls"]:
            control = route["control"]
            if control in expected_backend:
                self.assertEqual(
                    route["route"]["backend"], expected_backend[control],
                    f"{route['platform']} {control} {route['route']['mode']}")
                seen.setdefault((route["platform"], control), set()).add(
                    route["route"]["mode"])
        for platform in ("debian-12", "ubuntu-24.04"):
            for control in expected_backend:
                self.assertEqual(
                    seen.get((platform, control)),
                    {"audit", "remediation", "verification"},
                    f"{platform} {control} mode coverage")
        with (catalog / "semantic-review.yml").open(encoding="utf-8") as handle:
            review = json.load(handle)
        self.assertEqual(review["ledger_digest"], ledger["ledger_id"],
                         "semantic-review must bind to the regenerated ledger")
        reviewed = {entry["control"] for entry in review["reviews"]}
        for control in expected_backend:
            self.assertIn(control, reviewed,
                          f"{control} lost its semantic-common review")


if __name__ == "__main__":
    unittest.main()
