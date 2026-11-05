"""CIS 5.2.7 su restriction must require both the group-bearing PAM line and
an empty NSS group, on Debian 12 and Ubuntu 24.04, without touching unrelated
PAM lines."""

import base64
from pathlib import Path
import re
import unittest

import yaml
from jinja2 import Environment


ROLES = Path(__file__).resolve().parents[1] / "roles"
CONTROL = ROLES / ("cis_linux_common/tasks/sections/section_05_access_control/"
                   "5_2_7_su_restriction")
INSPECT = CONTROL / "inspect.yml"
REMEDIATION = CONTROL / "remediation.yml"
VERIFICATION = CONTROL / "verification.yml"
LEGACY_LINE = "auth required pam_wheel.so use_uid"
GROUP_LINE = "auth required pam_wheel.so use_uid group=sugroup"
PLATFORMS = {
    "cis_debian_12": "cis_debian_12_5_2_7_su_restriction_group",
    "cis_ubuntu_2404": "cis_ubuntu_2404_5_2_7_su_restriction_group",
}


def environment():
    env = Environment()
    env.filters["b64decode"] = lambda value: base64.b64decode(
        value.encode() if isinstance(value, str) else value).decode()
    env.filters["regex_replace"] = lambda value, find, replace: re.sub(find, replace, value)
    env.filters["regex_escape"] = lambda value, re_type="python": re.escape(value)
    env.filters["dict2items"] = lambda value: [{"key": k, "value": v}
                                               for k, v in value.items()]

    def search(value, pattern, ignorecase=False):
        return re.search(pattern, value or "", re.IGNORECASE if ignorecase else 0) is not None

    def match(value, pattern, ignorecase=False):
        return re.match(pattern, value or "", re.IGNORECASE if ignorecase else 0) is not None

    env.tests["search"] = search
    env.tests["match"] = match
    return env


def tasks_of(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def fact_task(path, title):
    task = next(task for task in tasks_of(path)
                if str(task.get("name", "")).endswith(title))
    return task["ansible.builtin.set_fact"]


class Context:
    """Registered-variable shapes plus the group input of one run."""

    def __init__(self, pam_text=None, group_name="sugroup", group_record=("x", "1500", ""),
                 passwd=None, unreadable=False, missing_file=False):
        self.group = group_name
        if pam_text is None:
            self.stat = {"changed": False,
                         "stat": {"exists": not missing_file, "isreg": not missing_file,
                                  "readable": not unreadable and not missing_file}}
            self.pam = {"changed": False, "skipped": True}
        else:
            self.stat = {"changed": False, "stat": {"exists": True, "isreg": True,
                                                    "readable": not unreadable}}
            if unreadable:
                self.pam = {"changed": False, "skipped": True}
            else:
                encoded = base64.b64encode(pam_text.encode()).decode()
                self.pam = {"changed": False, "content": encoded}
        self.group_entry = {"changed": False,
                            "ansible_facts": {"getent_group": {group_name: group_record}}}
        self.passwd_entries = {"changed": False,
                               "ansible_facts": {"getent_passwd": passwd or {}}}

    def vars(self):
        return {
            "cis_linux_common_config_line_path": "/etc/pam.d/su",
            "cis_linux_common_config_line_package": "login",
            "cis_linux_common_su_restriction_group": self.group,
            "cis_linux_common_su_restriction_pam_stat": self.stat,
            "cis_linux_common_su_restriction_pam_content": self.pam,
            "cis_linux_common_su_restriction_group_entry": self.group_entry,
            "cis_linux_common_su_restriction_passwd_entries": self.passwd_entries,
        }


class SuRestrictionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = environment()
        cls.steps = [
            fact_task(INSPECT, "Extract PAM line evidence"),
            fact_task(INSPECT, "Extract group evidence"),
            fact_task(INSPECT, "Derive group membership evidence"),
            fact_task(INSPECT, "Find users holding the group as primary GID"),
            fact_task(INSPECT, "Summarize compliance findings"),
        ]

    def render_fact(self, template, facts):
        """set_fact values of this control are exactly one Jinja expression."""
        expression = template.strip()
        self.assertTrue(expression.startswith("{{") and expression.endswith("}}"),
                        f"unexpected template shape: {expression[:60]}")
        return self.env.compile_expression(expression[2:-2], undefined_to_none=False)(**facts)

    def evaluate(self, context):
        """Run the inspect set_fact chain in task order, like Ansible would."""
        facts = context.vars()
        for step in self.steps:
            for key, template in step.items():
                facts[key] = self.render_fact(template, facts)
        return facts

    # --- remediation: group token, group creation, migration -----------------

    def test_remediation_delegates_group_bearing_line(self):
        remediation = tasks_of(REMEDIATION)
        config_line = next(task for task in remediation
                           if task.get("ansible.builtin.import_tasks")
                           == "mechanisms/config_line/remediation.yml")
        vars_ = config_line["vars"]
        template = self.env.from_string(vars_["cis_linux_common_config_line"])
        self.assertEqual(template.render(cis_linux_common_su_restriction_group="sugroup"),
                         GROUP_LINE)
        pattern = self.env.from_string(vars_["cis_linux_common_config_line_regexp"]).render(
            cis_linux_common_su_restriction_group="sugroup")
        self.assertTrue(re.match(pattern, GROUP_LINE))
        self.assertFalse(re.match(pattern, LEGACY_LINE),
                         "the ensure-step must not match the legacy line it migrates away")

    def test_remediation_creates_group_before_line_changes(self):
        remediation = tasks_of(REMEDIATION)
        group_task = next(task for task in remediation if "ansible.builtin.group" in task)
        options = group_task["ansible.builtin.group"]
        self.assertEqual(options["name"], "{{ cis_linux_common_su_restriction_group }}")
        self.assertEqual(options["state"], "present")
        imports = [i for i, task in enumerate(remediation)
                   if "ansible.builtin.import_tasks" in task]
        self.assertLess(remediation.index(group_task), min(imports))

    def test_remediation_migrates_legacy_line_without_matching_grouped_line(self):
        remediation = tasks_of(REMEDIATION)
        migration = next(task for task in remediation
                         if task.get("ansible.builtin.import_tasks")
                         == "mechanisms/line_absent/remediation.yml")
        pattern = migration["vars"]["cis_linux_common_config_line_regexp"]
        self.assertTrue(re.match(pattern, LEGACY_LINE))
        for preserved in (GROUP_LINE,
                          "# auth required pam_wheel.so use_uid",
                          "auth required pam_wheel.so use_uid debug",
                          "auth sufficient pam_wheel.so trust",
                          "auth include common-auth",
                          "session required pam_wheel.so use_uid"):
            with self.subTest(preserved=preserved):
                self.assertFalse(re.match(pattern, preserved))
        names = [task["name"] for task in remediation]
        self.assertLess(
            names.index("CIS 5.2.7 | Remediation | Remove legacy group-less managed pam_wheel line"),
            names.index("CIS 5.2.7 | Remediation | Delegate to config_line"))

    # --- audit/verification evidence: both sides required ---------------------

    def test_legacy_line_without_group_now_fails(self):
        facts = self.evaluate(Context(pam_text=f"{LEGACY_LINE}\n", group_record=None))
        self.assertFalse(facts["cis_linux_common_su_restriction_line_compliant"])
        self.assertFalse(facts["cis_linux_common_su_restriction_group_empty"])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_group_line_with_empty_group_passes(self):
        facts = self.evaluate(Context(pam_text=f"{GROUP_LINE}\n",
                                      group_record=("x", "1500", "")))
        self.assertTrue(facts["cis_linux_common_su_restriction_line_compliant"])
        self.assertTrue(facts["cis_linux_common_su_restriction_group_empty"])
        self.assertTrue(facts["cis_linux_common_su_restriction_compliant"])

    def test_group_line_with_missing_group_fails(self):
        facts = self.evaluate(Context(pam_text=f"{GROUP_LINE}\n", group_record=None))
        self.assertFalse(facts["cis_linux_common_su_restriction_group_empty"])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_populated_group_fails_on_supplementary_members(self):
        facts = self.evaluate(Context(pam_text=f"{GROUP_LINE}\n",
                                      group_record=("x", "1500", "mallory,vagrant")))
        self.assertEqual(facts["cis_linux_common_su_restriction_group_members"],
                         ["mallory", "vagrant"])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_populated_group_fails_on_primary_gid_holders(self):
        facts = self.evaluate(Context(
            pam_text=f"{GROUP_LINE}\n", group_record=("x", "1500", ""),
            passwd={"mallory": ["x", "1600", "1500", "", "/home/mallory", "/bin/bash"],
                    "vagrant": ["x", "1000", "1000", "", "/home/vagrant", "/bin/bash"]}))
        self.assertEqual(facts["cis_linux_common_su_restriction_group_primary_holders"],
                         ["mallory"])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_configurable_group_name_changes_both_sides(self):
        facts = self.evaluate(Context(
            pam_text="auth required pam_wheel.so use_uid group=wheeladmins\n",
            group_name="wheeladmins", group_record=("x", "1500", "")))
        self.assertEqual(
            facts["cis_linux_common_su_restriction_expected_line"],
            "auth required pam_wheel.so use_uid group=wheeladmins")
        self.assertTrue(facts["cis_linux_common_su_restriction_compliant"])
        stale = self.evaluate(Context(pam_text=f"{GROUP_LINE}\n", group_name="wheeladmins",
                                      group_record=("x", "1500", "")))
        self.assertFalse(stale["cis_linux_common_su_restriction_compliant"],
                         "renaming the group must invalidate the old line")

    # --- controlled failures: no crashes, no false pass -----------------------

    def test_unreadable_or_missing_file_fails_controlled(self):
        for label, context in (("unreadable", Context(pam_text=LEGACY_LINE, unreadable=True)),
                               ("missing", Context(missing_file=True))):
            with self.subTest(case=label):
                facts = self.evaluate(context)
                self.assertFalse(facts["cis_linux_common_su_restriction_file_readable"])
                self.assertEqual(facts["cis_linux_common_su_restriction_active_wheel_lines"], [])
                self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_skipped_collectors_do_not_crash_the_chain(self):
        context = Context()
        context.group_entry = {"changed": False, "skipped": True}
        context.passwd_entries = {"changed": False, "skipped": True}
        facts = self.evaluate(context)
        self.assertIsNone(facts["cis_linux_common_su_restriction_group_record"])
        self.assertEqual(facts["cis_linux_common_su_restriction_group_members"], [])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_malformed_and_multiple_active_lines_fail(self):
        for label, text in (("duplicate", f"{GROUP_LINE}\n{GROUP_LINE}\n"),
                            ("requisite variant",
                             "auth requisite pam_wheel.so use_uid group=sugroup\n"),
                            ("extra option",
                             "auth required pam_wheel.so use_uid debug group=sugroup\n"),
                            ("wrong group",
                             "auth required pam_wheel.so use_uid group=wheel\n")):
            with self.subTest(case=label):
                facts = self.evaluate(Context(pam_text=text, group_record=("x", "1500", "")))
                self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    def test_unrelated_pam_lines_are_never_treated_as_evidence(self):
        body = "\n".join([
            "# auth       required   pam_wheel.so",
            "auth sufficient pam_rootok.so",
            "auth include common-auth",
            "session required pam_permit.so",
            "session required pam_wheel.so use_uid",
        ]) + "\n"
        facts = self.evaluate(Context(pam_text=body, group_record=("x", "1500", "")))
        self.assertEqual(facts["cis_linux_common_su_restriction_active_wheel_lines"], [])
        self.assertFalse(facts["cis_linux_common_su_restriction_compliant"])

    # --- wrappers and defaults: explicit per-platform configurability ----------

    def test_wrappers_pass_group_into_common_control(self):
        for role, default_name in PLATFORMS.items():
            for phase in ("audit", "remediation", "verification"):
                with self.subTest(role=role, phase=phase):
                    adapter = tasks_of(ROLES / role / "tasks/sections/"
                                       "section_05_access_control/5_2_7_su_restriction"
                                       / f"{phase}.yml")
                    vars_ = adapter[0]["vars"]
                    self.assertIn("ansible.builtin.import_role", adapter[0])
                    self.assertEqual(
                        vars_["cis_linux_common_su_restriction_group"],
                        "{{ " + default_name + " }}")
                    defaults = yaml.safe_load(
                        (ROLES / role / "defaults/main.yml").read_text(encoding="utf-8"))
                    self.assertEqual(defaults[default_name], "sugroup")

    def test_verification_group_assert_carries_both_semantics(self):
        verification = tasks_of(VERIFICATION)
        group_assert = next(task["ansible.builtin.assert"] for task in verification
                            if "ansible.builtin.assert" in task
                            and "group" in str(task["name"]))
        for expression in group_assert["that"]:
            self.env.from_string("{{ " + expression + " }}")
        rendered = self.env.from_string(group_assert["fail_msg"]).render(
            cis_linux_common_su_restriction_group="sugroup",
            cis_linux_common_su_restriction_group_record=None,
            cis_linux_common_su_restriction_group_members=[],
            cis_linux_common_su_restriction_group_primary_holders=[])
        self.assertIn("stronger than the benchmark", rendered)
        self.assertIn("primary", rendered)


if __name__ == "__main__":
    unittest.main()
