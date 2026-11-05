"""Shared config-line verification must fail as a controlled assertion, not at slurp."""

import base64
from pathlib import Path
import re
import unittest

from jinja2 import Environment, StrictUndefined, Undefined
import yaml


MECHANISM = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
             "mechanisms/config_line/verification.yml")


def jinja_environment(undefined=Undefined):
    env = Environment(undefined=undefined)
    # Mirror the ansible.builtin b64decode filter and search test used by the
    # assert condition; neither exists in plain Jinja2. Ansible's b64decode
    # returns text, not bytes.
    env.filters["b64decode"] = lambda value: base64.b64decode(
        value.encode() if isinstance(value, str) else value).decode()

    def search(value, pattern, ignorecase=False, multiline=False):
        flags = 0
        if ignorecase:
            flags |= re.IGNORECASE
        if multiline:
            flags |= re.MULTILINE
        return re.search(pattern, value or "", flags) is not None

    env.tests["search"] = search
    return env


class ConfigLineMissingFileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tasks = yaml.safe_load(MECHANISM.read_text(encoding="utf-8"))
        cls.stat = next(task for task in cls.tasks if "ansible.builtin.stat" in task)
        cls.slurp = next(task for task in cls.tasks if "ansible.builtin.slurp" in task)
        cls.assert_task = next(task for task in cls.tasks if "ansible.builtin.assert" in task)
        cls.env = jinja_environment()

    def conditions(self, task):
        when = task["when"]
        return when if isinstance(when, list) else [when]

    def evaluate(self, expression, context):
        return bool(self.env.compile_expression(expression)(**context))

    def all_conditions_hold(self, task, context):
        return all(self.evaluate(condition, context)
                   for condition in self.conditions(task))

    def test_stat_probe_precedes_slurp_and_assert(self):
        self.assertLess(self.tasks.index(self.stat), self.tasks.index(self.slurp))
        self.assertLess(self.tasks.index(self.slurp), self.tasks.index(self.assert_task))
        self.assertEqual("{{ cis_linux_common_config_line_path }}",
                         self.stat["ansible.builtin.stat"]["path"])
        self.assertEqual("cis_linux_common_config_line_stat", self.stat["register"])
        self.assertEqual("cis_linux_common_config_line_content", self.slurp["register"])

    def test_slurp_fails_hard_instead_of_suppressing_unrelated_errors(self):
        self.assertNotIn("failed_when", self.slurp)
        self.assertNotIn("ignore_errors", self.slurp)

    def test_slurp_requires_existence_and_readability_before_reading(self):
        joined = " ".join(self.conditions(self.slurp))
        for key in ("stat.exists", "stat.isreg", "stat.readable"):
            self.assertIn(f"cis_linux_common_config_line_stat.{key}", joined)

    def contexts(self, installed, stat_result, content=None):
        """Registered-variable shapes Ansible produces for skipped/failed-free runs."""
        return {
            "cis_linux_common_config_line_package": "kmod",
            "cis_linux_common_config_line_path": "/etc/modprobe.d/overlayfs.conf",
            "cis_linux_common_config_line_regexp": "^install overlayfs /bin/true$",
            "ansible_facts": {"packages": {"kmod": [{}]} if installed else {}},
            "cis_linux_common_config_line_stat": stat_result,
            "cis_linux_common_config_line_content": content
            if content is not None else {"changed": False, "skipped": True},
        }

    def test_missing_file_skips_slurp_and_fails_assertion_without_pass(self):
        missing = {"changed": False, "stat": {"exists": False}}
        context = self.contexts(installed=True, stat_result=missing)
        with self.subTest(field="stat"):
            self.assertTrue(self.all_conditions_hold(self.stat, context))
        with self.subTest(field="slurp"):
            self.assertFalse(self.all_conditions_hold(self.slurp, context))
        with self.subTest(field="assert"):
            self.assertFalse(self.evaluate(
                self.assert_task["ansible.builtin.assert"]["that"][0], context))

    def test_unreadable_file_skips_slurp_and_fails_assertion_without_pass(self):
        unreadable = {"changed": False,
                      "stat": {"exists": True, "isreg": True, "readable": False}}
        context = self.contexts(installed=True, stat_result=unreadable)
        self.assertFalse(self.all_conditions_hold(self.slurp, context))
        self.assertFalse(self.evaluate(
            self.assert_task["ansible.builtin.assert"]["that"][0], context))

    def test_present_file_without_line_still_fails(self):
        present = {"changed": False,
                   "stat": {"exists": True, "isreg": True, "readable": True}}
        content = {"content": base64.b64encode(b"blacklist other\n").decode()}
        context = self.contexts(installed=True, stat_result=present, content=content)
        self.assertTrue(self.all_conditions_hold(self.slurp, context))
        self.assertFalse(self.evaluate(
            self.assert_task["ansible.builtin.assert"]["that"][0], context))

    def test_present_file_with_line_passes(self):
        present = {"changed": False,
                   "stat": {"exists": True, "isreg": True, "readable": True}}
        content = {"content": base64.b64encode(
            b"install overlayfs /bin/true\nblacklist overlayfs\n").decode()}
        context = self.contexts(installed=True, stat_result=present, content=content)
        self.assertTrue(self.all_conditions_hold(self.slurp, context))
        self.assertTrue(self.evaluate(
            self.assert_task["ansible.builtin.assert"]["that"][0], context))

    def test_absent_package_remains_not_applicable_pass(self):
        skipped = {"changed": False, "skipped": True}
        context = self.contexts(installed=False, stat_result=skipped)
        self.assertFalse(self.all_conditions_hold(self.stat, context))
        self.assertFalse(self.all_conditions_hold(self.slurp, context))
        self.assertTrue(self.evaluate(
            self.assert_task["ansible.builtin.assert"]["that"][0], context))

    def test_fail_msg_names_expected_line_and_path(self):
        fail_msg = self.assert_task["ansible.builtin.assert"]["fail_msg"]
        # The bare cis_linux_common_config_line is optional: many verification
        # wrappers only define the regexp, so fail_msg must rely on required
        # inputs only.
        self.assertIn("{{ cis_linux_common_config_line_regexp }}", fail_msg)
        self.assertIn("{{ cis_linux_common_config_line_path }}", fail_msg)
        self.assertNotIn("{{ cis_linux_common_config_line }}", fail_msg)

    def test_assert_arguments_finalize_without_optional_line_var(self):
        """Ansible templates every assert argument before running the task, even
        when the assertion passes; wrappers that omit the optional bare line var
        must not hit 'cis_linux_common_config_line' is undefined."""
        strict = jinja_environment(undefined=StrictUndefined)
        present = {"changed": False,
                   "stat": {"exists": True, "isreg": True, "readable": True}}
        missing = {"changed": False, "stat": {"exists": False}}
        matching = {"content": base64.b64encode(
            b"install overlayfs /bin/true\n").decode()}
        for label, stat_result, content, expect_pass in (
                ("passing run", present, matching, True),
                ("failing run", missing, {"changed": False, "skipped": True},
                 False)):
            # contexts() never defines cis_linux_common_config_line, proving
            # the absent-variable case under Ansible-like strict undefined.
            context = self.contexts(installed=True, stat_result=stat_result,
                                    content=content)
            self.assertNotIn("cis_linux_common_config_line", context)
            assertion = self.assert_task["ansible.builtin.assert"]
            with self.subTest(case=label, field="fail_msg"):
                rendered = strict.from_string(assertion["fail_msg"]).render(
                    **context)
                self.assertIn(context["cis_linux_common_config_line_regexp"],
                              rendered)
                self.assertIn(context["cis_linux_common_config_line_path"],
                              rendered)
            with self.subTest(case=label, field="that"):
                passed = bool(strict.compile_expression(assertion["that"][0])(
                    **context))
                self.assertEqual(passed, expect_pass)
            with self.subTest(case=label, field="presence-invariance"):
                with_var = dict(context)
                with_var["cis_linux_common_config_line"] = \
                    "install overlayfs /bin/true"
                self.assertEqual(passed, bool(
                    strict.compile_expression(assertion["that"][0])(
                        **with_var)))


if __name__ == "__main__":
    unittest.main()
