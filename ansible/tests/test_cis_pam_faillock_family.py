"""Focused source-contract tests for the CIS pam_faillock family.

Covers controls 5.3.2.2 (pam-auth-update profile stack) and 5.3.3.1.1-.3
(faillock.conf owned parameters). These tests validate the repository
contracts only: exact benchmark profile contents, PAM stack ordering and
strictness regexes, inline-override rejection, bounded parameter regexes,
idempotent command guards, and the rule that no task writes directly into
/etc/pam.d. Guest behaviour is verified separately by the verify playbooks.

Run inside ansible-control:
    /home/vagrant/.venvs/ansible-cis/bin/python -m unittest discover \
        -s ansible/tests -p 'test_cis_pam_faillock_family.py' -v
"""

import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "ansible" / "roles" / "cis_linux_common" / "tasks"
STACK = COMMON / "mechanisms" / "pam_faillock_stack"
PARAM = COMMON / "mechanisms" / "faillock_parameter"
SECTIONS = COMMON / "sections" / "section_05_access_control"
DEBIAN = ROOT / "ansible" / "roles" / "cis_debian_12"
UBUNTU = ROOT / "ansible" / "roles" / "cis_ubuntu_2404"

FAILLOCK_NOTIFY_PROFILE = (
    "Name: Notify of failed login attempts and reset count upon success\n"
    "Default: yes\n"
    "Priority: 1024\n"
    "Auth-Type: Primary\n"
    "Auth:\n"
    " requisite pam_faillock.so preauth\n"
    "Account-Type: Primary\n"
    "Account:\n"
    " required pam_faillock.so\n"
)
FAILLOCK_DENY_PROFILE = (
    "Name: Enable pam_faillock to deny access\n"
    "Default: yes\n"
    "Priority: 0\n"
    "Auth-Type: Primary\n"
    "Auth:\n"
    " [default=die] pam_faillock.so authfail\n"
)


def load_tasks(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def task_by_fragment(tasks, fragment):
    matches = [task for task in tasks if fragment in task.get("name", "")]
    if not matches:
        raise AssertionError(f"no task matching {fragment!r}")
    return matches


class StackProfileContractTest(unittest.TestCase):
    def test_profiles_match_benchmark(self):
        tasks = load_tasks(STACK / "remediation.yml")
        copies = task_by_fragment(tasks, "pam-auth-update profile")
        by_dest = {task["ansible.builtin.copy"]["dest"]: task["ansible.builtin.copy"]
                   for task in copies}
        self.assertEqual(
            set(by_dest),
            {"/usr/share/pam-configs/faillock_notify", "/usr/share/pam-configs/faillock"},
        )
        notify = by_dest["/usr/share/pam-configs/faillock_notify"]
        deny = by_dest["/usr/share/pam-configs/faillock"]
        self.assertEqual(notify["content"], FAILLOCK_NOTIFY_PROFILE)
        self.assertEqual(deny["content"], FAILLOCK_DENY_PROFILE)
        for profile in (notify, deny):
            self.assertEqual(profile["owner"], "root")
            self.assertEqual(profile["group"], "root")
            self.assertEqual(profile["mode"], "0644")

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
        self.assertEqual(len(commands), 1, "profiles must be enabled in one atomic regeneration")
        command = commands[0]
        argv = command["ansible.builtin.command"]["argv"]
        for token in ("pam-auth-update", "--enable", "faillock", "faillock_notify"):
            self.assertIn(token, argv)
        self.assertIn("cis_linux_common_faillock_pam_auth_update_force", argv,
                      "--force must stay behind the explicit operator gate")
        self.assertEqual(command["environment"], {"DEBIAN_FRONTEND": "noninteractive"})
        self.assertIs(command["changed_when"], True)
        joined = yaml.dump(command["when"])
        self.assertIn("cis_linux_common_faillock_stack_ok", joined)
        self.assertIn("notify_profile.changed", joined)
        self.assertIn("deny_profile.changed", joined)

    def test_remediation_and_verification_reinspect_stack(self):
        for name in ("remediation.yml", "verification.yml"):
            text = (STACK / name).read_text(encoding="utf-8")
            self.assertIn("mechanisms/pam_faillock_stack/inspect.yml", text)
        remediation = (STACK / "remediation.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(
            remediation.count("mechanisms/pam_faillock_stack/inspect.yml"), 2,
            "remediation must re-evaluate the stack after pam-auth-update",
        )


class StackEvidenceRegexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tasks = load_tasks(STACK / "inspect.yml")
        evidence = next(task for task in tasks
                        if "stack evidence" in task.get("name", ""))
        facts = evidence["ansible.builtin.set_fact"]
        cls.preauth = re.compile(cls._extract(facts["cis_linux_common_faillock_preauth_count"]))
        cls.authfail = re.compile(cls._extract(facts["cis_linux_common_faillock_authfail_count"]))
        cls.account = re.compile(cls._extract(facts["cis_linux_common_faillock_account_count"]))
        signature = (facts["cis_linux_common_faillock_auth_signature"])
        cls.token = re.compile(next(
            item for item in re.findall(r"'([^']*)'", signature)
            if item.startswith("preauth|authfail")))
        override = next(task for task in tasks
                        if "inline faillock overrides" in task.get("name", ""))
        cls.override = re.compile(
            override["vars"]["cis_linux_common_faillock_override_regex"])

    @staticmethod
    def _extract(text):
        quoted = re.findall(r"'([^']*)'", text)
        return next(item for item in quoted if "\\" in item)

    def test_strict_stack_lines_accept_benchmark_forms(self):
        wide = "auth       requisite                   pam_faillock.so preauth"
        self.assertTrue(self.preauth.match(wide))
        self.assertTrue(self.preauth.match("auth requisite pam_faillock.so preauth"))
        self.assertTrue(
            self.authfail.match("auth       [default=die]                 pam_faillock.so authfail"))
        self.assertTrue(
            self.account.match("account       required                        pam_faillock.so"))

    def test_strict_stack_lines_reject_variants(self):
        for pattern, bad in (
            (self.preauth, "auth required pam_faillock.so preauth"),
            (self.preauth, "auth requisite pam_faillock.so preauth silent"),
            (self.preauth, "auth requisite pam_faillock.sopreauth "),
            (self.authfail, "auth requisite pam_faillock.so authfail"),
            (self.authfail, "auth [default=die] pam_faillock.so"),
            (self.account, "account requisite pam_faillock.so"),
            (self.account, "account required pam_faillock.so deny=5"),
        ):
            self.assertIsNone(pattern.match(bad), bad)

    def test_signature_last_token_classifies_lines(self):
        cases = {
            "auth       requisite    pam_faillock.so preauth": "preauth",
            "auth [success=1 default=ignore] pam_unix.so nullok": "pam_unix.so",
            "auth [default=die] pam_faillock.so authfail": "authfail",
            "auth required pam_faillock.so": "pam_faillock.so",
        }
        for line, expected in cases.items():
            self.assertEqual(self.token.findall(line)[-1], expected, line)

    def test_override_regex_rejects_inline_arguments(self):
        bad = [
            "auth required pam_faillock.so preauth deny=5",
            "auth requisite pam_faillock.so preauth unlock_time=900",
            "auth [default=die] pam_faillock.so authfail even_deny_root",
            "auth required pam_faillock.so authfail root_unlock_time=1200",
            " requisite pam_faillock.so preauth deny=5",
            "account required pam_faillock.so unlock_time = 900",
        ]
        for line in bad:
            self.assertTrue(self.override.search(line + "\n"), line)

    def test_override_regex_accepts_canonical_and_unrelated_lines(self):
        good = [
            "auth       requisite                   pam_faillock.so preauth",
            "auth [default=die] pam_faillock.so authfail",
            "account    required                    pam_faillock.so",
            "# auth required pam_faillock.so preauth deny=5 was removed",
            "auth [success=1 default=ignore] pam_unix.so nullok",
            "auth requisite pam_deny.so",
            "auth required pam_permit.so",
        ]
        for line in good:
            self.assertIsNone(self.override.search(line + "\n"), line)

    def test_override_regex_is_line_bounded(self):
        multiline = ("auth requisite pam_faillock.so preauth\n"
                     "deny = 5 in faillock.conf is allowed\n")
        self.assertIsNone(self.override.search(multiline))

    def test_fail_safe_scan_guards(self):
        inspect_text = (STACK / "inspect.yml").read_text(encoding="utf-8")
        self.assertIn("failed_when: false", inspect_text)
        self.assertIn("skip_missing=true", inspect_text)
        self.assertIn("default('', true)", inspect_text)
        self.assertIn("difference(cis_linux_common_faillock_read_files)",
                      inspect_text.replace("\n         ", " "))

    def test_stack_verdict_requires_exact_lines_and_order(self):
        tasks = load_tasks(STACK / "inspect.yml")
        verdict = next(task for task in tasks
                       if "stack verdict" in task["name"])
        joined = " ".join(str(verdict["ansible.builtin.set_fact"][
            "cis_linux_common_faillock_stack_ok"]).split())
        for guard in (
            "cis_linux_common_faillock_unreadable_files | length == 0",
            "cis_linux_common_faillock_override_files | length == 0",
            # exactly-one counts: a duplicated preauth/authfail/account line
            # fails the verdict even though each individual line is canonical
            "cis_linux_common_faillock_preauth_count == 1",
            "cis_linux_common_faillock_authfail_count == 1",
            "cis_linux_common_faillock_account_count == 1",
            "cis_linux_common_faillock_auth_faillock_total == 2",
            "cis_linux_common_faillock_account_faillock_total == 1",
            # order: preauth < pam_unix < authfail inside common-auth
            "cis_linux_common_faillock_auth_signature == "
            "['preauth', 'pam_unix.so', 'authfail']",
        ):
            self.assertIn(guard, joined)


class ParameterRegexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controls = {}
        for control in ("5_3_3_1_1_faillock_deny", "5_3_3_1_2_faillock_unlock_time",
                        "5_3_3_1_3_faillock_even_deny_root"):
            tasks = load_tasks(SECTIONS / control / "audit.yml")
            cls.controls[control] = tasks[0]["vars"]

    def _regex(self, control, key):
        return re.compile(self.controls[control][key])

    def test_deny_regexes_are_value_bounded(self):
        value = self._regex("5_3_3_1_1_faillock_deny", "cis_linux_common_faillock_value_regex")
        name = self._regex("5_3_3_1_1_faillock_deny", "cis_linux_common_faillock_name_regex")
        self.assertTrue(value.match("deny = 5"))
        self.assertTrue(value.match(" deny=5"))
        for bad in ("deny = 55", "deny = 0", "deny = 6", "deny = 5x", "# deny = 5"):
            self.assertIsNone(value.match(bad), bad)
        self.assertTrue(name.match("deny = 55"))
        self.assertIsNone(name.match("# deny = 3"))

    def test_unlock_time_regexes_are_value_bounded(self):
        value = self._regex("5_3_3_1_2_faillock_unlock_time", "cis_linux_common_faillock_value_regex")
        for good in ("unlock_time = 900", "  unlock_time=900 "):
            self.assertTrue(value.match(good), good)
        for bad in ("unlock_time = 9000", "unlock_time = 90", "unlock_time = 0",
                    "unlock_time = 6048001", "# unlock_time = 900"):
            self.assertIsNone(value.match(bad), bad)

    def test_even_deny_root_regexes_and_companion_values(self):
        control = "5_3_3_1_3_faillock_even_deny_root"
        name = self._regex(control, "cis_linux_common_faillock_name_regex")
        value = self._regex(control, "cis_linux_common_faillock_value_regex")
        self.assertTrue(value.match("even_deny_root"))
        self.assertTrue(name.match("even_deny_root=1"))
        self.assertIsNone(value.match("even_deny_root=1"))
        self.assertIsNone(name.match("# even_deny_root"))
        companion = re.compile("(?m)^" + self.controls[control][
            "cis_linux_common_faillock_companion_value_regex"])
        text = "root_unlock_time = 60\nroot_unlock_time = 900\n# root_unlock_time = 5\n"
        self.assertEqual(companion.findall(text), ["60", "900"])
        # A trailing comment is not a reliably parsed value: it must not be captured.
        self.assertEqual(companion.findall("root_unlock_time = 900 # comment\n"), [])
        name_only = re.compile("(?m)^" + self.controls[control][
            "cis_linux_common_faillock_companion_name_regex"])
        # findall without groups returns the matched span; the mechanism counts
        # lines with select('match', ...), where one malformed line is one hit.
        self.assertEqual(name_only.findall("root_unlock_time = 900 # comment\n"),
                         ["root_unlock_time ="])

    def test_lineinfile_regexps_are_name_anchored(self):
        for control, sample in (
            ("5_3_3_1_1_faillock_deny", "deny = 55"),
            ("5_3_3_1_2_faillock_unlock_time", "unlock_time = 30"),
            ("5_3_3_1_3_faillock_even_deny_root", "even_deny_root # legacy"),
        ):
            regexp = re.compile(self.controls[control]["cis_linux_common_faillock_regexp"])
            self.assertTrue(regexp.match(sample), sample)

    def test_mechanism_wires_parameters_and_stack_guards(self):
        for name in ("audit.yml", "verification.yml", "remediation.yml"):
            text = (PARAM / name).read_text(encoding="utf-8")
            self.assertIn("mechanisms/pam_faillock_stack/inspect.yml", text)
            self.assertIn("faillock_parameter/evaluate.yml", text)
        evaluate = (PARAM / "evaluate.yml").read_text(encoding="utf-8")
        self.assertIn("cis_linux_common_faillock_override_files", evaluate)
        self.assertIn("cis_linux_common_faillock_unreadable_files", evaluate)
        self.assertIn("select('lt', 60)", evaluate)

    def test_missing_conf_fails_controlled_not_crashes(self):
        evaluate = load_tasks(PARAM / "evaluate.yml")
        stat = next(task for task in evaluate
                    if "Inspect the configuration file" in task["name"])
        self.assertIs(stat["ansible.builtin.stat"]["get_checksum"], False)
        slurp = next(task for task in evaluate
                     if "Read the configuration file" in task["name"])
        # A missing, non-regular, or unreadable conf never runs slurp blindly
        # and never crashes the evaluation: the guards plus failed_when keep
        # the empty-text path flowing into the numeric verdict, where
        # name_lines == 0 fails the exactly-one requirement in a controlled
        # assert instead of a module error.
        self.assertEqual(
            slurp["when"],
            [
                "cis_linux_common_faillock_conf_stat.stat.exists | default(false)",
                "cis_linux_common_faillock_conf_stat.stat.isreg | default(false)",
                "cis_linux_common_faillock_conf_stat.stat.readable | default(false)",
            ],
        )
        self.assertIs(slurp["failed_when"], False)
        text = (PARAM / "evaluate.yml").read_text(encoding="utf-8")
        self.assertIn("default('', true)", text)
        verdict = next(task for task in evaluate
                       if "parameter verdict" in task["name"])
        joined = " ".join(
            str(verdict["ansible.builtin.set_fact"][
                "cis_linux_common_faillock_parameter_ok"]).split())
        self.assertIn("name_count == 1", joined)
        self.assertIn("value_count == 1", joined)

    def test_existing_conf_ownership_and_mode_are_preserved(self):
        remediation = load_tasks(PARAM / "remediation.yml")
        set_task = next(task for task in remediation
                        if "Set the managed parameter line" in task["name"])
        args = set_task["ansible.builtin.lineinfile"]
        # An existing faillock.conf keeps its ownership and mode: no CIS
        # control of this family prescribes them, so remediation must never
        # silently loosen a site-hardened root:shadow 640. Only creation
        # applies the packaged default.
        for attr in ("owner", "group", "mode"):
            self.assertIn("omit if cis_linux_common_faillock_conf_stat.stat.exists",
                          str(args[attr]), attr)
        raise_task = next(task for task in remediation
                          if "below 60 seconds" in task["name"])
        # The root_unlock_time raise only ever runs against an existing
        # file, so it must not carry ownership attributes at all.
        raise_args = raise_task["ansible.builtin.lineinfile"]
        self.assertNotIn("owner", raise_args)
        self.assertNotIn("group", raise_args)
        self.assertNotIn("mode", raise_args)

    def test_root_unlock_time_below_60_is_rejected_and_raised(self):
        remediation = load_tasks(PARAM / "remediation.yml")
        raise_task = next(task for task in remediation
                          if "below 60 seconds" in task["name"])
        args = raise_task["ansible.builtin.lineinfile"]
        self.assertEqual(args["line"], "root_unlock_time = 900")
        self.assertIs(args["create"], False)
        self.assertEqual(
            raise_task["when"],
            [
                "cis_linux_common_faillock_package in ansible_facts.packages",
                "cis_linux_common_faillock_kind == 'flag'",
                "cis_linux_common_faillock_root_unlock_invalid | default(false) | bool",
            ],
        )
        # The numeric raise target (900) is itself bounded: a 9000-style
        # runaway value must not be produced or accepted.
        self.assertNotIn("9000", yaml.dump(args))


class RoutingContractTest(unittest.TestCase):
    def test_section_files_route_dedicated_mechanisms(self):
        mapping = {
            "5_3_2_2_pam_faillock": "mechanisms/pam_faillock_stack",
            "5_3_3_1_1_faillock_deny": "mechanisms/faillock_parameter",
            "5_3_3_1_2_faillock_unlock_time": "mechanisms/faillock_parameter",
            "5_3_3_1_3_faillock_even_deny_root": "mechanisms/faillock_parameter",
        }
        for control, mechanism in mapping.items():
            for mode in ("audit.yml", "remediation.yml", "verification.yml"):
                tasks = load_tasks(SECTIONS / control / mode)
                imported = tasks[0]["ansible.builtin.import_tasks"]
                self.assertTrue(imported.startswith(mechanism), imported)

    def test_platform_wrappers_pass_faillock_variables(self):
        for role, benchmark in ((DEBIAN, "CIS Debian Linux 12 Benchmark v1.1.0"),
                                (UBUNTU, "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0")):
            for control in ("5_3_2_2_pam_faillock", "5_3_3_1_1_faillock_deny",
                            "5_3_3_1_2_faillock_unlock_time",
                            "5_3_3_1_3_faillock_even_deny_root"):
                for mode in ("audit.yml", "remediation.yml", "verification.yml"):
                    tasks = load_tasks(
                        role / "tasks" / "sections" / "section_05_access_control" / control / mode)
                    vars_ = tasks[0]["vars"]
                    self.assertEqual(vars_["cis_linux_common_benchmark"], benchmark)
                    self.assertNotIn("cis_linux_common_config_line_path", vars_)
                    self.assertNotIn("cis_linux_common_config_line_package", vars_)
                    self.assertEqual(vars_["cis_linux_common_faillock_package"], "libpam-modules")
                    if control != "5_3_2_2_pam_faillock":
                        self.assertEqual(
                            vars_["cis_linux_common_faillock_conf_path"],
                            "/etc/security/faillock.conf")

    def test_gates_and_selectors_preserved(self):
        for role, prefix in ((DEBIAN, "cis_debian_12"), (UBUNTU, "cis_ubuntu_2404")):
            defaults = yaml.safe_load((role / "defaults" / "main.yml").read_text(encoding="utf-8"))
            for control in ("5_3_2_2_pam_faillock", "5_3_3_1_1_faillock_deny",
                            "5_3_3_1_2_faillock_unlock_time",
                            "5_3_3_1_3_faillock_even_deny_root"):
                self.assertIs(defaults[f"{prefix}_{control}"], True)
                self.assertIs(defaults[f"{prefix}_{control}_remediate"], False)
            main = (role / "tasks" / "main.yml").read_text(encoding="utf-8")
            for control in ("5_3_2_2", "5_3_3_1_1", "5_3_3_1_2", "5_3_3_1_3"):
                tag_lines = [line for line in main.splitlines() if f"cis_{control}," in line]
                self.assertTrue(tag_lines, control)
                for line in tag_lines:
                    self.assertIn("gated_unsafe", line)

    def test_ledger_generator_routes_family(self):
        text = (ROOT / "ansible" / "scripts" / "generate_ledger.py").read_text(encoding="utf-8")
        for rule in (('("5.3.2.2", "pam_faillock_stack")',),
                     ('("5.3.3.1.1", "faillock_parameter")',),
                     ('("5.3.3.1.2", "faillock_parameter")',),
                     ('("5.3.3.1.3", "faillock_parameter")',)):
            self.assertIn(rule[0], text)
        self.assertLess(text.index('"5.3.2.2", "pam_faillock_stack"'),
                        text.index('("5.3.", "config_line")'))

    def test_generated_ledger_artifacts_route_family(self):
        # The generator source is not enough: the committed artifacts must
        # carry the dedicated PAM backends, otherwise runtime routing tables
        # still point the family at config_line.
        catalog = ROOT / "ansible" / "cis" / "catalog"
        with (catalog / "control-ledger.yml").open(encoding="utf-8") as handle:
            ledger = json.load(handle)
        expected_backend = {
            "5.3.2.2": "cis_linux_common.pam_faillock_stack",
            "5.3.3.1.1": "cis_linux_common.faillock_parameter",
            "5.3.3.1.2": "cis_linux_common.faillock_parameter",
            "5.3.3.1.3": "cis_linux_common.faillock_parameter",
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
