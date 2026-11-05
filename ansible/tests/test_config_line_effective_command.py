"""config_line effective-command mode: sshd 5.1.x resolve `sshd -T` output,
backward-compatible slurp fallback, and fail-closed banner content checks."""

import base64
from pathlib import Path
import re
import unittest

from jinja2 import Environment, StrictUndefined, Undefined
import yaml

from test_config_line_missing_file import jinja_environment

ROOT = Path(__file__).resolve().parents[1]
MECHANISM = ROOT / "roles/cis_linux_common/tasks/mechanisms/config_line"
COMMON_S5 = ROOT / ("roles/cis_linux_common/tasks/sections/"
                    "section_05_access_control")
PLATFORM_S5 = {role: ROOT / f"roles/{role}/tasks/sections/section_05_access_control"
               for role in ("cis_debian_12", "cis_ubuntu_2404")}
PLATFORM_S1 = {role: ROOT / f"roles/{role}/tasks/sections/section_01_initial_setup"
               for role in ("cis_debian_12", "cis_ubuntu_2404")}

SSHD_DIR = {
    "5.1.5": "5_1_5_ssh_banner",
    "5.1.6": "5_1_6_ssh_ciphers",
    "5.1.7": "5_1_7_ssh_client_alive",
    "5.1.8": "5_1_8_ssh_disable_forwarding",
    "5.1.9": "5_1_9_ssh_gssapi_authentication",
    "5.1.10": "5_1_10_ssh_hostbased_authentication",
    "5.1.11": "5_1_11_ssh_ignore_rhosts",
    "5.1.12": "5_1_12_ssh_kex_algorithms",
    "5.1.13": "5_1_13_ssh_login_grace_time",
    "5.1.14": "5_1_14_ssh_log_level",
    "5.1.15": "5_1_15_ssh_macs",
    "5.1.16": "5_1_16_ssh_max_auth_tries",
    "5.1.17": "5_1_17_ssh_max_sessions",
    "5.1.18": "5_1_18_ssh_max_startups",
    "5.1.19": "5_1_19_ssh_permit_empty_passwords",
    "5.1.20": "5_1_20_ssh_permit_root_login",
    "5.1.21": "5_1_21_ssh_permit_user_environment",
    "5.1.22": "5_1_22_ssh_use_pam",
}

# Per control (aligned with the order of import_tasks blocks in the common
# role file): list of (compliant-tuple, non-compliant-tuple) groups, one per
# config_line sub-check. Values mirror the accepted ranges of CIS Debian 12
# v1.1.0 and CIS Ubuntu 24.04 v1.0.0.
SSHD_SAMPLES = {
    "5.1.5": [(("banner /etc/issue.net", "banner /etc/ssh/banner.d/site"),
               ("banner none", "port 22\ngssapiauthentication no"))],
    "5.1.6": [(("ciphers aes128-ctr,aes192-ctr,aes256-ctr,"
               "aes128-gcm@openssh.com,aes256-gcm@openssh.com",
               # chacha20-poly1305 is allowed pending the benchmark's
               # CVE-2023-48795 review, so a patched compliant host passes.
               "ciphers chacha20-poly1305@openssh.com,aes128-ctr"),
              ("ciphers 3des-cbc,aes128-ctr", "ciphers aes128-cbc,aes256-ctr",
               "ciphers chacha20-poly1305@openssh.com,aes192-cbc",
               # file-style exclusion syntax is never present in sshd -T output
               "ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc"))],
    "5.1.7": [(("clientaliveinterval 15", "clientaliveinterval 300"),
               ("clientaliveinterval 0",)),
              (("clientalivecountmax 3",), ("clientalivecountmax 0",))],
    "5.1.8": [(("disableforwarding yes",), ("disableforwarding no",
                                            "disableforwarding ask"))],
    "5.1.9": [(("gssapiauthentication no",), ("gssapiauthentication yes",))],
    "5.1.10": [(("hostbasedauthentication no",),
                ("hostbasedauthentication yes",))],
    "5.1.11": [(("ignorerhosts yes",), ("ignorerhosts no",))],
    "5.1.12": [(("kexalgorithms curve25519-sha256,ecdh-sha2-nistp256,"
                "diffie-hellman-group16-sha512",
                "kexalgorithms sntrup761x25519-sha512@openssh.com,"
                "diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256"),
               ("kexalgorithms diffie-hellman-group14-sha1,curve25519-sha256",
                "kexalgorithms diffie-hellman-group-exchange-sha1",
                "kexalgorithms diffie-hellman-group1-sha1,"
                "diffie-hellman-group16-sha512"))],
    "5.1.13": [(("logingracetime 1", "logingracetime 30", "logingracetime 60",
                 "logingracetime 59"),
                ("logingracetime 0", "logingracetime 61",
                 "logingracetime 120"))],
    "5.1.14": [(("loglevel VERBOSE", "loglevel INFO", "loglevel info"),
                ("loglevel DEBUG", "loglevel quiet"))],
    "5.1.15": [(("macs hmac-sha2-256,hmac-sha2-512,hmac-sha1",
                 "macs hmac-sha2-256-etm@openssh.com,umac-128@openssh.com,"
                 "hmac-sha1-etm@openssh.com"),
                ("macs hmac-md5,hmac-sha1", "macs umac-64@openssh.com",
                 "macs hmac-sha1-96", "macs umac-128-etm@openssh.com",
                 "macs hmac-md5-96-etm@openssh.com"))],
    "5.1.16": [(("maxauthtries 2", "maxauthtries 4"),
                ("maxauthtries 5", "maxauthtries 6", "maxauthtries 14"))],
    "5.1.17": [(("maxsessions 4", "maxsessions 10"),
                ("maxsessions 11", "maxsessions 100"))],
    "5.1.18": [(("maxstartups 10:30:60", "maxstartups 8:20:40",
                 "maxstartups 5", "maxstartups 10:30", "maxstartups 10:29:59"),
                ("maxstartups 10:30:100", "maxstartups 11:30:60",
                 "maxstartups 10:40:60", "maxstartups 100"))],
    "5.1.19": [(("permitemptypasswords no",), ("permitemptypasswords yes",))],
    "5.1.20": [(("permitrootlogin no",),
                ("permitrootlogin yes", "permitrootlogin prohibit-password",
                 "permitrootlogin without-password"))],
    "5.1.21": [(("permituserenvironment no",), ("permituserenvironment yes",))],
    "5.1.22": [(("usepam yes", "USEPAM YES"), ("usepam no",))],
}

BANNER_CONTROLS = {
    "1.6.1": "1_6_1_motd_banner",
    "1.6.2": "1_6_2_issue_banner",
    "1.6.3": "1_6_3_issue_net_banner",
}

BANNER_COMPLIANT = (
    "Authorized users only. All activity may be monitored and reported.\n",
    "WARNING!\nUnauthorized access is prohibited and monitored.\n",
)
BANNER_NONCOMPLIANT = (
    "",
    "   \n\t\n",
    "Debian GNU/Linux 12\nWelcome\n",
    "Ubuntu 24.04 LTS\n",
    "Welcome to ubuntu server\n",
    "This is a UBUNTU host\n",
    r"banner with escape \v and \m codes",
    r"release info: \r here",
)

SSHD_T_COMPLIANT = "\n".join([
    "port 22", "addressfamily any", "listenaddress [::]:22",
    "listenaddress 0.0.0.0:22", "logingracetime 60", "maxauthtries 4",
    "permitrootlogin no", "ignorerhosts yes", "hostbasedauthentication no",
    "gssapiauthentication no", "permitemptypasswords no", "usepam yes",
    "loglevel VERBOSE", "banner /etc/issue.net",
    "ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,"
    "aes256-gcm@openssh.com",
])
# The Include/duplicate override scenario: sshd_config says `no`, but the
# effective (first-match) value resolved by sshd -T is `yes`.
SSHD_T_OVERRIDDEN = SSHD_T_COMPLIANT.replace("permitrootlogin no",
                                             "permitrootlogin yes")


def load_tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def task_with(tasks, module):
    return next(task for task in tasks if module in task)


class ConfigLineEffectiveMechanismTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verify = load_tasks(MECHANISM / "verification.yml")
        cls.audit = load_tasks(MECHANISM / "audit.yml")
        cls.command = task_with(cls.verify, "ansible.builtin.command")
        cls.stat = task_with(cls.verify, "ansible.builtin.stat")
        cls.slurp = task_with(cls.verify, "ansible.builtin.slurp")
        cls.assert_task = task_with(cls.verify, "ansible.builtin.assert")
        cls.assertion = cls.assert_task["ansible.builtin.assert"]["that"][0]
        cls.env = jinja_environment()

    def conditions(self, task):
        when = task["when"]
        return when if isinstance(when, list) else [when]

    def holds(self, task, context):
        return all(bool(self.env.compile_expression(condition)(**context))
                   for condition in self.conditions(task))

    def evaluate(self, expression, context, undefined=False):
        env = jinja_environment(undefined=StrictUndefined) if undefined else self.env
        return bool(env.compile_expression(expression)(**context))

    def base_context(self, installed=True):
        return {
            "cis_linux_common_config_line_package": "openssh-server",
            "cis_linux_common_config_line_path": "/etc/ssh/sshd_config",
            # Legacy file-format regexp: the fallback branch keeps today's
            # case-sensitive semantics; the effective branch is case
            # insensitive, so the same pattern matches sshd -T output too.
            "cis_linux_common_config_line_regexp": r"^PermitRootLogin\s+no$",
            "ansible_facts": {"packages": {"openssh-server": [{}]} if installed else {}},
            "cis_linux_common_config_line_stat": {"stat": {"exists": True, "isreg": True,
                                                           "readable": True}},
            "cis_linux_common_config_line_content": {"skipped": True},
        }

    def effective_context(self, stdout, rc=0):
        context = self.base_context()
        context["cis_linux_common_config_line_effective_command"] = "sshd -T"
        context["cis_linux_common_config_line_effective"] = {"stdout": stdout, "rc": rc}
        return context

    def test_command_task_shape_is_fail_closed_and_read_only(self):
        self.assertEqual("cis_linux_common_config_line_effective",
                         self.command["register"])
        self.assertFalse(self.command["changed_when"])
        self.assertFalse(self.command["failed_when"])
        self.assertFalse(self.command["check_mode"])
        # sshd -T needs the root-only host keys; audit/verify plays run
        # become: false, so the task must escalate explicitly.
        self.assertTrue(self.command["become"])
        self.assertEqual("{{ cis_linux_common_config_line_effective_command }}",
                         self.command["ansible.builtin.command"]["cmd"])
        self.assertLess(self.verify.index(self.command), self.verify.index(self.stat))
        self.assertLess(self.verify.index(self.slurp), self.verify.index(self.assert_task))

    def test_effective_mode_runs_command_and_skips_stat_and_slurp(self):
        context = self.effective_context("permitrootlogin no\n")
        self.assertTrue(self.holds(self.command, context))
        self.assertFalse(self.holds(self.stat, context))
        self.assertFalse(self.holds(self.slurp, context))

    def test_fallback_mode_skips_command_and_keeps_legacy_stat_slurp(self):
        context = self.base_context()
        context["cis_linux_common_config_line_content"] = {"content": base64.b64encode(
            b"PermitRootLogin no\n").decode()}
        self.assertFalse(self.holds(self.command, context))
        self.assertTrue(self.holds(self.stat, context))
        self.assertTrue(self.holds(self.slurp, context))

    def test_effective_stdout_match_passes_case_insensitively(self):
        for stdout in ("permitrootlogin no\n", "PermitRootLogin NO\n"):
            with self.subTest(stdout=stdout):
                self.assertTrue(self.evaluate(
                    self.assertion, self.effective_context(stdout)))

    def test_effective_stdout_no_match_fails(self):
        for stdout in ("permitrootlogin yes\n", "permitrootlogin prohibit-password\n",
                       SSHD_T_OVERRIDDEN):
            with self.subTest(stdout=stdout.splitlines()[0] if "\n" not in stdout else "blob"):
                self.assertFalse(self.evaluate(
                    self.assertion, self.effective_context(stdout)))

    def test_effective_command_failure_fails_closed(self):
        # rc != 0 (e.g. sshd -T as non-root or broken config) -> empty stdout.
        for registered in ({"stdout": "", "rc": 255}, {"changed": False, "skipped": True}):
            with self.subTest(registered=str(registered)):
                context = self.effective_context("")
                context["cis_linux_common_config_line_effective"] = registered
                self.assertFalse(self.evaluate(self.assertion, context))

    def test_effective_mode_catches_include_override_the_old_slurp_missed(self):
        # Single-file presence (old behavior) sees the correct line and passes
        # even though the effective value is overridden.
        file_context = self.base_context()
        file_context["cis_linux_common_config_line_content"] = {"content": base64.b64encode(
            b"Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n").decode()}
        self.assertTrue(self.evaluate(self.assertion, file_context))
        self.assertFalse(self.evaluate(
            self.assertion, self.effective_context(SSHD_T_OVERRIDDEN)))

    def test_absent_package_stays_not_applicable_in_both_modes(self):
        for context in (self.effective_context("anything"),
                        self.base_context(installed=False)):
            context = dict(context, **{"ansible_facts": {"packages": {}}})
            with self.subTest(cmd=context.get(
                    "cis_linux_common_config_line_effective_command", "slurp")):
                self.assertTrue(self.evaluate(self.assertion, context))
                self.assertFalse(self.holds(self.command, context))

    def test_backward_compatible_slurp_paths_still_assert(self):
        for text, expected in (("PermitRootLogin no\n", True),
                               ("PermitRootLogin yes\n", False),
                               # Fallback stays case-sensitive, exactly as
                               # before: lowercase effective text does not
                               # match the legacy file-format pattern.
                               (SSHD_T_COMPLIANT, False),
                               (SSHD_T_OVERRIDDEN, False)):
            context = self.base_context()
            context["cis_linux_common_config_line_content"] = {
                "content": base64.b64encode(text.encode()).decode()}
            with self.subTest(text=text[:22]):
                self.assertEqual(expected, self.evaluate(self.assertion, context))

    def test_assert_is_strict_undefined_safe_without_optional_vars(self):
        # Fallback wrappers never define the effective vars.
        self.assertFalse(self.evaluate(self.assertion, self.base_context(),
                                       undefined=True))
        # Effective wrappers never define slurp vars.
        context = self.effective_context("permitrootlogin no\n")
        del context["cis_linux_common_config_line_content"]
        self.assertTrue(self.evaluate(self.assertion, context, undefined=True))

    def test_audit_classification_reports_pass_fail_and_not_applicable(self):
        classification = task_with(self.audit, "ansible.builtin.debug")["ansible.builtin.debug"]["msg"]["classification"]
        for label, context, expected in (
                ("effective-pass", self.effective_context("permitrootlogin no\n"), "PASS"),
                ("effective-fail", self.effective_context("permitrootlogin yes\n"), "FAIL"),
                ("command-failed", self.effective_context("", rc=255), "FAIL"),
                ("slurp-pass", None, "PASS"),
                ("not-applicable", None, "NOT_APPLICABLE")):
            if context is None:
                context = self.base_context(installed=expected != "NOT_APPLICABLE")
                context["cis_linux_common_config_line_content"] = {"content": base64.b64encode(
                    b"PermitRootLogin no\n").decode()}
            rendered = self.env.from_string(classification).render(**context).strip()
            with self.subTest(case=label):
                self.assertEqual(expected, rendered)


class SshdControlsEffectiveWiringTest(unittest.TestCase):
    def controls(self, cid):
        path = COMMON_S5 / SSHD_DIR[cid]
        tasks = {}
        for kind in ("audit", "verification"):
            tasks[kind] = [(t["vars"]["cis_linux_common_config_line_effective_command"],
                            t["vars"]["cis_linux_common_config_line_regexp"])
                           for t in load_tasks(path / f"{kind}.yml")]
        return tasks

    def test_common_controls_delegate_with_effective_command(self):
        for cid in SSHD_DIR:
            for kind, pairs in self.controls(cid).items():
                with self.subTest(control=cid, kind=kind):
                    self.assertEqual(2 if cid == "5.1.7" else 1, len(pairs))
                    for command, _regexp in pairs:
                        self.assertEqual("sshd -T", command)

    def test_sshd_regexps_match_effective_output_per_benchmark(self):
        for cid, sample_groups in SSHD_SAMPLES.items():
            regexps = []
            for kind in ("audit", "verification"):
                pairs = self.controls(cid)[kind]
                regexps.append([regexp for _c, regexp in pairs])
                self.assertEqual(regexps[0], regexps[-1],
                                 f"{cid} {kind}: audit/verification diverged")
            for index, (compliant, noncompliant) in enumerate(sample_groups):
                regexp = regexps[0][index]
                compiled = re.compile(regexp, re.IGNORECASE | re.MULTILINE)
                for line in compliant:
                    with self.subTest(control=cid, compliant=line[:60]):
                        self.assertTrue(compiled.search(line))
                for line in noncompliant:
                    with self.subTest(control=cid, noncompliant=line[:60]):
                        self.assertIsNone(compiled.search(line))

    def test_regexps_match_only_after_resolution_not_file_duplicates(self):
        # 5.1.20 against full sshd -T blobs (keys already lowercased by sshd).
        _command, regexp = self.controls("5.1.20")["audit"][0]
        compiled = re.compile(regexp, re.IGNORECASE | re.MULTILINE)
        self.assertTrue(compiled.search(SSHD_T_COMPLIANT))
        self.assertIsNone(compiled.search(SSHD_T_OVERRIDDEN))

    def test_platform_wrappers_stay_in_sync_with_common_controls(self):
        for role, base in PLATFORM_S5.items():
            for cid, directory in SSHD_DIR.items():
                pairs = self.controls(cid)["audit"]
                for kind in ("audit", "verification"):
                    text = (base / directory / f"{kind}.yml").read_text(encoding="utf-8")
                    data = load_tasks(base / directory / f"{kind}.yml")
                    vars_ = data[0]["vars"]
                    with self.subTest(role=role, control=cid, kind=kind):
                        if cid == "5.1.7":
                            # Two sub-checks live in the common role; the
                            # wrapper must not carry a single shadowing regexp.
                            self.assertNotIn("cis_linux_common_config_line_regexp", text)
                            continue
                        self.assertIn("cis_linux_common_config_line_effective_command",
                                      vars_)
                        self.assertEqual("sshd -T",
                                         vars_["cis_linux_common_config_line_effective_command"])
                        self.assertEqual(pairs[0][1],
                                         vars_["cis_linux_common_config_line_regexp"])


class BannerContentControlsTest(unittest.TestCase):
    def wrapper_vars(self, role, cid, kind):
        data = load_tasks(PLATFORM_S1[role] / BANNER_CONTROLS[cid] / f"{kind}.yml")
        return data[0]["vars"]

    def test_banner_wrappers_reject_empty_and_os_leaks(self):
        for role in PLATFORM_S1:
            for cid in BANNER_CONTROLS:
                for kind in ("audit", "verification"):
                    regexp = self.wrapper_vars(role, cid, kind)[
                        "cis_linux_common_config_line_regexp"]
                    compiled = re.compile(regexp, re.MULTILINE)
                    with self.subTest(role=role, control=cid, kind=kind):
                        self.assertNotEqual("^.*$", regexp)
                        for text in BANNER_COMPLIANT:
                            self.assertTrue(compiled.search(text), text[:40])
                        for text in BANNER_NONCOMPLIANT:
                            self.assertIsNone(compiled.search(text),
                                              f"must reject: {text!r}")

    def test_banner_remediation_targets_the_warning_line(self):
        for role in PLATFORM_S1:
            for cid in BANNER_CONTROLS:
                vars_ = self.wrapper_vars(role, cid, "remediation")
                with self.subTest(role=role, control=cid):
                    self.assertEqual("^Authorized users only",
                                     vars_["cis_linux_common_config_line_regexp"])
                    self.assertTrue(
                        re.compile(vars_["cis_linux_common_config_line_regexp"],
                                   re.MULTILINE).search(
                            vars_["cis_linux_common_config_line"]))

    def test_banner_wrappers_do_not_define_effective_command(self):
        # MOTD/issue content has no effective resolver: these controls keep
        # the backward-compatible slurp path.
        for role in PLATFORM_S1:
            for cid in BANNER_CONTROLS:
                for kind in ("audit", "remediation", "verification"):
                    vars_ = self.wrapper_vars(role, cid, kind)
                    with self.subTest(role=role, control=cid, kind=kind):
                        self.assertNotIn(
                            "cis_linux_common_config_line_effective_command", vars_)

    def test_remediation_files_keep_legacy_delegation_shape(self):
        for cid in SSHD_DIR:
            for kind in ("remediation",):
                text = (COMMON_S5 / SSHD_DIR[cid] / f"{kind}.yml").read_text(
                    encoding="utf-8")
                with self.subTest(control=cid):
                    self.assertNotIn("cis_linux_common_config_line_effective_command",
                                     text)


if __name__ == "__main__":
    unittest.main()
