"""CIS 1.7.x must check GDM itself, not the /etc/motd + /etc/issue banners.

The benchmark section 1.7 is "Configure GNOME Display Manager": 1.7.1 audits
that gdm3 is not installed, 1.7.2-1.7.9 audit dconf/gsettings state that only
exists when GDM is installed (NOT_APPLICABLE when gdm3 is absent, per the
section's "IF - GDM is not installed on the system, this section can be
skipped"), 1.7.10 (XDMCP) is audited regardless, and every control is
Automated. The banners belong to section 1.6 (already implemented there); no
1.7 control may observe /etc/motd, /etc/issue or /etc/issue.net.
"""

from pathlib import Path
import json
import re
import unittest

import yaml

from test_config_line_missing_file import jinja_environment

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "roles/cis_linux_common/tasks"
DEBIAN = ROOT / "roles/cis_debian_12/tasks"
UBUNTU = ROOT / "roles/cis_ubuntu_2404/tasks"
MECHANISM = COMMON / "mechanisms/gdm_configuration"
LEDGER = ROOT / "cis/catalog/control-ledger.yml"
PHASES = ("audit.yml", "remediation.yml", "verification.yml")

# dir name, expected gdm_configuration checks (None -> package_absent/gdm3),
# expected apply-gate for the mechanism wrappers.
CONTROLS = {
    "1.7.1": ("1_7_1_gdm_removed", None, None),
    "1.7.2": ("1_7_2_gdm_banner", [
        "gsettings|org.gnome.login-screen|banner-message-enable|^true$",
        "gsettings_text|org.gnome.login-screen|banner-message-text",
    ], True),
    "1.7.3": ("1_7_3_gdm_user_list", [
        "gsettings|org.gnome.login-screen|disable-user-list|^true$",
    ], True),
    "1.7.4": ("1_7_4_gdm_screen_lock", [
        "gsettings_uint|org.gnome.desktop.screensaver|lock-delay|0|5",
        "gsettings_uint|org.gnome.desktop.session|idle-delay|1|900",
    ], True),
    "1.7.5": ("1_7_5_gdm_screen_lock_lock", [
        r"locks|^\h*/org/gnome/desktop/session/idle-delay\b",
        r"locks|^\h*/org/gnome/desktop/screensaver/lock-delay\b",
    ], True),
    "1.7.6": ("1_7_6_gdm_automount", [
        "gsettings|org.gnome.desktop.media-handling|automount|^false$",
        "gsettings|org.gnome.desktop.media-handling|automount-open|^false$",
    ], True),
    "1.7.7": ("1_7_7_gdm_automount_lock", [
        r"locks|^\h*automount\h*=\h*false\b",
        r"locks|^\h*automount-open\h*=\h*false\b",
    ], True),
    "1.7.8": ("1_7_8_gdm_autorun_never", [
        "gsettings|org.gnome.desktop.media-handling|autorun-never|^true$",
    ], True),
    "1.7.9": ("1_7_9_gdm_autorun_never_lock", [
        r"locks|^\h*autorun-never\h*=\h*true\b",
    ], True),
    "1.7.10": ("1_7_10_gdm_xdmcp", ["xdmcp"], False),
}

STALE_DIRS = (
    "1_7_1_motd", "1_7_2_issue", "1_7_3_issue_net", "1_7_4_motd_permissions",
    "1_7_5_issue_permissions", "1_7_6_issue_net_permissions",
    "1_7_7_gdm_banner", "1_7_8_gdm_user_list", "1_7_9_gdm_xdmcp",
    "1_7_10_gdm_xdmcp2",
)


def load(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def wrapper_vars(path):
    collected = {}
    for task in load(path):
        if isinstance(task.get("ansible.builtin.import_role"), dict):
            collected.update(task.get("vars") or {})
    return collected


def delegated_vars(path, mechanism):
    for task in load(path):
        imported = task.get("ansible.builtin.import_tasks")
        if isinstance(imported, str) and imported.endswith(mechanism):
            return task.get("vars", {})
    return {}


class MechanismProbeStructureTest(unittest.TestCase):
    """Runtime gotchas the mechanism must not regress on."""

    def test_environment_is_a_task_keyword_not_a_module_arg(self):
        # `environment` nested inside the shell module args is an
        # "Unsupported parameters" module error, masked by failed_when:false
        # into an empty-evidence FAIL (found on the first lab runtime pass).
        tasks = load(MECHANISM / "inspect.yml")
        probe = next(t for t in tasks if "ansible.builtin.shell" in t)
        self.assertNotIn("environment", probe["ansible.builtin.shell"])
        self.assertIn("CIS_GDM_CHECKS_JSON", probe["environment"])

    def test_probe_runs_in_check_mode_with_become_and_no_failures(self):
        tasks = load(MECHANISM / "inspect.yml")
        probe = next(t for t in tasks if "ansible.builtin.shell" in t)
        self.assertIs(False, probe["check_mode"])
        self.assertIs(False, probe["failed_when"])
        self.assertIs(False, probe["changed_when"])
        self.assertIs(True, probe["become"])

    def test_1_7_10_remediation_uses_the_stat_item_value(self):
        text = (COMMON / "sections/section_01_initial_setup/1_7_10_gdm_xdmcp/remediation.yml"
                ).read_text(encoding="utf-8")
        # A skipped loop result carries item as a bare path string: item.item
        # is correct, item.item.path raised a loop_control label warning.
        self.assertNotIn("item.item.path", text)
        self.assertIn("{{ item.item }}", text)


class WrapperAlignmentTest(unittest.TestCase):
    """Platform wrappers carry the benchmark GDM checks, not the banners."""

    def test_stale_banner_control_directories_are_gone(self):
        for base in (COMMON, DEBIAN, UBUNTU):
            for stale in STALE_DIRS:
                with self.subTest(path=f"{base / 'sections/section_01_initial_setup' / stale}"):
                    self.assertFalse((base / "sections/section_01_initial_setup" / stale).exists())

    def test_wrappers_carry_expected_checks_and_gate_package(self):
        for base in (DEBIAN, UBUNTU):
            for number, (directory, checks, gate) in CONTROLS.items():
                for phase in PHASES:
                    vars_ = wrapper_vars(
                        base / f"sections/section_01_initial_setup/{directory}" / phase)
                    with self.subTest(role=base.parts[-2], control=number, phase=phase):
                        self.assertEqual(number, vars_["cis_linux_common_control_id"])
                        if checks is None:
                            # 1.7.1: the benchmark audit is "gdm3 is not installed".
                            self.assertEqual("gdm3", vars_["cis_linux_common_package_name"])
                        else:
                            self.assertEqual("gdm3", vars_["cis_linux_common_gdm_gate_package"])
                            self.assertEqual(checks, vars_["cis_linux_common_gdm_checks"])
                            if gate is False:
                                self.assertIs(False, vars_["cis_linux_common_gdm_apply_gate"])
                            else:
                                self.assertNotIn("cis_linux_common_gdm_apply_gate", vars_)

    def test_no_1_7_control_observes_banner_files(self):
        # The original defect: /etc/motd, /etc/issue and /etc/issue.net under
        # GDM control ids. Those files belong to 1.6.x only.
        for base in (COMMON, DEBIAN, UBUNTU):
            for directory, _checks, _gate, in CONTROLS.values():
                for phase in PHASES:
                    text = (base / "sections/section_01_initial_setup" / directory / phase).read_text(
                        encoding="utf-8")
                    with self.subTest(path=f"{base.parts[-2]}/{directory}/{phase}"):
                        self.assertNotIn("manual_path", text)
                        self.assertNotIn("/etc/motd", text)
                        self.assertNotIn("/etc/issue", text)
                        self.assertNotRegex(text, r"manual_observation")

    def test_common_sections_delegate_to_the_right_mechanisms(self):
        for number, (directory, checks, _gate) in CONTROLS.items():
            mechanism = ("mechanisms/package_absent/" if checks is None
                         else "mechanisms/gdm_configuration/")
            phases = list(PHASES)
            if directory == "1_7_10_gdm_xdmcp":
                # XDMCP remediation edits [xdmcp] blocks in place, not dconf
                # files: it deliberately does not delegate to the mechanism.
                phases = ["audit.yml", "verification.yml"]
            for phase in phases:
                imported = [task.get("ansible.builtin.import_tasks")
                            for task in load(COMMON / f"sections/section_01_initial_setup/{directory}" / phase)
                            if isinstance(task.get("ansible.builtin.import_tasks"), str)]
                with self.subTest(control=number, phase=phase):
                    self.assertTrue(any(p.endswith(f"{mechanism}{phase}") for p in imported),
                                    f"{directory}/{phase}: {imported}")


class RoutingGateTest(unittest.TestCase):
    """1.7 controls left the `na`/manual_observation placeholder routing."""

    def roles(self):
        for role, prefix in (("cis_debian_12", "cis_debian_12"), ("cis_ubuntu_2404", "cis_ubuntu_2404")):
            yield role, prefix, load(ROOT / f"roles/{role}/tasks/main.yml")

    def test_routes_are_gated_audited_and_remediation_opt_in(self):
        for role, prefix, tasks in self.roles():
            for number, (directory, _checks, _gate) in CONTROLS.items():
                tag = "cis_" + number.replace(".", "_")
                var = f"{prefix}_{directory}"
                modes = {}
                for task in tasks:
                    source = task.get("ansible.builtin.import_tasks")
                    if isinstance(source, str) and f"/{directory}/" in source:
                        mode = source.rsplit("/", 1)[1].removesuffix(".yml")
                        modes.setdefault(mode, []).append(task)
                with self.subTest(role=role, control=number):
                    self.assertEqual({"audit", "remediation", "verification"}, set(modes))
                    for mode, hits in modes.items():
                        self.assertEqual(1, len(hits))
                        task = hits[0]
                        self.assertIn(tag, task["tags"])
                        self.assertNotIn("na", task["tags"])
                        self.assertNotIn("manual_observation", task["tags"])
                        if mode == "remediation":
                            joined = " ".join(task["when"])
                            self.assertIn(f"{var}_remediate | bool", joined)
                            self.assertIn(f"{prefix}_remediation_enabled | bool", joined)

    def test_remediate_selectors_default_false_and_audited_selectors_true(self):
        for role, prefix in (("cis_debian_12", "cis_debian_12"), ("cis_ubuntu_2404", "cis_ubuntu_2404")):
            defaults = yaml.safe_load(
                (ROOT / f"roles/{role}/defaults/main.yml").read_text(encoding="utf-8"))
            for _number, (directory, _checks, _gate) in CONTROLS.items():
                var = f"{prefix}_{directory}"
                with self.subTest(role=role, control=directory):
                    self.assertIs(True, defaults[var])
                    self.assertIs(False, defaults[f"{var}_remediate"])

    def test_1_7_1_is_gated_unsafe_like_the_other_package_purges(self):
        for role, prefix in (("cis_debian_12", "cis_debian_12"), ("cis_ubuntu_2404", "cis_ubuntu_2404")):
            for task in load(ROOT / f"roles/{role}/tasks/main.yml"):
                source = task.get("ansible.builtin.import_tasks")
                if isinstance(source, str) and "1_7_1_gdm_removed" in source:
                    with self.subTest(role=role, mode=source):
                        self.assertIn("gated_unsafe", task["tags"])


class LedgerBackendTest(unittest.TestCase):
    """Regenerated ledger routes 1.7.x to the GDM mechanisms."""

    def routes_for(self, platform, control):
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if f'"platform":"{platform}"' in line and f'"control":"{control}"' in line:
                yield json.loads(line.strip().rstrip(","))

    def test_backends_and_remediation_routes(self):
        for platform in ("debian-12", "ubuntu-24.04"):
            for number, (directory, checks, _gate) in CONTROLS.items():
                expected = ("cis_linux_common.package_absent" if checks is None
                            else "cis_linux_common.gdm_configuration")
                seen = list(self.routes_for(platform, number))
                with self.subTest(platform=platform, control=number):
                    self.assertTrue(seen)
                    for route in seen:
                        self.assertEqual(expected, route["route"]["backend"])
                        self.assertNotEqual("na", route["disposition"])
                    self.assertEqual(
                        {"audit", "remediation", "verification"},
                        {route["route"]["mode"] for route in seen})


class MechanismClassificationTest(unittest.TestCase):
    """Mini evaluator for inspect.yml: canned probe results in, classification
    out, so the PASS / FAIL / NOT_APPLICABLE decision is proven, not asserted
    structurally (mirrors test_kernel_module_disabled.MechanismRun)."""

    def eval_inspect(self, checks, packages=("gdm3",), apply_gate=None, probe=None):
        env = jinja_environment()
        # Ansible ships a `match` test (anchored); plain Jinja only gained
        # `search`/`regex` extensions, so mirror the runtime semantics.
        env.tests.setdefault("match", lambda value, pattern: re.match(pattern, value or "") is not None)
        # Ansible's `bool` filter (plain Jinja lacks it): truthiness strings.
        env.filters.setdefault(
            "bool",
            lambda value: str(value).strip().lower() not in
            ("", "0", "false", "f", "no", "n", "off") if value is not None else False)
        context = {
            "cis_linux_common_control_id": "test",
            "cis_linux_common_platform": "test",
            "cis_linux_common_benchmark": "test",
            "cis_linux_common_gdm_gate_package": "gdm3",
            "cis_linux_common_gdm_checks": list(checks),
        }
        if apply_gate is not None:
            context["cis_linux_common_gdm_apply_gate"] = apply_gate
        ansible_facts = {"packages": {name: [{}] for name in packages}}
        context["ansible_facts"] = ansible_facts
        installed = "gdm3" in ansible_facts["packages"]
        gate = context.get("cis_linux_common_gdm_apply_gate", True)
        probe_required = installed or not gate
        if not probe_required:
            context["cis_linux_common_gdm_probe"] = {"skipped": True}
        elif probe is not None:
            context["cis_linux_common_gdm_probe"] = probe
        else:
            stdout = "\n".join(f"CHECK pass synthetic {c}" for c in checks)
            context["cis_linux_common_gdm_probe"] = {
                "rc": 0, "stdout": stdout, "stdout_lines": stdout.splitlines()}
        for task in load(MECHANISM / "inspect.yml"):
            if "ansible.builtin.package_facts" in task or "ansible.builtin.shell" in task:
                continue
            for key, template in task["ansible.builtin.set_fact"].items():
                context[key] = env.from_string(template).render(**context).strip()
        return context

    def state(self, *args, **kwargs):
        return self.eval_inspect(*args, **kwargs)["cis_linux_common_gdm_state"]

    def probe(self, lines, rc=0):
        stdout = "\n".join(lines)
        return {"rc": rc, "stdout": stdout, "stdout_lines": stdout.splitlines()}

    def test_absent_gdm_is_not_applicable_for_gated_controls(self):
        self.assertEqual("NOT_APPLICABLE",
                         self.state(["locks|^x$"], packages=()))

    def test_present_gdm_all_pass_is_pass(self):
        self.assertEqual("PASS", self.state(["locks|^x$"], packages=("gdm3",)))

    def test_ungated_control_probes_even_without_gdm(self):
        # 1.7.10: apply_gate false -> the probe runs even with gdm3 absent.
        context = self.eval_inspect(["xdmcp"], packages=(), apply_gate=False)
        self.assertEqual("PASS", context["cis_linux_common_gdm_state"])
        self.assertIsNot(context["cis_linux_common_gdm_probe"].get("skipped"), True)

    def test_single_failing_check_classifies_fail(self):
        self.assertEqual("FAIL", self.state(
            ["locks|^x$", "locks|^y$"],
            probe=self.probe(["CHECK pass locks ^x$", "CHECK fail locks ^y$"])))

    def test_unreadable_check_classifies_fail(self):
        self.assertEqual("FAIL", self.state(
            ["gsettings|a|b|^true$"],
            probe=self.probe(["CHECK unreadable gsettings a b (gsettings get failed)"])))

    def test_probe_command_failure_classifies_fail(self):
        self.assertEqual("FAIL", self.state(
            ["locks|^x$"], probe=self.probe(["CHECK pass locks ^x$"], rc=1)))

    def test_missing_evidence_line_classifies_fail(self):
        # One check declared, zero CHECK lines emitted -> fail closed.
        self.assertEqual("FAIL", self.state(["locks|^x$"], probe=self.probe([])))

    def test_extra_junk_line_classifies_fail(self):
        self.assertEqual("FAIL", self.state(
            ["locks|^x$"], probe=self.probe(["CHECK pass locks ^x$", "boom"])))

    def test_empty_check_list_fails_closed(self):
        self.assertEqual("FAIL", self.state([], packages=("gdm3",)))

    def test_not_applicable_wins_even_with_hostile_probe_state(self):
        self.assertEqual("NOT_APPLICABLE", self.state(
            ["locks|^x$"], packages=(), probe=self.probe(["CHECK fail locks ^x$"], rc=1)))


class ProbePatternSemanticsTest(unittest.TestCase):
    """The regexes the wrappers hand to `grep -P` (and the remediation files
    that must satisfy them) stay semantically aligned. \\h is PCRE-only, so it
    is translated for the python engine exactly like GNU grep -P interprets
    it (horizontal whitespace)."""

    @staticmethod
    def pcre(pattern):
        # \\h is horizontal whitespace in PCRE (GNU grep -P); re.M so ^ anchors
        # each line. Note Pattern.search's second positional is `pos`, not
        # flags — the flag must go on compile().
        return re.compile(pattern.replace(r"\h", r"[ \t]"), re.M)

    def locks_patterns(self):
        for base in (DEBIAN, UBUNTU):
            vars_ = wrapper_vars(base / "sections/section_01_initial_setup/"
                                 "1_7_5_gdm_screen_lock_lock/audit.yml")
            return [c.split("|", 1)[1] for c in vars_["cis_linux_common_gdm_checks"]]

    def test_1_7_5_locks_patterns_match_their_remediation(self):
        remediation = delegated_vars(
            COMMON / "sections/section_01_initial_setup/1_7_5_gdm_screen_lock_lock/remediation.yml",
            "mechanisms/gdm_configuration/remediation.yml")
        content = remediation["cis_linux_common_gdm_remediate_files"][0]["content"]
        for pattern in self.locks_patterns():
            with self.subTest(pattern=pattern):
                self.assertTrue(self.pcre(pattern).search(content, re.M), content)

    def test_locks_value_checks_match_their_remediation_files(self):
        for directory in ("1_7_7_gdm_automount_lock", "1_7_9_gdm_autorun_never_lock"):
            patterns = [c.split("|", 1)[1] for c in wrapper_vars(
                DEBIAN / f"sections/section_01_initial_setup/{directory}/audit.yml"
            )["cis_linux_common_gdm_checks"]]
            files = delegated_vars(
                COMMON / f"sections/section_01_initial_setup/{directory}/remediation.yml",
                "mechanisms/gdm_configuration/remediation.yml",
            )["cis_linux_common_gdm_remediate_files"]
            content = "\n".join(entry["content"] for entry in files)
            for pattern in patterns:
                with self.subTest(control=directory, pattern=pattern):
                    self.assertTrue(self.pcre(pattern).search(content, re.M), content)

    def test_gsettings_expects_match_the_benchmark_outputs(self):
        # Exact outputs the benchmark audit shows must satisfy the expects.
        accepted = {
            "gsettings|org.gnome.login-screen|banner-message-enable|^true$": "true",
            "gsettings|org.gnome.login-screen|disable-user-list|^true$": "true",
            "gsettings|org.gnome.desktop.media-handling|automount|^false$": "false",
            "gsettings|org.gnome.desktop.media-handling|automount-open|^false$": "false",
            "gsettings|org.gnome.desktop.media-handling|autorun-never|^true$": "true",
        }
        rejected = {
            "gsettings|org.gnome.login-screen|banner-message-enable|^true$": "false",
            "gsettings|org.gnome.login-screen|disable-user-list|^true$": "",
            "gsettings|org.gnome.desktop.media-handling|automount|^false$": "true",
        }
        for check, stdout in accepted.items():
            regex = check.split("|", 3)[3]
            with self.subTest(accept=check, stdout=stdout):
                self.assertTrue(re.fullmatch(regex, stdout))
        for check, stdout in rejected.items():
            regex = check.split("|", 3)[3]
            with self.subTest(reject=check, stdout=stdout):
                self.assertIsNone(re.fullmatch(regex, stdout))

    def test_banner_text_check_rejects_empty_and_accepts_site_text(self):
        # gsettings_text renders ^'..*'$ inside the probe; mirror it here.
        quoted = re.compile(r"^'..*'$")
        self.assertIsNone(quoted.fullmatch("''"))
        self.assertIsNotNone(quoted.fullmatch(
            "'Authorized uses only. All activity may be monitored and reported'"))

    def test_uint_bounds_follow_the_benchmark_notes(self):
        # lock-delay 5 or less; idle-delay 900 or less and never 0.
        bounds = {c: (c.split("|")[3], c.split("|")[4]) for c in
                  wrapper_vars(DEBIAN / "sections/section_01_initial_setup/"
                               "1_7_4_gdm_screen_lock/audit.yml")["cis_linux_common_gdm_checks"]}
        self.assertIn("gsettings_uint|org.gnome.desktop.screensaver|lock-delay|0|5", bounds)
        self.assertIn("gsettings_uint|org.gnome.desktop.session|idle-delay|1|900", bounds)


class RemediationDelegateTest(unittest.TestCase):
    """The dconf artifacts written per control mirror the benchmark."""

    def files_for(self, directory):
        return delegated_vars(
            COMMON / f"sections/section_01_initial_setup/{directory}/remediation.yml",
            "mechanisms/gdm_configuration/remediation.yml",
        )["cis_linux_common_gdm_remediate_files"]

    def test_paths_and_contents_follow_the_benchmark(self):
        expected = {
            "1_7_2_gdm_banner": ("/etc/dconf/db/gdm.d/01-banner-message", "banner-message-enable=true"),
            "1_7_3_gdm_user_list": ("/etc/dconf/db/gdm.d/00-login-screen", "disable-user-list=true"),
            "1_7_4_gdm_screen_lock": ("/etc/dconf/db/local.d/00-screensaver", "idle-delay=uint32 900"),
            "1_7_5_gdm_screen_lock_lock": (
                "/etc/dconf/db/local.d/locks/00-screensaver",
                "/org/gnome/desktop/session/idle-delay"),
            "1_7_6_gdm_automount": ("/etc/dconf/db/local.d/00-media-automount", "automount=false"),
            "1_7_7_gdm_automount_lock": (
                "/etc/dconf/db/local.d/locks/00-media-automount", "automount-open=false"),
            "1_7_8_gdm_autorun_never": ("/etc/dconf/db/local.d/00-media-autorun", "autorun-never=true"),
            "1_7_9_gdm_autorun_never_lock": (
                "/etc/dconf/db/local.d/locks/00-media-autorun", "autorun-never=true"),
        }
        for directory, (path, needle) in expected.items():
            entries = self.files_for(directory)
            with self.subTest(control=directory):
                self.assertEqual([path], [entry["path"] for entry in entries])
                self.assertIn(needle, entries[0]["content"])

    def test_1_7_10_remediation_comments_only_xdmcp_enable_true(self):
        tasks = load(COMMON / "sections/section_01_initial_setup/1_7_10_gdm_xdmcp/remediation.yml")
        text = str(tasks)
        self.assertIn("[xdmcp]", text)
        self.assertIn("/etc/gdm3/custom.conf", text)
        self.assertIn("/etc/gdm/daemon.conf", text)
        shell = [t for t in tasks if "ansible.builtin.shell" in t][0]
        self.assertIn("changed_when", shell)
        # Case-sensitive like the benchmark audit awk.
        self.assertIn("/^[[:space:]]*Enable[[:space:]]*=[[:space:]]*true", shell["ansible.builtin.shell"]["cmd"])


if __name__ == "__main__":
    unittest.main()
