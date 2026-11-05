"""CIS kernel-module controls must prove the module is actually unavailable.

The old config_line wiring only checked that `install <mod> /bin/true` and
`blacklist <mod>` lines existed in one modprobe.d file. The shared
kernel_module_disabled mechanism additionally verifies:

* the effective `modprobe --showconfig` resolves both entries (a file line can
  be shadowed or malformed),
* `lsmod` does not show the module loaded,
* the module is actually loadable (.ko in any installed kernel) -- absent or
  built-in modules are NOT_APPLICABLE per the benchmark,
* unreadable probe state fails closed instead of passing,
* the overlayfs -> overlay benchmark mapping (1.1.1.6) and the usb-storage
  dash/underscore normalization survive the rewrite.
"""

from pathlib import Path
import re
import unittest

from jinja2 import StrictUndefined
import yaml

from test_config_line_missing_file import jinja_environment

ROOT = Path(__file__).resolve().parents[1] / "roles" / "cis_linux_common" / "tasks"
MECHANISM = ROOT / "mechanisms" / "kernel_module_disabled"
COMMON = ROOT / "sections"
PLATFORM_ROLES = ("cis_debian_12", "cis_ubuntu_2404")

CONTROLS = {
    "1.1.1.1": ("section_01_initial_setup/1_1_1_1_cramfs", "cramfs"),
    "1.1.1.2": ("section_01_initial_setup/1_1_1_2_freevxfs", "freevxfs"),
    "1.1.1.3": ("section_01_initial_setup/1_1_1_3_hfs", "hfs"),
    "1.1.1.4": ("section_01_initial_setup/1_1_1_4_hfsplus", "hfsplus"),
    "1.1.1.5": ("section_01_initial_setup/1_1_1_5_jffs2", "jffs2"),
    "1.1.1.6": ("section_01_initial_setup/1_1_1_6_overlayfs", "overlay"),
    "1.1.1.7": ("section_01_initial_setup/1_1_1_7_squashfs", "squashfs"),
    "1.1.1.8": ("section_01_initial_setup/1_1_1_8_udf", "udf"),
    "1.1.1.9": ("section_01_initial_setup/1_1_1_9_usb_storage", "usb-storage"),
    "3.2.1": ("section_03_network/3_2_1_dccp", "dccp"),
    "3.2.2": ("section_03_network/3_2_2_tipc", "tipc"),
    "3.2.3": ("section_03_network/3_2_3_rds", "rds"),
    "3.2.4": ("section_03_network/3_2_4_sctp", "sctp"),
}
PHASES = ("audit", "remediation", "verification")

SKIPPED = {"changed": False, "skipped": True}


def disabled_showconfig(module):
    """Effective dump with the benchmark-disable entries for one module, in
    the underscore spelling kmod uses inside `modprobe --showconfig`."""
    under = module.replace("-", "_")
    return f"install {under} /bin/true\nblacklist {under}\n"


def load(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def ansible_template(source):
    """Render a task template the way ansible-core 2.21 does, not plain Jinja.

    ansible-core >= 2.19 stopped interpreting Python-style escape sequences in
    Jinja string literals: '{{ '\\b' }}' reaches the template output as the
    two characters backslash+b. Plain Jinja collapses them (and turns '\\b'
    into a backspace), which diverged the harness from the runtime and made a
    runtime-correct mechanism test red (and vice versa). Doubling every
    backslash before plain rendering restores the collapsed result to the
    exact bytes ansible produces, so the mechanism files can keep the single
    regex backslashes that are correct for the real engine.
    """
    return source.replace("\\", "\\\\")


def probe(stdout="", rc=0):
    return {"changed": False, "rc": rc, "stdout": stdout, "stdout_lines":
            stdout.splitlines(), "stderr": "", "stderr_lines": []}


class MechanismRun:
    """Mini Ansible evaluator for inspect.yml: canned probe results in,
    rendered facts out, so the decision logic is proven, not asserted
    structurally."""

    def __init__(self, module, package="kmod", packages=("kmod",), **overrides):
        self.env = jinja_environment()
        self.context = {
            "cis_linux_common_kernel_module": module,
            "cis_linux_common_config_line_package": package,
            "cis_linux_common_config_line_path":
                f"/etc/modprobe.d/{module}.conf",
            "cis_linux_common_control_id": "test",
            "cis_linux_common_platform": "test",
            "ansible_facts": {"packages": {name: [{}] for name in packages}},
        }
        self.probes = {}
        self.overrides = overrides

    def _probes(self):
        # Resolve every probe override without nesting probe(): passing
        # probe(result) as an eager .get() default would re-probe a dict.
        availability_token = (
            "LOADABLE" if self.overrides.get("loadable", True) else "NOT_LOADABLE")
        defaults = {
            "lsmod": probe("Module Size Used by\n"),
            "showconfig": probe(disabled_showconfig(
                self.context["cis_linux_common_kernel_module"])),
            "availability": probe(availability_token),
            "builtin": probe("NOT_BUILTIN"),
        }
        merged = {key: self.overrides.get(key, value)
                  for key, value in defaults.items()}
        return {
            "cis_linux_common_kernel_module_lsmod_probe": merged["lsmod"],
            "cis_linux_common_kernel_module_showconfig_probe": merged["showconfig"],
            "cis_linux_common_kernel_module_availability_probe": merged["availability"],
            "cis_linux_common_kernel_module_builtin_probe": merged["builtin"],
        }

    def run(self):
        if "kmod" not in self.context["ansible_facts"]["packages"]:
            # Mirrors the mechanism: every probe is gated on the package fact.
            self.probes = {name: dict(SKIPPED) for name in self._probes()}
        else:
            self.probes = self._probes()
        for task in load(MECHANISM / "inspect.yml"):
            if "ansible.builtin.package_facts" in task:
                continue
            if "ansible.builtin.set_fact" in task:
                for key, template in task["ansible.builtin.set_fact"].items():
                    self.context[key] = self.env.from_string(
                        ansible_template(template)).render(**self.context)
            elif "ansible.builtin.command" in task or "ansible.builtin.shell" in task:
                self.context[task["register"]] = self.probes[task["register"]]
            else:
                raise AssertionError(f"unexpected inspect task: {task['name']}")
        return self.context

    def render(self, template):
        return self.env.from_string(ansible_template(template)).render(**self.context)

    def holds(self, task):
        when = task.get("when")
        if when is None:
            return True
        conditions = when if isinstance(when, list) else [when]
        return all(bool(self.env.compile_expression(ansible_template(c))(**self.context))
                   for c in conditions)


class ClassificationTest(unittest.TestCase):
    def state(self, module="cramfs", **overrides):
        return MechanismRun(module, **overrides).run()[
            "cis_linux_common_kernel_module_state"]

    def test_loadable_configured_unloaded_passes(self):
        # The file line is not the proof: the effective --showconfig dump
        # carries both entries and lsmod is clear.
        self.assertEqual("PASS", self.state(loadable=True))

    def test_loadable_but_unconfigured_fails(self):
        for showconfig in (
                probe(""),  # configured file never reached modprobe
                probe("blacklist cramfs\n"),  # install entry missing
                probe("install cramfs /bin/true\n"),  # blacklist missing
                probe("install cramfs /bin/echo\n"),  # not true/false
        ):
            with self.subTest(showconfig=showconfig["stdout"] or "empty"):
                self.assertEqual("FAIL", self.state(showconfig=showconfig))

    def test_loaded_module_fails_even_when_configured(self):
        self.assertEqual("FAIL", self.state(
            lsmod=probe("Module                  Size  Used by\ncramfs   32768  1\n")))

    def test_similar_module_name_is_not_confused(self):
        # hfs must treat a loaded hfsplus as NOT loaded, but a loaded hfs IS
        # loaded: the lsmod match is anchored to the first column.
        hfsplus_only = probe("Module                  Size  Used by\n"
                             "hfsplus   32768  0\n")
        self.assertEqual("PASS", self.state("hfs", lsmod=hfsplus_only))
        self.assertEqual("FAIL", self.state("hfsplus", lsmod=hfsplus_only))

    def test_builtin_module_is_not_applicable(self):
        # No .ko anywhere (e.g. compiled into the kernel): no config required.
        self.assertEqual("NOT_APPLICABLE", self.state(
            loadable=False, builtin=probe("BUILTIN")))

    def test_unavailable_module_is_not_applicable(self):
        for availability in (probe("NOT_LOADABLE"), probe("NO_KERNEL_TREE")):
            with self.subTest(token=availability["stdout"]):
                self.assertEqual("NOT_APPLICABLE", self.state(
                    loadable=False, availability=availability,
                    # Loaded state is authoritative even when not loadable:
                    showconfig=probe("")),
                    msg=availability["stdout"])

    def test_loadable_loaded_is_fail_before_availability_judgement(self):
        self.assertEqual("FAIL", self.state(
            lsmod=probe("Module Size Used by\nhfs 20480 0\n"),
            loadable=True, showconfig=probe("")))

    def test_unreadable_state_fails_closed(self):
        cases = {
            "lsmod_unreadable": {"lsmod": probe("", rc=1)},
            "availability_probe_error": {"availability": probe("PROBE_ERROR")},
            "availability_garbage": {"availability": probe("SOMETHING_ELSE")},
            "showconfig_unreadable_while_loadable": {"showconfig": probe("", rc=1)},
        }
        for label, overrides in cases.items():
            with self.subTest(case=label):
                self.assertEqual("FAIL", self.state(**overrides))

    def test_absent_kmod_package_is_not_applicable(self):
        run = MechanismRun("cramfs", packages=())
        self.assertEqual("NOT_APPLICABLE",
                         run.run()["cis_linux_common_kernel_module_state"])

    def test_showconfig_normalization_accepts_underscore_or_true_forms(self):
        # kmod normalizes '-' to '_' in --showconfig; both /bin/true and
        # /bin/false (and the /usr/bin prefix) satisfy the benchmark.
        for install_cmd in ("/bin/true", "/bin/false", "/usr/bin/false"):
            showconfig = probe(
                f"install cramfs {install_cmd}\nblacklist cramfs\n")
            with self.subTest(cmd=install_cmd):
                self.assertEqual("PASS", self.state(showconfig=showconfig))


class BenchmarkNameMappingTest(unittest.TestCase):
    def test_overlayfs_control_resolves_to_overlay_module(self):
        # The 1.1.1.6 wrappers pass the benchmark check name "overlay".
        run = MechanismRun("overlay")
        context = run.run()
        self.assertEqual("overlay", context["cis_linux_common_kernel_module_under"])
        self.assertEqual("PASS", context["cis_linux_common_kernel_module_state"])

    def test_obsolete_overlayfs_lines_alone_cannot_pass(self):
        # A host that only has the retired managed lines must FAIL: the
        # effective dump needs the overlay entries themselves.
        self.assertEqual("FAIL", MechanismRun("overlay", showconfig=probe(
            "install overlayfs /bin/true\nblacklist overlayfs\n")).run()[
            "cis_linux_common_kernel_module_state"])

    def test_usb_storage_dash_and_underscore_forms(self):
        run = MechanismRun("usb-storage")
        context = run.run()
        self.assertEqual("usb_storage", context["cis_linux_common_kernel_module_under"])
        self.assertEqual("PASS", context["cis_linux_common_kernel_module_state"])
        # lsmod reports the underscore spelling: loaded detection uses it.
        loaded = MechanismRun("usb-storage", lsmod=probe(
            "Module                  Size  Used by\nusb_storage  77824  0\n"))
        self.assertEqual("yes", loaded.run()["cis_linux_common_kernel_module_loaded"])
        self.assertEqual("FAIL", loaded.run()["cis_linux_common_kernel_module_state"])
        # The managed file line keeps the dashed benchmark spelling.
        rem = load(MECHANISM / "remediation.yml")
        install = next(t for t in rem if "ansible.builtin.lineinfile" in t)
        self.assertEqual("install usb-storage /bin/true",
                         install["ansible.builtin.lineinfile"]["line"]
                         .replace("{{ cis_linux_common_kernel_module }}",
                                  "usb-storage"))


class VerificationAndAuditBehaviourTest(unittest.TestCase):
    def classification(self, run):
        audit = load(MECHANISM / "audit.yml")
        debug = next(t for t in audit if "ansible.builtin.debug" in t)
        return run.render(debug["ansible.builtin.debug"]["msg"]["classification"])

    def test_audit_debug_reports_the_computed_classification(self):
        for label, overrides, expected in (
                ("pass", {}, "PASS"),
                ("loaded", {"lsmod": probe("Module Size Used by\noverlay 1 0\n")},
                 "FAIL"),
                ("not loadable", {"loadable": False}, "NOT_APPLICABLE"),
        ):
            with self.subTest(case=label):
                run = MechanismRun("overlay", **overrides)
                run.run()
                self.assertEqual(expected, self.classification(run))

    def assert_expression(self):
        verify = load(MECHANISM / "verification.yml")
        return next(t for t in verify
                    if "ansible.builtin.assert" in t)["ansible.builtin.assert"][
            "that"][0]

    def test_verification_assert_mirrors_the_classification(self):
        expression = self.assert_expression()
        for label, overrides, accepted in (
                ("configured", {}, True),
                ("unconfigured", {"showconfig": probe("")}, False),
                ("loaded", {"lsmod": probe("Module Size Used by\ncramfs 32768 1\n")},
                 False),
                ("unreadable", {"lsmod": probe("", rc=1)}, False),
                ("builtin", {"loadable": False, "builtin": probe("BUILTIN")}, True),
                ("absent", {"loadable": False}, True),
        ):
            run = MechanismRun("cramfs", **overrides)
            context = run.run()
            env = jinja_environment()
            with self.subTest(case=label):
                self.assertEqual(
                    accepted,
                    bool(env.compile_expression(ansible_template(expression))(**context)))

    def test_verification_fail_msg_renders_under_strict_undefined(self):
        verify = load(MECHANISM / "verification.yml")
        assert_task = next(t for t in verify
                           if "ansible.builtin.assert" in t)["ansible.builtin.assert"]
        run = MechanismRun("cramfs")
        context = run.run()
        env = jinja_environment(undefined=StrictUndefined)
        for field in ("fail_msg", "success_msg"):
            with self.subTest(field=field):
                env.from_string(assert_task[field]).render(**context)


class RemediationGateTest(unittest.TestCase):
    """The remediation must write only install+blacklist lines, only when the
    module is loadable and the effective config lacks the entry, and unload
    only when loaded and safe."""

    def tasks(self):
        return load(MECHANISM / "remediation.yml")

    def lineinfile_tasks(self):
        return [t for t in self.tasks() if "ansible.builtin.lineinfile" in t]

    def test_write_gates_are_effective_and_loadability_aware(self):
        for missing in ("install", "blacklist"):
            task = next(t for t in self.lineinfile_tasks()
                        if t["ansible.builtin.lineinfile"]["line"].startswith(missing))
            conditions = " ".join(task["when"])
            with self.subTest(entry=missing):
                self.assertIn(f"cis_linux_common_kernel_module_loadable == 'yes'",
                              conditions)
                self.assertIn(
                    f"cis_linux_common_kernel_module_effective_{missing} == 'no'",
                    conditions)
                self.assertIn("cis_linux_common_kernel_module_probes_ok == 'yes'",
                              conditions)
                self.assertIn("cis_linux_common_config_line_package "
                              "in ansible_facts.packages", conditions)

    def test_writes_are_skipped_when_already_effective(self):
        run = MechanismRun("cramfs")
        run.run()
        for task in self.lineinfile_tasks():
            with self.subTest(name=task["name"]):
                self.assertFalse(run.holds(task))

    def test_writes_run_only_for_the_missing_effective_entries(self):
        run = MechanismRun("cramfs", showconfig=probe("blacklist cramfs\n"))
        run.run()
        for task in self.lineinfile_tasks():
            line = task["ansible.builtin.lineinfile"]["line"]
            with self.subTest(line=line):
                self.assertEqual(line.startswith("install"), run.holds(task))

    def test_writes_are_skipped_for_unavailable_modules(self):
        run = MechanismRun("cramfs", loadable=False)
        run.run()
        for task in self.lineinfile_tasks():
            with self.subTest(name=task["name"]):
                self.assertFalse(run.holds(task))

    def test_unload_only_runs_when_loaded(self):
        unload = next(t for t in self.tasks()
                      if "ansible.builtin.command" in t
                      and "modprobe -r" in t["ansible.builtin.command"]["cmd"])
        self.assertIn("{{ cis_linux_common_kernel_module }}",
                      unload["ansible.builtin.command"]["cmd"])
        self.assertFalse(unload["failed_when"])
        self.assertTrue(unload["changed_when"])
        unloaded = MechanismRun("cramfs")
        unloaded.run()
        self.assertFalse(unloaded.holds(unload))
        loaded = MechanismRun("cramfs", lsmod=probe(
            "Module Size Used by\ncramfs 32768 1\n"))
        loaded.run()
        self.assertTrue(loaded.holds(unload))
        # In check mode the command is skipped; the confirm chain must follow.
        skipped_ctx = {"cis_linux_common_kernel_module_unload": dict(SKIPPED)}
        post = next(t for t in self.tasks()
                    if t.get("register") == "cis_linux_common_kernel_module_post_unload_probe")
        merged = dict(loaded.context, **skipped_ctx)
        env = jinja_environment()
        self.assertFalse(all(bool(env.compile_expression(ansible_template(c))(**merged))
                             for c in post["when"]))

    def test_confirm_assert_requires_reloaded_absence(self):
        confirm = next(t for t in self.tasks() if "ansible.builtin.assert" in t)
        env = jinja_environment()
        base = MechanismRun("cramfs", lsmod=probe(
            "Module Size Used by\ncramfs 32768 1\n"))
        context = base.run()
        for stdout, rc, accepted in (
                ("Module Size Used by\n", 0, True),  # unload succeeded
                ("Module Size Used by\ncramfs 32768 1\n", 0, False),  # in use
                ("", 1, False),  # post state unreadable
        ):
            merged = dict(context, cis_linux_common_kernel_module_post_unload_probe=
                          probe(stdout, rc))
            with self.subTest(stdout=stdout or "empty", rc=rc):
                self.assertTrue(all(bool(env.compile_expression(ansible_template(c))(**merged))
                                    for c in confirm["when"]))
                self.assertEqual(
                    accepted,
                    all(bool(env.compile_expression(ansible_template(c))(**merged))
                        for c in confirm["ansible.builtin.assert"]["that"]))

    def test_remediation_touches_no_files_beyond_the_managed_path(self):
        for task in self.lineinfile_tasks():
            self.assertEqual("{{ cis_linux_common_config_line_path }}",
                             task["ansible.builtin.lineinfile"]["path"])
            self.assertNotIn("line", task["ansible.builtin.lineinfile"]
                             if task["ansible.builtin.lineinfile"].get("state")
                             == "absent" else ())


class TaskSchemaTest(unittest.TestCase):
    """Probes must stay executable by the real module, not just renderable.

    An `environment:` nested inside the module arguments (instead of as the
    task keyword) reaches command/shell as an unsupported parameter; the probe
    then fails, `failed_when: false` hides it as "ok", and every host is
    permanently classified FAIL with unreadable probes. Runtime hit exactly
    this; the classification tests cannot see it because they only feed the
    set_fact templates.
    """

    def test_shell_environment_is_a_task_keyword_not_a_module_argument(self):
        inspect = load(MECHANISM / "inspect.yml")
        shell_tasks = [t for t in inspect if "ansible.builtin.shell" in t]
        self.assertEqual(2, len(shell_tasks))
        for task in shell_tasks:
            with self.subTest(task=task["name"]):
                self.assertNotIn("environment", task["ansible.builtin.shell"])
                env = task.get("environment")
                self.assertIsInstance(env, dict)
                self.assertEqual(
                    {"MOD_NAME", "MOD_UNDER"},
                    set(env))


class ControlWiringTest(unittest.TestCase):
    def test_common_controls_delegate_to_the_mechanism(self):
        for cid, (rel, module) in CONTROLS.items():
            for phase in PHASES:
                tasks = load(COMMON / rel / f"{phase}.yml")
                imports = [t for t in tasks
                           if "ansible.builtin.import_tasks" in t]
                with self.subTest(control=cid, phase=phase):
                    self.assertEqual(1, len(
                        [t for t in imports if t["ansible.builtin.import_tasks"]
                         == f"mechanisms/kernel_module_disabled/{phase}.yml"]))
                    self.assertNotIn("mechanisms/config_line",
                                     [t["ansible.builtin.import_tasks"]
                                      for t in imports])

    def test_overlayfs_remediation_still_retires_obsolete_lines(self):
        tasks = load(COMMON / "section_01_initial_setup/1_1_1_6_overlayfs" /
                     "remediation.yml")
        imports = [t for t in tasks if "ansible.builtin.import_tasks" in t]
        removals = [t for t in tasks
                    if "ansible.builtin.lineinfile" in t
                    and t["ansible.builtin.lineinfile"].get("state") == "absent"]
        self.assertEqual(2, len(removals))
        self.assertLess(tasks.index(imports[-1]), tasks.index(removals[0]))

    def test_platform_wrappers_pass_the_mechanism_inputs(self):
        expected = {
            "1.1.1.1": ("cramfs", "/etc/modprobe.d/cramfs.conf"),
            "1.1.1.6": ("overlay", "/etc/modprobe.d/overlayfs.conf"),
            "1.1.1.9": ("usb-storage", "/etc/modprobe.d/usb-storage.conf"),
            "3.2.1": ("dccp", "/etc/modprobe.d/dccp.conf"),
            "3.2.4": ("sctp", "/etc/modprobe.d/sctp.conf"),
        }
        for cid, (module, config_path) in expected.items():
            rel = CONTROLS[cid][0]
            for platform in PLATFORM_ROLES:
                for phase in PHASES:
                    tasks = load(ROOT.parent.parent / platform / "tasks" /
                                 "sections" / rel / f"{phase}.yml")
                    vars_ = tasks[0]["vars"]
                    with self.subTest(control=cid, platform=platform, phase=phase):
                        self.assertEqual(module,
                                         vars_["cis_linux_common_kernel_module"])
                        self.assertEqual(config_path,
                                         vars_["cis_linux_common_config_line_path"])
                        self.assertEqual("kmod",
                                         vars_["cis_linux_common_config_line_package"])

    def test_ledger_routes_kernel_module_controls_to_the_new_mechanism(self):
        # ansible/scripts lives two levels above roles/, not inside it.
        text = (ROOT.parent.parent.parent / "scripts" / "generate_ledger.py").read_text(
            encoding="utf-8")
        for cid, (_rel, _module) in CONTROLS.items():
            self.assertIn(f'("{cid}", "kernel_module_disabled")', text)
        # The rules must precede the 1.1.1. prefix fallback (first match wins).
        self.assertLess(text.index('("1.1.1.1", "kernel_module_disabled")'),
                        text.index('("1.1.1.", "config_line")'))


if __name__ == "__main__":
    unittest.main()
