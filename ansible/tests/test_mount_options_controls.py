"""CIS 1.1.2.x mount controls must audit the LIVE mount table, not stat.

The old wiring delegated every mount control to the observation-only
manual_observation mechanism (`stat` + a MANUAL debug report). That can never
certify a separate partition or a mount option, and the benchmark's own
`findmnt -kn <path> | grep -v <opt>` audit is a FALSE PASS when the path is
not mounted at all (the grep simply returns nothing). The mount_options
mechanism replaces it and additionally:

* derives PASS/FAIL/NOT_APPLICABLE from findmnt evidence only (unreadable
  evidence fails closed; an unmounted option-audit target is NOT_APPLICABLE,
  never a silent pass),
* audits `systemctl is-enabled <unit>.mount` for boot persistence where the
  benchmark requires it (CIS 1.1.2.1.1 /tmp) and rejects masked/disabled
  units everywhere else,
* normalises the Debian 252 vs Ubuntu 255 "not-found" divergence,
* keeps the phantom controls 1.1.2.3.4 (/home noexec) and 1.1.2.4.4
  (/var noexec) out of the tree: they exist in no benchmark and no ledger.
"""

from pathlib import Path
import re
import unittest

from jinja2 import StrictUndefined
import yaml

from test_config_line_missing_file import jinja_environment

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "roles"
COMMON = ROLES / "cis_linux_common" / "tasks"
MECHANISM = COMMON / "mechanisms" / "mount_options"
SEC = "sections/section_01_initial_setup"
PLATFORM_ROLES = ("cis_debian_12", "cis_ubuntu_2404")
LEDGER = ROOT / "cis" / "catalog" / "control-ledger.yml"
MATRIX = ROOT / "cis" / "catalog" / "disposition-matrix.yml"

# cid -> (dirname, path, unit, check, unit_required, disposition)
CONTROLS = {
    "1.1.2.1.1": ("1_1_2_1_tmp_partition", "/tmp", "tmp.mount",
                  "partition", "yes", "automated"),
    "1.1.2.1.2": ("1_1_2_1_tmp_nodev", "/tmp", "tmp.mount",
                  "nodev", "no", "automated"),
    "1.1.2.1.3": ("1_1_2_1_tmp_nosuid", "/tmp", "tmp.mount",
                  "nosuid", "no", "automated"),
    "1.1.2.1.4": ("1_1_2_1_tmp_noexec", "/tmp", "tmp.mount",
                  "noexec", "no", "automated"),
    "1.1.2.2.1": ("1_1_2_2_dev_shm_partition", "/dev/shm", "dev-shm.mount",
                  "partition", "no", "automated"),
    "1.1.2.2.2": ("1_1_2_2_dev_shm_nodev", "/dev/shm", "dev-shm.mount",
                  "nodev", "no", "automated"),
    "1.1.2.2.3": ("1_1_2_2_dev_shm_nosuid", "/dev/shm", "dev-shm.mount",
                  "nosuid", "no", "automated"),
    "1.1.2.2.4": ("1_1_2_2_dev_shm_noexec", "/dev/shm", "dev-shm.mount",
                  "noexec", "no", "automated"),
    "1.1.2.3.1": ("1_1_2_3_home_partition", "/home", "home.mount",
                  "partition", "no", "manual"),
    "1.1.2.3.2": ("1_1_2_3_home_nodev", "/home", "home.mount",
                  "nodev", "no", "manual"),
    "1.1.2.3.3": ("1_1_2_3_home_nosuid", "/home", "home.mount",
                  "nosuid", "no", "manual"),
    "1.1.2.4.1": ("1_1_2_4_var_partition", "/var", "var.mount",
                  "partition", "no", "manual"),
    "1.1.2.4.2": ("1_1_2_4_var_nodev", "/var", "var.mount",
                  "nodev", "no", "manual"),
    "1.1.2.4.3": ("1_1_2_4_var_nosuid", "/var", "var.mount",
                  "nosuid", "no", "manual"),
    "1.1.2.5.1": ("1_1_2_5_var_tmp_partition", "/var/tmp", "var-tmp.mount",
                  "partition", "no", "automated"),
    "1.1.2.5.2": ("1_1_2_5_var_tmp_nodev", "/var/tmp", "var-tmp.mount",
                  "nodev", "no", "automated"),
    "1.1.2.5.3": ("1_1_2_5_var_tmp_nosuid", "/var/tmp", "var-tmp.mount",
                  "nosuid", "no", "automated"),
    "1.1.2.5.4": ("1_1_2_5_var_tmp_noexec", "/var/tmp", "var-tmp.mount",
                  "noexec", "no", "automated"),
    "1.1.2.6.1": ("1_1_2_6_var_log_partition", "/var/log", "var-log.mount",
                  "partition", "no", "manual"),
    "1.1.2.6.2": ("1_1_2_6_var_log_nodev", "/var/log", "var-log.mount",
                  "nodev", "no", "manual"),
    "1.1.2.6.3": ("1_1_2_6_var_log_nosuid", "/var/log", "var-log.mount",
                  "nosuid", "no", "manual"),
    "1.1.2.6.4": ("1_1_2_6_var_log_noexec", "/var/log", "var-log.mount",
                  "noexec", "no", "manual"),
    "1.1.2.7.1": ("1_1_2_7_var_log_audit_partition", "/var/log/audit",
                  "var-log-audit.mount", "partition", "no", "manual"),
    "1.1.2.7.2": ("1_1_2_7_var_log_audit_nodev", "/var/log/audit",
                  "var-log-audit.mount", "nodev", "no", "manual"),
    "1.1.2.7.3": ("1_1_2_7_var_log_audit_nosuid", "/var/log/audit",
                  "var-log-audit.mount", "nosuid", "no", "manual"),
    "1.1.2.7.4": ("1_1_2_7_var_log_audit_noexec", "/var/log/audit",
                  "var-log-audit.mount", "noexec", "no", "manual"),
}
PHANTOMS = ("1_1_2_3_home_noexec", "1_1_2_4_var_noexec")
PHANTOM_IDS = ("1.1.2.3.4", "1.1.2.4.4")
FSTAB_OPTS = "defaults,rw,nosuid,nodev,noexec,relatime"
COMPLIANT_TMPFS = "rw,nosuid,nodev,noexec,relatime"


def load(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def ansible_template(source):
    # Mirror ansible-core 2.21 escape handling for plain-Jinja rendering, as
    # the kernel_module harness does. No backslashes live in this mechanism
    # today; the doubling keeps the emulation honest if they ever appear.
    return source.replace("\\", "\\\\")


def probe(stdout=""):
    return {"changed": False, "rc": 0, "stdout": stdout,
            "stdout_lines": stdout.splitlines(), "stderr": ""}


class MechanismRun:
    """Mini Ansible evaluator for inspect.yml: canned probe results in,
    rendered facts out, so the fail-closed decision table is proven."""

    def __init__(self, check="partition", path="/tmp", unit_name="tmp.mount",
                 unit_required="no", **overrides):
        self.env = jinja_environment()
        self.context = {
            "cis_linux_common_mount_check": check,
            "cis_linux_common_mount_path": path,
            "cis_linux_common_mount_unit": unit_name,
            "cis_linux_common_mount_unit_required": unit_required,
            "cis_linux_common_control_id": "test",
            "cis_linux_common_platform": "test",
            "cis_linux_common_benchmark": "test",
            # Remediation parameter, supplied by the common section delegation.
            "cis_linux_common_mount_fstab_opts": FSTAB_OPTS,
            "ansible_check_mode": False,
        }
        defaults = {
            "exists": probe("UNMOUNTED"),
            "options": probe("UNMOUNTED"),
            "unit": probe("STATE:generated"),
        }
        merged = {key: overrides.get(key, value) for key, value in defaults.items()}
        self.probes = {
            "cis_linux_common_mount_exists_probe": merged["exists"],
            "cis_linux_common_mount_options_probe": merged["options"],
            "cis_linux_common_mount_unit_probe": merged["unit"],
        }

    def run(self):
        for task in load(MECHANISM / "inspect.yml"):
            if "ansible.builtin.set_fact" in task:
                for key, template in task["ansible.builtin.set_fact"].items():
                    self.context[key] = self.env.from_string(
                        ansible_template(template)).render(**self.context).strip()
            elif "ansible.builtin.shell" in task:
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


def run_state(check="partition", path="/tmp", unit_name="tmp.mount",
              unit_required="no", exists="UNMOUNTED", options="UNMOUNTED",
              unit="STATE:generated"):
    return MechanismRun(check=check, path=path, unit_name=unit_name,
                        unit_required=unit_required, exists=probe(exists),
                        options=probe(options), unit=probe(unit)).run()[
        "cis_linux_common_mount_state"]


class PartitionClassificationTest(unittest.TestCase):
    def test_unmounted_path_fails_never_manual(self):
        # The exact FRESH-lab state: single root partition, no mount unit.
        for unit in ("PROBE_ERROR", "STATE:not-found", "", "STATE:generated"):
            with self.subTest(unit=unit):
                self.assertEqual("FAIL", run_state(unit=unit))

    def test_mounted_with_boot_unit_passes(self):
        self.assertEqual("PASS", run_state(exists="MOUNTED",
                                           options=COMPLIANT_TMPFS,
                                           unit="STATE:generated"))
        for ok in ("STATE:enabled", "STATE:static", "STATE:alias",
                   "STATE:linked", "STATE:indirect"):
            with self.subTest(unit=ok):
                self.assertEqual("PASS", run_state(exists="MOUNTED",
                                                   options=COMPLIANT_TMPFS,
                                                   unit=ok))

    def test_masked_or_disabled_unit_fails_even_when_mounted(self):
        for bad in ("STATE:masked", "STATE:disabled"):
            with self.subTest(unit=bad):
                self.assertEqual("FAIL", run_state(exists="MOUNTED",
                                                   options=COMPLIANT_TMPFS,
                                                   unit=bad))

    def test_unit_required_rejects_missing_unit_file(self):
        # /tmp control: the benchmark ALSO requires `systemctl is-enabled
        # tmp.mount` to be neither masked nor disabled; a missing or
        # unreadable unit is no proof of a boot mount.
        for unreadable in ("", "PROBE_ERROR", "STATE:not-found"):
            with self.subTest(unit=unreadable):
                self.assertEqual("FAIL", run_state(
                    exists="MOUNTED", options=COMPLIANT_TMPFS,
                    unit=unreadable, unit_required="yes"))

    def test_unit_required_accepts_generated(self):
        self.assertEqual("PASS", run_state(
            exists="MOUNTED", options=COMPLIANT_TMPFS,
            unit="STATE:generated", unit_required="yes"))

    def test_unit_not_required_keeps_benchmark_findmnt_scope(self):
        # Only CIS 1.1.2.1.1 audits the boot unit. /dev/shm is mounted by
        # pid1 without any unit file (verified on both lab nodes); the
        # benchmark's findmnt audit still passes.
        self.assertEqual("PASS", run_state(
            path="/dev/shm", unit_name="dev-shm.mount", exists="MOUNTED",
            options="rw,nosuid,nodev,inode64", unit="STATE:not-found"))
        self.assertEqual("FAIL", run_state(
            path="/dev/shm", unit_name="dev-shm.mount", exists="MOUNTED",
            options=COMPLIANT_TMPFS, unit="STATE:masked"))


class OptionClassificationTest(unittest.TestCase):
    def test_unmounted_option_audit_is_not_applicable_never_pass(self):
        # THE false-PASS killer: `findmnt -kn /tmp | grep -v nodev` prints
        # nothing for an unmounted /tmp and the literal benchmark reads as
        # compliant. The honest verdict is NOT_APPLICABLE, never PASS.
        for check in ("nodev", "nosuid", "noexec"):
            with self.subTest(check=check):
                self.assertEqual("NOT_APPLICABLE", run_state(check=check))

    def test_option_present_passes_absent_fails(self):
        for check in ("nodev", "nosuid", "noexec"):
            with self.subTest(present=check):
                self.assertEqual("PASS", run_state(check=check,
                                                   exists="MOUNTED",
                                                   options=COMPLIANT_TMPFS))
        self.assertEqual("FAIL", run_state(check="noexec", exists="MOUNTED",
                                           options="rw,nosuid,nodev,inode64"))

    def test_real_fresh_node_evidence(self):
        # Live probe from debian12/ubuntu24 FRESH: /dev/shm is a tmpfs
        # mounted rw,nosuid,nodev,inode64 - no noexec. nodev/nosuid pass,
        # noexec fails honestly.
        for check, expected in (("nodev", "PASS"), ("nosuid", "PASS"),
                                ("noexec", "FAIL")):
            with self.subTest(check=check):
                self.assertEqual(expected, run_state(check=check,
                                                     exists="MOUNTED",
                                                     options="rw,nosuid,nodev,inode64"))

    def test_stacked_mounts_need_every_row_compliant(self):
        self.assertEqual("FAIL", run_state(check="noexec", exists="MOUNTED",
                                           options=COMPLIANT_TMPFS + "\nrw,exec"))
        self.assertEqual("PASS", run_state(check="noexec", exists="MOUNTED",
                                           options="rw,noexec\nro,noexec"))

    def test_option_substring_lookalikes_do_not_pass(self):
        # 'xnodev' and 'nodev2' must not satisfy nodev: the token matcher is
        # anchored on comma boundaries, mirroring findmnt's option list.
        self.assertEqual("FAIL", run_state(check="nodev", exists="MOUNTED",
                                           options="rw,xnodev,nodev2"))


class FailClosedEvidenceTest(unittest.TestCase):
    def test_probe_errors_fail_closed_on_every_check(self):
        for check in ("partition", "nodev", "nosuid", "noexec"):
            for kind in ("exists_error", "options_error", "options_empty",
                         "mismatched_evidence"):
                with self.subTest(check=check, kind=kind):
                    exists, options = "MOUNTED", COMPLIANT_TMPFS
                    if kind == "exists_error":
                        exists = "PROBE_ERROR"
                    elif kind == "options_error":
                        options = "PROBE_ERROR"
                    elif kind == "options_empty":
                        options = ""
                    elif kind == "mismatched_evidence":
                        # findmnt says mounted, the OPTIONS read disagrees.
                        options = "UNMOUNTED"
                    self.assertEqual("FAIL", run_state(check=check,
                                                       exists=exists,
                                                       options=options))

    def test_unmounted_and_unreadable_options_still_consistent(self):
        self.assertEqual("FAIL", run_state(check="nodev", exists="UNMOUNTED",
                                           options="PROBE_ERROR"))


class AuditVerificationBehaviourTest(unittest.TestCase):
    def classification(self, run):
        run.run()
        audit = load(MECHANISM / "audit.yml")
        debug = next(t for t in audit if "ansible.builtin.debug" in t)
        return run.render(debug["ansible.builtin.debug"]["msg"]["classification"])

    def test_audit_debug_reports_the_computed_classification(self):
        for label, kwargs, expected in (
                ("fresh unmounted tmp partition", {}, "FAIL"),
                ("fresh dev/shm partition", dict(exists=probe("MOUNTED"),
                                                  options=probe(
                                                      "rw,nosuid,nodev,inode64"),
                                                  unit=probe("STATE:not-found"),
                                                  path="/dev/shm"), "PASS"),
                ("remediated tmp partition", dict(exists=probe("MOUNTED"),
                                                  options=probe(COMPLIANT_TMPFS),
                                                  unit=probe("STATE:generated"),
                                                  unit_required="yes"), "PASS"),
                ("home nodev without partition", dict(check="nodev",
                                                      path="/home"), "NOT_APPLICABLE"),
        ):
            with self.subTest(case=label):
                self.assertEqual(expected, self.classification(MechanismRun(**kwargs)))

    def assert_expression(self):
        verify = load(MECHANISM / "verification.yml")
        return next(t for t in verify if "ansible.builtin.assert" in t)[
            "ansible.builtin.assert"]["that"][0]

    def test_verification_assert_mirrors_the_classification(self):
        expression = self.assert_expression()
        self.assertEqual("cis_linux_common_mount_state != 'FAIL'", expression)
        env = jinja_environment()
        for label, kwargs, accepted in (
                ("fresh tmp partition", {}, False),
                ("fresh tmp nodev (unmounted)", dict(check="nodev"), True),
                ("compliant tmpfs partition", dict(
                    exists=probe("MOUNTED"), options=probe(COMPLIANT_TMPFS),
                    unit=probe("STATE:generated"), unit_required="yes"), True),
                ("missing noexec on dev/shm", dict(
                    check="noexec", exists=probe("MOUNTED"),
                    options=probe("rw,nosuid,nodev,inode64")), False),
                ("unreadable probes", dict(exists=probe("PROBE_ERROR")), False),
        ):
            context = MechanismRun(**kwargs).run()
            with self.subTest(case=label):
                self.assertEqual(
                    accepted,
                    bool(env.compile_expression(ansible_template(expression))(**context)))

    def test_verification_fail_msg_renders_under_strict_undefined(self):
        verify = load(MECHANISM / "verification.yml")
        assert_task = next(t for t in verify
                           if "ansible.builtin.assert" in t)["ansible.builtin.assert"]
        context = MechanismRun().run()
        env = jinja_environment(undefined=StrictUndefined)
        for field in ("fail_msg", "success_msg"):
            with self.subTest(field=field):
                env.from_string(ansible_template(assert_task[field])).render(**context)


class RemediationBehaviourTest(unittest.TestCase):
    def setUp(self):
        self.tasks = load(MECHANISM / "remediation.yml")

    def by_keyword(self, module):
        return [t for t in self.tasks if module in t]

    @property
    def mount_task(self):
        return next(t for t in self.by_keyword("ansible.builtin.command")
                    if t["ansible.builtin.command"]["cmd"].startswith("mount {{"))

    @property
    def remount_task(self):
        return next(t for t in self.by_keyword("ansible.builtin.command")
                    if t["ansible.builtin.command"]["cmd"].startswith("mount -o"))

    def test_inspect_precedes_any_mutation(self):
        first_import = self.tasks[0]["ansible.builtin.import_tasks"]
        self.assertTrue(first_import.endswith("mount_options/inspect.yml"))
        mutate = next(i for i, t in enumerate(self.tasks)
                      if "ansible.builtin.lineinfile" in t)
        self.assertLess(0, mutate)

    def test_evidence_gate_refuses_unreadable_mount_table(self):
        gate = next(t for t in self.tasks if "ansible.builtin.assert" in t)
        self.assertEqual(["cis_linux_common_mount_evidence_ok == 'yes'"],
                         gate["ansible.builtin.assert"]["that"])

    def test_fstab_line_matches_benchmark_shape(self):
        line = next(t for t in self.tasks
                    if "ansible.builtin.lineinfile" in t)["ansible.builtin.lineinfile"]
        rendered = MechanismRun().render(line["line"])
        self.assertEqual(f"tmpfs /tmp tmpfs {FSTAB_OPTS} 0 0", rendered)
        # The regexp's backslashes live OUTSIDE the Jinja expression, so they
        # pass through the template untouched; substitute the delegated path.
        regexp = line["regexp"].replace("{{ cis_linux_common_mount_path }}", "/tmp")
        self.assertEqual(r"^[^#\s]+\s+/tmp\s+", regexp)
        self.assertTrue(re.match(regexp, f"tmpfs /tmp tmpfs {FSTAB_OPTS} 0 0"))
        self.assertFalse(re.match(regexp, f"tmpfs /var/tmp tmpfs {FSTAB_OPTS} 0 0"))
        self.assertTrue(re.match(regexp, "/dev/sdb1 /tmp ext4 defaults 0 0"))
        self.assertFalse(re.match(regexp, "# tmpfs /tmp tmpfs x 0 0"))

    def test_mount_actions_skip_when_compliant(self):
        run = MechanismRun(exists=probe("MOUNTED"), options=probe(COMPLIANT_TMPFS),
                           unit=probe("STATE:generated"))
        run.run()
        self.assertFalse(run.holds(self.mount_task))
        self.assertFalse(run.holds(self.remount_task))

    def test_mount_actions_skip_in_check_mode(self):
        run = MechanismRun()  # fresh /tmp: FAIL, unmounted
        run.run()
        run.context["ansible_check_mode"] = True
        self.assertFalse(run.holds(self.mount_task))
        self.assertFalse(run.holds(self.remount_task))

    def test_unmounted_fresh_target_mounts_after_fstab_and_reload(self):
        run = MechanismRun()
        run.run()
        self.assertTrue(run.holds(self.mount_task))
        self.assertFalse(run.holds(self.remount_task))
        # The payload of a module that mounts over /tmp must not live under
        # /tmp itself: the lab proved the mount succeeds and then the module
        # dies serializing its result (ansiballz unpacks under TMPDIR).
        for task in (self.mount_task, self.remount_task):
            self.assertEqual({"TMPDIR": "/run"}, task["environment"])
        fstab = next(i for i, t in enumerate(self.tasks)
                     if "ansible.builtin.lineinfile" in t)
        reload_ = next(i for i, t in enumerate(self.tasks)
                       if isinstance(t.get("ansible.builtin.systemd"), dict)
                       and t["ansible.builtin.systemd"].get("daemon_reload"))
        self.assertLess(fstab, reload_)
        self.assertLess(reload_, self.tasks.index(self.mount_task))

    def test_dev_shm_option_drift_uses_remount_not_plain_mount(self):
        run = MechanismRun(check="noexec", exists=probe("MOUNTED"),
                           options=probe("rw,nosuid,nodev,inode64"))
        run.run()
        self.assertFalse(run.holds(self.mount_task))
        self.assertTrue(run.holds(self.remount_task))

    def test_final_certification_re_reads_and_demands_pass(self):
        certify = [t for t in self.tasks if "ansible.builtin.assert" in t][-1]
        self.assertEqual(["cis_linux_common_mount_state == 'PASS'"],
                         certify["ansible.builtin.assert"]["that"])
        self.assertIn("not ansible_check_mode", certify["when"])
        reinspect = [t for t in self.tasks
                     if str(t.get("ansible.builtin.import_tasks", ""))
                     .endswith("mount_options/inspect.yml")]
        self.assertEqual(2, len(reinspect))
        self.assertLess(self.tasks.index(reinspect[-1]),
                        self.tasks.index(certify))

    def test_unmask_only_when_masked_outside_check_mode(self):
        unmask = next(t for t in self.tasks
                      if isinstance(t.get("ansible.builtin.systemd"), dict)
                      and t["ansible.builtin.systemd"].get("masked") is False)
        self.assertIn("cis_linux_common_mount_unit_state == 'masked'", unmask["when"])
        self.assertIn("not ansible_check_mode", unmask["when"])
        masked = MechanismRun(exists=probe("MOUNTED"), options=probe(COMPLIANT_TMPFS),
                              unit=probe("STATE:masked"))
        masked.run()
        self.assertTrue(masked.holds(unmask))
        ok = MechanismRun(exists=probe("MOUNTED"), options=probe(COMPLIANT_TMPFS))
        ok.run()
        self.assertFalse(ok.holds(unmask))


class RoutingStructureTest(unittest.TestCase):
    def test_phantom_controls_are_gone_everywhere(self):
        for role in PLATFORM_ROLES + ("cis_linux_common",):
            for dirname in PHANTOMS:
                self.assertFalse((ROLES / role / "tasks" / SEC / dirname).exists(),
                                 f"{role} still ships {dirname}")
        for role in PLATFORM_ROLES:
            text = (ROLES / role / "defaults/main.yml").read_text(encoding="utf-8")
            for dirname in PHANTOMS:
                self.assertNotIn(dirname, text)
            routing = (ROLES / role / "tasks/main.yml").read_text(encoding="utf-8")
            for dirname in PHANTOMS:
                self.assertNotIn(dirname, routing)
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            for pid in PHANTOM_IDS:
                self.assertNotIn(f'"control":"{pid}"', line)

    def test_common_delegation_carries_the_mount_specification(self):
        for cid, (dirname, path, unit, check, req, _disp) in CONTROLS.items():
            for phase in ("audit", "verification", "remediation"):
                path_file = COMMON / SEC / dirname / f"{phase}.yml"
                if not path_file.exists():
                    continue
                tasks = load(path_file)
                imported = next(t for t in tasks
                                if str(t.get("ansible.builtin.import_tasks", ""))
                                .endswith(f"mount_options/{phase}.yml"))
                vars_ = imported["vars"]
                with self.subTest(cid=cid, phase=phase):
                    self.assertEqual(path, vars_["cis_linux_common_mount_path"])
                    self.assertEqual(unit, vars_["cis_linux_common_mount_unit"])
                    self.assertEqual(check, vars_["cis_linux_common_mount_check"])
                    self.assertEqual(req,
                                     vars_["cis_linux_common_mount_unit_required"])
                    if phase == "remediation":
                        self.assertEqual(FSTAB_OPTS,
                                         vars_["cis_linux_common_mount_fstab_opts"])

    def test_no_control_delegates_to_manual_observation_anymore(self):
        for _cid, (dirname, *_rest) in CONTROLS.items():
            for phase in ("audit", "verification", "remediation"):
                path = COMMON / SEC / dirname / f"{phase}.yml"
                if not path.exists():
                    continue
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("manual_observation", text, dirname)

    def test_automated_controls_ship_remediation_and_manual_do_not(self):
        for cid, (dirname, _p, _u, _c, _r, disp) in CONTROLS.items():
            for role in ("cis_linux_common",) + PLATFORM_ROLES:
                exists = (ROLES / role / "tasks" / SEC / dirname
                          / "remediation.yml").exists()
                with self.subTest(cid=cid, role=role):
                    self.assertEqual(disp == "automated", exists)

    def test_wrappers_carry_identity_vars_only(self):
        for role in PLATFORM_ROLES:
            platform = "debian_12" if "debian" in role else "ubuntu_2404"
            for cid, (dirname, *_rest) in CONTROLS.items():
                for phase in ("audit", "verification", "remediation"):
                    path = ROLES / role / "tasks" / SEC / dirname / f"{phase}.yml"
                    if not path.exists():
                        continue
                    tasks = load(path)
                    vars_ = tasks[0]["vars"]
                    with self.subTest(role=role, cid=cid, phase=phase):
                        self.assertEqual(cid, vars_["cis_linux_common_control_id"])
                        self.assertEqual(platform, vars_["cis_linux_common_platform"])
                        self.assertNotIn("cis_linux_common_manual_path", vars_)


BLOCK_RE = re.compile(
    r"- name: (?:Audit|Verify|Remediate) [^\n]* CIS [\d.]+(?: \(manual\))?\n"
    r"  ansible\.builtin\.import_tasks: sections/section_01_initial_setup/"
    r"([^\s/]+)/([a-z]+)\.yml\n"
    r"(?:  [^\n]*\n)*")


class MainRoutingTest(unittest.TestCase):
    def route_blocks(self, role):
        text = (ROLES / role / "tasks/main.yml").read_text(encoding="utf-8")
        found = {}
        for match in BLOCK_RE.finditer(text):
            dirname, phase = match.groups()
            found.setdefault((dirname, phase), []).append(match.group(0))
        return text, found

    def test_every_mount_block_is_rewired(self):
        for role in PLATFORM_ROLES:
            text, found = self.route_blocks(role)
            for cid, (dirname, _p, _u, _c, _r, _disp) in CONTROLS.items():
                for phase in ("audit", "verification"):
                    with self.subTest(role=role, cid=cid, phase=phase):
                        blocks = found.get((dirname, phase), [])
                        self.assertEqual(1, len(blocks))
                        self.assertIn("mount_options", blocks[0])
                        self.assertNotIn("manual_observation", blocks[0])
                        self.assertNotIn(", na]", blocks[0])

    def test_remediation_routes_exist_only_for_automated_and_are_gated(self):
        for role in PLATFORM_ROLES:
            _text, found = self.route_blocks(role)
            for cid, (dirname, _p, _u, _c, _r, disp) in CONTROLS.items():
                blocks = found.get((dirname, "remediation"), [])
                with self.subTest(role=role, cid=cid):
                    self.assertEqual(disp == "automated", len(blocks) == 1)
                    if not blocks:
                        continue
                    route = blocks[0]
                    self.assertIn(f"{role}_remediation_enabled | bool", route)
                    self.assertIn(f"{role}_{dirname} | bool", route)
                    self.assertIn(f"{role}_{dirname}_remediate | bool", route)
                    if role == "cis_debian_12":
                        self.assertIn("cis_debian_12_canary_confirmed | bool", route)
                    else:
                        self.assertNotIn("canary", route)

    def test_ledger_rules_route_mount_controls_to_the_new_mechanism(self):
        text = (ROOT / "scripts" / "generate_ledger.py").read_text(encoding="utf-8")
        self.assertIn('("1.1.2.", "mount_options")', text)
        self.assertNotIn('("1.1.2.", "manual_observation")', text)


class DefaultsTest(unittest.TestCase):
    def test_control_flags_on_opt_ins_off(self):
        for role in PLATFORM_ROLES:
            defaults = load(ROLES / role / "defaults/main.yml")
            for cid, (dirname, _p, _u, _c, _r, disp) in CONTROLS.items():
                var = f"{role}_{dirname}"
                with self.subTest(role=role, var=var):
                    self.assertIs(True, defaults[var])
                    opt_in = f"{var}_remediate"
                    if disp == "automated":
                        self.assertIs(False, defaults[opt_in])
                    else:
                        self.assertNotIn(opt_in, defaults)
            for dirname in PHANTOMS:
                self.assertNotIn(f"{role}_{dirname}", defaults)


class LedgerRouteTest(unittest.TestCase):
    def rows(self):
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if '"control":"1.1.2.' in line:
                yield line

    def test_backend_and_modes_match_the_disposition(self):
        import json
        seen = {}
        count = 0
        for line in self.rows():
            row = json.loads(line.rstrip(","))
            count += 1
            self.assertEqual("cis_linux_common.mount_options",
                             row["route"]["backend"], row["control"])
            self.assertEqual(CONTROLS[row["control"]][5], row["disposition"],
                             row["control"])
            seen.setdefault((row["platform"], row["control"]), set()).add(
                row["route"]["mode"])
        self.assertEqual(26 * 2, len(seen))
        self.assertEqual(12 * 3 * 2 + 14 * 2 * 2, count)
        for (platform, cid), modes in seen.items():
            disp = CONTROLS[cid][5]
            with self.subTest(platform=platform, cid=cid):
                if disp == "automated":
                    self.assertEqual({"audit", "remediation", "verification"}, modes)
                else:
                    self.assertEqual({"audit", "verification"}, modes)

    def test_matrix_dispositions_moved_from_na(self):
        matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
        for corpus in matrix["corpora"]:
            for item in corpus["dispositions"]:
                if item["control"].startswith("1.1.2."):
                    with self.subTest(platform=corpus["platform"],
                                      cid=item["control"]):
                        self.assertEqual(
                            CONTROLS[item["control"]][5], item["disposition"])


if __name__ == "__main__":
    unittest.main()
