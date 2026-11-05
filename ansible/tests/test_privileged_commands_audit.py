"""CIS 6.2.3.6 must be an automated privileged-commands audit control.

The benchmark (CIS Debian 12 v1.1.0 / CIS Ubuntu 24.04 v1.0.0, 6.2.3.6)
enumerates, per traversable partition, the files with the setuid/setgid bits
(`find <part> -xdev -perm /6000 -type f`) and requires one audit rule per file
written to /etc/audit/rules.d/50-privileged.rules:

  -a always,exit -F path=<file> -F perm=x -F auid>=<UID_MIN> -F auid!=unset -k privileged

followed by `augenrules --load`. The old stub only ran manual_observation on
/etc/audit/rules.d/audit.rules: it could never PASS or FAIL the control. These
tests prove the dedicated cis_linux_common.privileged_commands_audit mechanism
mirrors the benchmark (partition enumeration, canonical rule lines, UID_MIN
from /etc/login.defs), fails closed on unreadable state, removes stale rules,
keeps remediation opt-in (default false), and refuses to run `augenrules
--load` while the audit configuration is immutable (-e 2) — reporting the
reboot requirement instead of crashing, per the benchmark's "Potential reboot
required" note.
"""

from pathlib import Path
import ast
import json
import re
import unittest

import yaml

from test_config_line_missing_file import jinja_environment

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "roles/cis_linux_common/tasks"
DEBIAN = ROOT / "roles/cis_debian_12/tasks"
UBUNTU = ROOT / "roles/cis_ubuntu_2404/tasks"
MECHANISM = COMMON / "mechanisms/privileged_commands_audit"
CONTROL_DIR = "sections/section_06_logging/6_2_3_6_privileged_commands"
LEDGER = ROOT / "cis/catalog/control-ledger.yml"
MATRIX = ROOT / "cis/catalog/disposition-matrix.yml"
GENERATOR = ROOT / "scripts/generate_ledger.py"
PHASES = ("audit.yml", "remediation.yml", "verification.yml")

RULES_PATH = "/etc/audit/rules.d/50-privileged.rules"

CANONICAL_RULE = ("-a always,exit -F path={file} -F perm=x "
                  "-F auid>={uid_min} -F auid!=unset -k privileged")


def load(path):
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def wrapper_vars(path):
    collected = {}
    for task in load(path):
        if isinstance(task.get("ansible.builtin.import_role"), dict):
            collected.update(task.get("vars") or {})
    return collected


def probe_task():
    tasks = load(MECHANISM / "discover.yml")
    return next(t for t in tasks if "ansible.builtin.shell" in t)


def probe_script():
    return probe_task()["ansible.builtin.shell"]["cmd"]


def tasks_by_module(path, module):
    return [t for t in load(path) if isinstance(t.get(module), dict)]


class MechanismStructureTest(unittest.TestCase):
    def test_mechanism_has_the_three_phases_plus_discovery(self):
        for name in ("discover.yml", "audit.yml", "remediation.yml", "verification.yml"):
            with self.subTest(name=name):
                self.assertTrue((MECHANISM / name).is_file())

    def test_control_phases_delegate_to_the_mechanism(self):
        for phase in PHASES:
            imported = [task.get("ansible.builtin.import_tasks")
                        for task in load(COMMON / CONTROL_DIR / phase)
                        if isinstance(task.get("ansible.builtin.import_tasks"), str)]
            with self.subTest(phase=phase):
                self.assertTrue(any(p.endswith(f"privileged_commands_audit/{phase}")
                                    for p in imported), f"{phase}: {imported}")

    def test_manual_stub_is_gone(self):
        for base in (COMMON, DEBIAN, UBUNTU):
            for phase in PHASES:
                text = (base / CONTROL_DIR / phase).read_text(encoding="utf-8")
                with self.subTest(role=base.parts[-2], phase=phase):
                    self.assertNotIn("manual_observation", text)
                    self.assertNotIn("manual_path", text)


class WrapperContractTest(unittest.TestCase):
    def test_wrappers_carry_the_benchmark_mechanism_vars(self):
        for base, platform, benchmark in (
                (DEBIAN, "debian_12", "CIS Debian Linux 12 Benchmark v1.1.0"),
                (UBUNTU, "ubuntu_2404", "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0")):
            for phase in PHASES:
                path = base / CONTROL_DIR / phase
                tasks = load(path)
                vars_ = wrapper_vars(path)
                with self.subTest(role=base.parts[-2], phase=phase):
                    self.assertEqual("6.2.3.6", vars_["cis_linux_common_control_id"])
                    self.assertEqual(platform, vars_["cis_linux_common_platform"])
                    self.assertEqual(benchmark, vars_["cis_linux_common_benchmark"])
                    self.assertEqual("auditd", vars_["cis_linux_common_privileged_package"])
                    self.assertEqual(RULES_PATH,
                                     vars_["cis_linux_common_privileged_rules_path"])
                    self.assertEqual("privileged", vars_["cis_linux_common_privileged_key"])
                    role_call = tasks[0]["ansible.builtin.import_role"]
                    self.assertEqual("cis_linux_common", role_call["name"])
                    self.assertEqual(f"{CONTROL_DIR}/{phase}", role_call["tasks_from"])


class BenchmarkFidelityTest(unittest.TestCase):
    """The discovery probe must mirror the benchmark scripts."""

    def test_partition_enumeration_is_the_benchmark_findmnt_pipeline(self):
        script = probe_script()
        self.assertIn("findmnt -n -l -k -it", script)
        self.assertIn("awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,",
                      script)
        self.assertIn('grep -Pv "noexec|nosuid${l_exclude}"', script)

    def test_setuid_setgid_scan_matches_the_benchmark_find(self):
        script = probe_script()
        self.assertIn('-xdev -perm /6000 -type f', script)

    def test_uid_min_comes_from_login_defs(self):
        script = probe_script()
        self.assertIn(r"awk '/^\s*UID_MIN/{print $2}' /etc/login.defs", script)

    def test_canonical_rule_line_format(self):
        script = probe_script()
        self.assertIn("-a always,exit -F path=%s -F perm=x -F auid>=%s "
                      "-F auid!=unset -k %s", script)
        # The generated set is sorted/deduplicated (benchmark printf | sort -u).
        self.assertIn('sort -u', script)

    def test_rule_echo_only_when_requested_by_remediation(self):
        script = probe_script()
        self.assertIn('if [ "$l_emit" = "1" ] && [ -n "$l_rules" ]; then', script)

    def test_probe_never_loads_rules(self):
        # augenrules belongs to remediation only; the shared discovery probe
        # and the audit/verification phases must never mutate the running
        # configuration (the header comment may mention the load step, the
        # executed code may not).
        self.assertNotIn("augenrules", probe_script())
        for name in ("audit.yml", "verification.yml"):
            text = (MECHANISM / name).read_text(encoding="utf-8")
            with self.subTest(name=name):
                self.assertNotIn("augenrules", text)

    def test_immutable_reboot_carveout_follows_the_benchmark(self):
        script = probe_script()
        self.assertIn("auditctl -s", script)
        self.assertIn("enabled 2", script)
        # With -e 2 locked, a running mismatch is reported, not failed; the
        # on-disk rules remain the gate.
        self.assertIn('CHECK pass running immutable', script)
        self.assertIn('CHECK fail running missing=', script)

    def test_stale_and_missing_set_comparisons_use_comm(self):
        script = probe_script()
        self.assertIn('comm -23 <(printf \'%s\\n\' "$l_gen_sorted")', script)
        self.assertIn('comm -13 <(printf \'%s\\n\' "$l_gen_sorted")', script)


class SetFactResolutionTest(unittest.TestCase):
    """Ansible resolves the keys of one set_fact in ALPHABETICAL order, not in
    file order: a key that references a sibling key defined later
    alphabetically explodes at runtime ('X is undefined') even though the
    YAML looks sequential. The evaluator loop iterates file order, so this
    class of failure is only provable statically."""

    def test_no_fact_references_a_sibling_defined_later_alphabetically(self):
        for name in ("discover.yml", "audit.yml", "remediation.yml", "verification.yml"):
            for task in load(MECHANISM / name):
                facts = task.get("ansible.builtin.set_fact") or {}
                names = set(facts)
                for key, template in facts.items():
                    refs = set(re.findall(r"cis_linux_common_privileged_\w+",
                                          str(template)))
                    for ref in refs:
                        if ref in names and ref > key:
                            with self.subTest(task=name, key=key, ref=ref):
                                self.fail(
                                    f"{name}: '{key}' resolves before "
                                    f"'{ref}' (alphabetical order) but "
                                    "references it")

    def test_readable_is_established_before_probe_ok_consume_it(self):
        tasks = load(MECHANISM / "discover.yml")
        index = {}
        same_task = {}
        for i, task in enumerate(tasks):
            facts = task.get("ansible.builtin.set_fact") or {}
            for key in facts:
                index[key] = i
                same_task[key] = facts
        self.assertLess(index["cis_linux_common_privileged_readable"],
                        index["cis_linux_common_privileged_probe_ok"])
        self.assertNotIn("cis_linux_common_privileged_readable",
                         same_task["cis_linux_common_privileged_probe_ok"])


class ClassificationEvaluatorTest(unittest.TestCase):
    """Mini-evaluator for discover.yml: canned probe output in, facts out, so
    PASS / FAIL / NOT_APPLICABLE and the fail-closed behaviour are proven
    (mirrors test_cis_section17_gdm.MechanismClassificationTest)."""

    def eval_discover(self, probe, packages=("auditd",)):
        env = jinja_environment()
        env.tests.setdefault(
            "match", lambda value, pattern: re.match(pattern, value or "") is not None)
        env.filters.setdefault(
            "regex_replace",
            lambda value, pattern, replacement: re.sub(pattern, replacement, value))
        context = {
            "cis_linux_common_control_id": "6.2.3.6",
            "cis_linux_common_platform": "test",
            "cis_linux_common_privileged_package": "auditd",
            "cis_linux_common_privileged_rules_path": RULES_PATH,
            "cis_linux_common_privileged_key": "privileged",
            "ansible_facts": {"packages": {name: [{}] for name in packages}},
            "cis_linux_common_privileged_probe": probe,
        }
        for task in load(MECHANISM / "discover.yml"):
            if "ansible.builtin.package_facts" in task or "ansible.builtin.shell" in task:
                continue
            for key, template in task.get("ansible.builtin.set_fact", {}).items():
                rendered = env.from_string(template).render(**context).strip()
                if key == "cis_linux_common_privileged_generated":
                    context[key] = ast.literal_eval(rendered)
                else:
                    context[key] = rendered
        return context

    def canned(self, lines, rc=0):
        return {"changed": False, "rc": rc, "stdout": "\n".join(lines),
                "stdout_lines": list(lines)}

    COMPLIANT_MUTABLE = [
        "CHECK pass uid_min 1000",
        "CHECK pass partitions 2 traversable filesystems",
        "CHECK pass scan 2 privileged files",
        f"CHECK pass on_disk 2 rules match {RULES_PATH}",
        "STATE enabled 1",
        "COUNT missing_running 0",
        "CHECK pass running all 2 privileged paths loaded",
        "SUMMARY generated=2 disk_missing=0 disk_stale=0 running_missing=0 immutable=no",
    ]

    def test_compliant_mutable_host_passes(self):
        facts = self.eval_discover(self.canned(self.COMPLIANT_MUTABLE))
        self.assertEqual("PASS", facts["cis_linux_common_privileged_state"])
        self.assertEqual("yes", facts["cis_linux_common_privileged_readable"])
        self.assertEqual("no", facts["cis_linux_common_privileged_immutable"])
        self.assertEqual(0, int(facts["cis_linux_common_privileged_missing_running"]))

    def test_disk_missing_rules_fail(self):
        lines = [
            "CHECK pass uid_min 1000",
            "CHECK pass partitions 1 traversable filesystems",
            "CHECK pass scan 2 privileged files",
            "RULE -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            "RULE -a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            "EVIDENCE missing -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            "CHECK fail on_disk missing=1 stale=0",
            "STATE enabled 1",
            "COUNT missing_running 1",
            "CHECK fail running missing=1",
            "SUMMARY generated=2 disk_missing=1 disk_stale=0 running_missing=1 immutable=no",
        ]
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])
        # Still readable: remediation is allowed to write the fix.
        self.assertEqual("yes", facts["cis_linux_common_privileged_readable"])
        self.assertEqual(2, len(facts["cis_linux_common_privileged_generated"]))
        self.assertEqual(CANONICAL_RULE.format(file="/usr/bin/sudo", uid_min="1000"),
                         facts["cis_linux_common_privileged_generated"][0])

    def test_stale_rule_fails_and_generated_set_still_drives_remediation(self):
        lines = [
            "CHECK pass uid_min 1000",
            "CHECK pass partitions 1 traversable filesystems",
            "CHECK pass scan 1 privileged files",
            "RULE -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            "EVIDENCE stale -a always,exit -F path=/usr/bin/gone -F perm=x -F auid>=1000 -F auid!=unset -k privileged",
            "CHECK fail on_disk missing=0 stale=1",
            "STATE enabled 1",
            "COUNT missing_running 0",
            "CHECK pass running all 1 privileged paths loaded",
            "SUMMARY generated=1 disk_missing=0 disk_stale=1 running_missing=0 immutable=no",
        ]
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])
        self.assertEqual("yes", facts["cis_linux_common_privileged_readable"])

    def test_running_missing_with_mutable_runtime_fails(self):
        lines = list(self.COMPLIANT_MUTABLE)
        lines[5] = "COUNT missing_running 1"
        lines[6] = "EVIDENCE running-missing /usr/bin/sudo"
        lines.insert(6, "CHECK fail running missing=1")
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])

    def test_immutable_lock_reports_and_passes_on_disk_state(self):
        lines = [
            "CHECK pass uid_min 1000",
            "CHECK pass partitions 2 traversable filesystems",
            "CHECK pass scan 250 privileged files",
            f"CHECK pass on_disk 250 rules match {RULES_PATH}",
            "STATE enabled 2",
            "COUNT missing_running 3",
            "CHECK pass running immutable (locked by -e 2: 3 rules pending reboot)",
            "SUMMARY generated=250 disk_missing=0 disk_stale=0 running_missing=3 immutable=yes",
        ]
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("PASS", facts["cis_linux_common_privileged_state"])
        self.assertEqual("yes", facts["cis_linux_common_privileged_immutable"])
        self.assertEqual(3, int(facts["cis_linux_common_privileged_missing_running"]))

    def test_unreadable_uid_min_fails_closed(self):
        lines = ["CHECK unreadable uid_min (/etc/login.defs unreadable or UID_MIN not found)",
                 "SUMMARY generated=0 unreadable=1"]
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])
        # Remediation must refuse to write in this state.
        self.assertEqual("no", facts["cis_linux_common_privileged_readable"])

    def test_unreadable_running_state_fails_closed(self):
        lines = [
            "CHECK pass uid_min 1000",
            "CHECK pass partitions 1 traversable filesystems",
            "CHECK pass scan 2 privileged files",
            f"CHECK pass on_disk 2 rules match {RULES_PATH}",
            "CHECK unreadable running (auditctl -l failed; is auditd running?)",
            "SUMMARY generated=2 disk_missing=0 disk_stale=0",
        ]
        facts = self.eval_discover(self.canned(lines))
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])
        self.assertEqual("no", facts["cis_linux_common_privileged_readable"])

    def test_probe_command_failure_fails_closed(self):
        facts = self.eval_discover({"failed": True, "rc": 2, "stdout": "", "stdout_lines": []})
        self.assertEqual("FAIL", facts["cis_linux_common_privileged_state"])
        self.assertEqual("no", facts["cis_linux_common_privileged_readable"])

    def test_absent_auditd_is_not_applicable(self):
        facts = self.eval_discover({"changed": False, "skipped": True}, packages=())
        self.assertEqual("NOT_APPLICABLE", facts["cis_linux_common_privileged_state"])
        self.assertEqual([], facts["cis_linux_common_privileged_generated"])

    def test_probe_runs_with_become_check_mode_and_suppressed_failures(self):
        task = probe_task()
        self.assertIs(True, task["become"])
        self.assertIs(False, task["check_mode"])
        self.assertIs(False, task["failed_when"])
        self.assertIs(False, task["changed_when"])
        self.assertEqual("/bin/bash", task["ansible.builtin.shell"]["executable"])
        joined = " ".join(task["when"] if isinstance(task["when"], list) else [task["when"]])
        self.assertIn("cis_linux_common_privileged_required == 'yes'", joined)


class RemediationGuardTest(unittest.TestCase):
    def test_fail_closed_assert_precedes_the_rules_file_write(self):
        tasks = load(MECHANISM / "remediation.yml")
        assert_indexes = [i for i, t in enumerate(tasks) if "ansible.builtin.assert" in t]
        copy = tasks_by_module(MECHANISM / "remediation.yml", "ansible.builtin.copy")[0]
        copy_index = tasks.index(copy)
        self.assertTrue(assert_indexes)
        self.assertTrue(all(i < copy_index for i in assert_indexes))
        assert_task = tasks[assert_indexes[0]]
        self.assertIn("cis_linux_common_privileged_required == 'no' or "
                      "cis_linux_common_privileged_readable == 'yes'",
                      " ".join(assert_task["ansible.builtin.assert"]["that"]))

    def test_discovery_is_imported_with_rule_emission_enabled(self):
        tasks = load(MECHANISM / "remediation.yml")
        imports = [t for t in tasks
                   if str(t.get("ansible.builtin.import_tasks", "")).endswith("discover.yml")]
        self.assertEqual(1, len(imports))
        self.assertEqual({"cis_linux_common_privileged_emit_rules": "1"}, imports[0]["vars"])

    def test_rules_file_write_is_idempotent_owned_and_exact(self):
        tasks = load(MECHANISM / "remediation.yml")
        copy = tasks_by_module(MECHANISM / "remediation.yml", "ansible.builtin.copy")[0]
        args = copy["ansible.builtin.copy"]
        self.assertEqual("{{ cis_linux_common_privileged_rules_path }}", args["dest"])
        self.assertEqual("root", args["owner"])
        self.assertEqual("root", args["group"])
        self.assertEqual("0640", args["mode"])
        content = args["content"]
        # Exact generated set (no merge-with-old): a Jinja loop over the
        # normalized rule lines, with a managed-by header comment.
        self.assertIn("{% for rule in cis_linux_common_privileged_generated %}", content)
        self.assertIn("{{ rule }}", content)
        self.assertTrue(content.splitlines()[0].lstrip().startswith("# CIS"))
        self.assertEqual("cis_linux_common_privileged_required == 'yes'", str(copy["when"]))
        self.assertIs(True, copy["become"])

    def test_augenrules_load_is_guarded(self):
        tasks = load(MECHANISM / "remediation.yml")
        commands = [t for t in tasks if "ansible.builtin.command" in t]
        self.assertEqual(1, len(commands))
        load_task = commands[0]
        self.assertEqual("augenrules --load", load_task["ansible.builtin.command"]["cmd"])
        conditions = " ".join(load_task["when"])
        self.assertIn("not ansible_check_mode", conditions)
        # -e 2 immutable: the load is skipped, not attempted-then-masked.
        self.assertIn("cis_linux_common_privileged_immutable == 'no'", conditions)
        # Only when something actually needs converging.
        self.assertIn("cis_linux_common_privileged_file.changed | default(false)", conditions)
        self.assertIn("cis_linux_common_privileged_missing_running | int > 0", conditions)
        self.assertNotIn("failed_when", load_task)  # a real failure must surface
        self.assertIs(True, load_task["changed_when"])

    def test_report_task_announces_the_reboot_requirement(self):
        text = (MECHANISM / "remediation.yml").read_text(encoding="utf-8")
        self.assertIn("reboot is", text)
        self.assertIn("-e 2", text)
        # Skipped tasks register skipped:true; executed results lack the key.
        self.assertIn("cis_linux_common_privileged_load.skipped | default(false)", text)


class VerificationTest(unittest.TestCase):
    def test_verification_asserts_non_fail_state(self):
        tasks = load(MECHANISM / "verification.yml")
        assert_task = tasks_by_module(MECHANISM / "verification.yml",
                                      "ansible.builtin.assert")[0]
        self.assertEqual(["cis_linux_common_privileged_state != 'FAIL'"],
                         assert_task["ansible.builtin.assert"]["that"])

    def test_fail_msg_carries_evidence(self):
        text = (MECHANISM / "verification.yml").read_text(encoding="utf-8")
        self.assertIn("cis_linux_common_privileged_evidence[:25]", text)


class RoutingGateTest(unittest.TestCase):
    def routes(self, role):
        for task in load(ROOT / f"roles/{role}/tasks/main.yml"):
            source = task.get("ansible.builtin.import_tasks")
            if isinstance(source, str) and "6_2_3_6_privileged_commands" in source:
                yield source.rsplit("/", 1)[1].removesuffix(".yml"), task

    def test_every_mode_has_exactly_one_route(self):
        for role in ("cis_debian_12", "cis_ubuntu_2404"):
            modes = dict(self.routes(role))
            with self.subTest(role=role):
                self.assertEqual({"audit", "remediation", "verification"}, set(modes))
                for _mode, task in modes.items():
                    self.assertIn("cis_6_2_3_6", task["tags"])
                    self.assertNotIn("manual", task["tags"])

    def test_remediation_is_default_false_and_opt_in(self):
        for role, prefix in (("cis_debian_12", "cis_debian_12"),
                             ("cis_ubuntu_2404", "cis_ubuntu_2404")):
            defaults = load(ROOT / f"roles/{role}/defaults/main.yml")
            control = f"{prefix}_6_2_3_6_privileged_commands"
            modes = dict(self.routes(role))
            with self.subTest(role=role):
                self.assertIs(True, defaults[control])
                self.assertIs(False, defaults[control + "_remediate"])
                joined = " ".join(modes["remediation"]["when"])
                self.assertIn(f"{control} | bool", joined)
                self.assertIn(f"{control}_remediate | bool", joined)
                self.assertIn(f"{prefix}_remediation_enabled | bool", joined)
                audit_joined = " ".join(modes["audit"]["when"])
                self.assertIn(f"{prefix}_execution_mode == 'audit'", audit_joined)

    def test_6_2_3_6_is_dispatched_before_the_immutable_control(self):
        # The privileged set must converge before 6.2.3.20 locks -e 2.
        for role in ("cis_debian_12", "cis_ubuntu_2404"):
            indexes = {}
            for i, task in enumerate(load(ROOT / f"roles/{role}/tasks/main.yml")):
                source = task.get("ansible.builtin.import_tasks")
                if not isinstance(source, str):
                    continue
                if "6_2_3_6_privileged_commands/remediation.yml" in source:
                    indexes["privileged"] = i
                if "6_2_3_20_audit_immutable/remediation.yml" in source:
                    indexes["immutable"] = i
            with self.subTest(role=role):
                self.assertLess(indexes["privileged"], indexes["immutable"])


class CatalogLedgerTest(unittest.TestCase):
    def routes_for(self, platform, control):
        for line in LEDGER.read_text(encoding="utf-8").splitlines():
            if f'"platform":"{platform}"' in line and f'"control":"{control}"' in line:
                yield json.loads(line.strip().rstrip(","))

    def test_ledger_routes_6_2_3_6_to_the_new_mechanism(self):
        for platform in ("debian-12", "ubuntu-24.04"):
            seen = list(self.routes_for(platform, "6.2.3.6"))
            with self.subTest(platform=platform):
                self.assertEqual(3, len(seen))
                self.assertEqual({"audit", "remediation", "verification"},
                                 {route["route"]["mode"] for route in seen})
                for route in seen:
                    self.assertEqual("cis_linux_common.privileged_commands_audit",
                                     route["route"]["backend"])
                    self.assertEqual("automated", route["disposition"])

    def test_disposition_matrix_marks_it_automated(self):
        matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        for corpus in matrix["corpora"]:
            for item in corpus["dispositions"]:
                if item["control"] == "6.2.3.6":
                    with self.subTest(platform=corpus["platform"]):
                        self.assertEqual("automated", item["disposition"])

    def test_generator_mechanism_rule_updated(self):
        text = GENERATOR.read_text(encoding="utf-8")
        self.assertIn('("6.2.3.6", "privileged_commands_audit")', text)
        self.assertNotIn('("6.2.3.6", "manual_observation")', text)


if __name__ == "__main__":
    unittest.main()
