"""Guard the shared fixed-file set semantics: full-set discovery, strict
not-more-permissive mode comparison, fail-closed behavior, and remediation
that touches only non-compliant files and only their failing dimensions."""

from pathlib import Path
import json
import unittest

from jinja2 import Environment
import yaml


MECH = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
        "mechanisms/fixed_file_permissions")


def _to_json(value):
    return json.dumps(value)


def load_tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def template_for(tasks_path, fact_name):
    for task in load_tasks(tasks_path):
        fact = task.get("ansible.builtin.set_fact") or {}
        if fact_name in fact:
            value = fact[fact_name]
            if isinstance(value, str) and value.lstrip().startswith("{%-"):
                return value
    raise AssertionError(f"no block template producing {fact_name} in {tasks_path}")


class StubEnvironmentMixin:
    env_kwargs = {}

    def setUp(self):
        env = Environment(**self.env_kwargs)
        env.filters["to_json"] = _to_json
        self.env = env

    def render(self, template, **context):
        return json.loads(self.env.from_string(template).render(**context))


PLAN = template_for(MECH / "discover.yml",
                    "cis_linux_common_fixed_file_plan_json")
TARGETS = template_for(MECH / "discover.yml",
                       "cis_linux_common_fixed_file_targets_json")
VIOLATIONS = template_for(MECH / "evaluate.yml",
                           "cis_linux_common_fixed_file_violations_json")
ACTIONS = template_for(MECH / "remediation.yml",
                       "cis_linux_common_fixed_file_actions_json")

GLOBAL_DEFAULTS = {
    "cis_linux_common_fixed_file_owner": "root",
    "cis_linux_common_fixed_file_group": "root",
    "cis_linux_common_fixed_file_expected_type": "file",
    "cis_linux_common_fixed_file_max_mode": "0644",
    "cis_linux_common_fixed_file_remediation_mode": "u-x,go-wx",
    "cis_linux_common_fixed_file_expected_mode_description": "0644 or more restrictive",
}


def base_context(**overrides):
    context = dict(GLOBAL_DEFAULTS)
    context.update(overrides)
    return context


def stat_meta(mode="0644", owner="root", group="root", exists=True,
              isreg=True, isdir=False):
    meta = {"exists": exists, "mode": mode, "isreg": isreg, "isdir": isdir}
    if exists:
        meta["pw_name"] = owner
        meta["gr_name"] = group
    return {"stat": meta}


class PlanNormalizationTest(StubEnvironmentMixin, unittest.TestCase):
    def test_scalar_path_stays_backward_compatible(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_path="/etc/issue"))
        self.assertEqual(1, len(plan["scopes"]))
        self.assertEqual(["/etc/issue"], plan["scopes"][0]["literals"])
        self.assertEqual([], plan["search_specs"])
        self.assertEqual("0644", plan["scopes"][0]["max_mode"])
        self.assertTrue(plan["scopes"][0]["enforce_group"])

    def test_path_accepts_a_list_of_paths(self):
        tools = ["/sbin/auditctl", "/sbin/aureport"]
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_path=tools))
        self.assertEqual(tools, plan["scopes"][0]["literals"])

    def test_search_normalizes_dict_and_lists(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_path="/etc/ssh/sshd_config",
            cis_linux_common_fixed_file_search={
                "paths": "/etc/ssh/sshd_config.d",
                "patterns": ["*.conf"], "recurse": True}))
        self.assertEqual(1, len(plan["search_specs"]))
        spec = plan["search_specs"][0]
        self.assertEqual(["/etc/ssh/sshd_config.d"], spec["paths"])
        self.assertEqual(0, spec["scope_index"])
        self.assertTrue(spec["recurse"])

    def test_scope_fields_override_the_globals(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_scopes=[
                {"label": "wtmp", "search": {"paths": "/var/log",
                                             "patterns": ["wtmp*"]},
                 "groups": ["root", "utmp"], "max_mode": "0664",
                 "remediation_mode": "ug-x,o-wx"},
                {"label": "default", "search": {"paths": "/var/log",
                                                "patterns": ["*"],
                                                "recurse": True},
                 "owners": ["root", "syslog"], "max_mode": "0640"},
            ]))
        self.assertEqual(["wtmp", "default"], [s["label"] for s in plan["scopes"]])
        self.assertEqual(["root", "utmp"], plan["scopes"][0]["groups"])
        self.assertEqual(["root"], plan["scopes"][0]["owners"])
        self.assertEqual(["root", "syslog"], plan["scopes"][1]["owners"])
        self.assertEqual(2, len(plan["search_specs"]))

    def test_legacy_enforce_group_false_is_preserved_per_scope(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_enforce_group=False,
            cis_linux_common_fixed_file_path="/var/log/audit/audit.log"))
        self.assertFalse(plan["scopes"][0]["enforce_group"])

    def test_global_allowed_groups_apply_to_the_default_scope(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_allowed_groups=["root", "adm"],
            cis_linux_common_fixed_file_path="/var/log/audit/audit.log"))
        self.assertEqual(["root", "adm"], plan["scopes"][0]["groups"])

    def test_scope_group_override_beats_global_allowed_groups(self):
        plan = self.render(PLAN, **base_context(
            cis_linux_common_fixed_file_allowed_groups=["root", "adm"],
            cis_linux_common_fixed_file_scopes=[
                {"path": "/etc/shadow", "group": "shadow"}]))
        self.assertEqual("shadow", plan["scopes"][0]["group"])
        self.assertEqual(["shadow"], plan["scopes"][0]["groups"])


class TargetDeduplicationTest(StubEnvironmentMixin, unittest.TestCase):
    def test_literal_and_search_duplicates_resolve_to_first_scope(self):
        plan = {"scopes": [{"label": "literal"}, {"label": "searched"}],
                "search_specs": []}
        find_results = [
            {"item": {"scope_index": 0}, "files": [{"path": "/etc/audit/auditd.conf"}]},
            {"item": {"scope_index": 1}, "files": [
                {"path": "/etc/audit/auditd.conf"},
                {"path": "/etc/audit/rules.d/audit.rules"}]},
        ]
        targets = self.render(TARGETS,
            cis_linux_common_fixed_file_plan=plan,
            cis_linux_common_fixed_file_search_results={
                "results": find_results})
        self.assertEqual(["/etc/audit/auditd.conf"],
                         [t["path"] for t in targets
                          if t["scope_index"] == 0])
        self.assertEqual(["/etc/audit/rules.d/audit.rules"],
                         [t["path"] for t in targets
                          if t["scope_index"] == 1])

    def test_missing_search_roots_yield_no_targets(self):
        plan = {"scopes": [{"label": "s", "literals": []}],
                "search_specs": []}
        targets = self.render(TARGETS,
            cis_linux_common_fixed_file_plan=plan,
            cis_linux_common_fixed_file_search_results={
                "results": [
                    {"item": {"scope_index": 0}, "skipped": True},
                ]})
        self.assertEqual([], targets)


class ModeComparisonTest(StubEnvironmentMixin, unittest.TestCase):
    def evaluate(self, mode, cap="0644", **extra):
        context = base_context(
            cis_linux_common_fixed_file_plan={
                "scopes": [{"label": "s", "owner": "root", "owners": ["root"],
                            "group": "root", "groups": ["root"],
                            "enforce_group": True, "type": "file",
                            "max_mode": cap, "remediation_mode": "u-x,go-wx",
                            "description": "", "allow_missing": extra.get(
                                "allow_missing", False), "literals": []}],
                "search_specs": []},
            cis_linux_common_fixed_file_targets=[
                {"path": "/etc/issue", "scope_index": 0, "source": "literal"}],
            cis_linux_common_fixed_file_target_stats={
                "results": [stat_meta(mode)]})
        return self.render(VIOLATIONS, **context)

    def test_equal_mode_passes_and_every_restriction_passes(self):
        for mode in ("0644", "0600", "0400", "0444", "0000"):
            with self.subTest(mode=mode):
                self.assertEqual([], self.evaluate(mode))

    def test_group_or_other_write_bits_fail_even_when_in_old_zero_to_six_range(self):
        for mode in ("0646", "0664", "0666", "0622", "0606", "0266"):
            with self.subTest(mode=mode):
                violations = self.evaluate(mode)
                self.assertEqual(1, len(violations), mode)
                self.assertIn("mode", violations[0]["dimensions"])
                self.assertIn("more permissive than 0644", violations[0]["reasons"][0])

    def test_execute_bits_beyond_cap_fail_for_files(self):
        # 0654 grants other-x; 0744 grants owner-x: both exceed 0644.
        self.assertEqual(1, len(self.evaluate("0654")))
        self.assertEqual(1, len(self.evaluate("0744")))

    def test_special_bits_beyond_cap_fail_fail_closed(self):
        self.assertEqual(1, len(self.evaluate("2644")))
        self.assertEqual(1, len(self.evaluate("4644")))

    def test_directories_accept_execute_within_cap(self):
        self.assertEqual([], self.evaluate("0755", cap="0755"))
        self.assertEqual([], self.evaluate("0750", cap="0755"))
        self.assertEqual(1, len(self.evaluate("0757", cap="0755")))
        self.assertEqual(1, len(self.evaluate("0775", cap="0755")))

    def test_zero_sixteen_six_accepts_group_write_but_rejects_other_write(self):
        self.assertEqual([], self.evaluate("0664", cap="0664"))
        self.assertEqual(1, len(self.evaluate("0666", cap="0664")))


class OwnerGroupExistenceTest(StubEnvironmentMixin, unittest.TestCase):
    def run_case(self, meta, scope_overrides=None, path="/etc/shadow"):
        scope = {"label": "s", "owner": "root", "owners": ["root"],
                 "group": "root", "groups": ["root"], "enforce_group": True,
                 "type": "file", "max_mode": "0640",
                 "remediation_mode": "u-x,g-wx,o-rwx", "description": "",
                 "allow_missing": False, "literals": []}
        scope.update(scope_overrides or {})
        context = base_context(
            cis_linux_common_fixed_file_plan={
                "scopes": [scope], "search_specs": []},
            cis_linux_common_fixed_file_targets=[
                {"path": path, "scope_index": 0, "source": "literal"}],
            cis_linux_common_fixed_file_target_stats={"results": [meta]})
        return self.render(VIOLATIONS, **context)

    def test_world_readable_shadow_fails_on_mode(self):
        violations = self.run_case(stat_meta("0644"))
        self.assertIn("mode", violations[0]["dimensions"])

    def test_wrong_owner_and_group_are_reported(self):
        violations = self.run_case(stat_meta("0640", owner="nobody", group="staff"))
        self.assertEqual(1, len(violations))
        self.assertEqual({"owner", "group"}, set(violations[0]["dimensions"]))

    def test_allowed_owners_and_groups_accept_benchmark_classes(self):
        violations = self.run_case(
            stat_meta("0640", owner="syslog", group="adm"),
            {"owners": ["root", "syslog"], "groups": ["root", "adm"]})
        self.assertEqual([], violations)

    def test_unresolvable_owner_is_a_violation(self):
        meta = {"stat": {"exists": True, "isreg": True, "mode": "0640",
                         "uid": 1234, "gid": 4321}}
        violations = self.run_case(meta)
        self.assertIn("owner unresolvable not in root", violations[0]["reasons"])

    def test_missing_literal_fails_closed(self):
        violations = self.run_case(stat_meta(exists=False, isreg=False))
        self.assertEqual(["missing or unreadable"], violations[0]["reasons"])

    def test_allow_missing_only_excuses_the_missing_file(self):
        violations = self.run_case(stat_meta(exists=False, isreg=False),
                                   {"allow_missing": True})
        self.assertEqual([], violations)
        violations = self.run_case(stat_meta("0666"), {"allow_missing": True})
        self.assertEqual(1, len(violations))

    def test_enforce_group_false_ignores_the_group_digit(self):
        violations = self.run_case(
            stat_meta("0640", group="adm"),
            {"enforce_group": False})
        self.assertEqual([], violations)

    def test_directory_target_rejects_regular_file(self):
        violations = self.run_case(
            stat_meta("0750", isreg=False, isdir=True),
            {"type": "directory", "max_mode": "0750"})
        self.assertEqual([], violations)
        violations = self.run_case(
            stat_meta("0750", isdir=False),
            {"type": "directory", "max_mode": "0750"})
        self.assertIn("not a directory", violations[0]["reasons"])


class RemediationActionTest(StubEnvironmentMixin, unittest.TestCase):
    def build(self, violations, metas, scopes, check_mode=False):
        return self.render(ACTIONS,
            ansible_check_mode=check_mode,
            cis_linux_common_fixed_file_plan={
                "scopes": scopes, "search_specs": []},
            cis_linux_common_fixed_file_target_stats={"results": metas},
            cis_linux_common_fixed_file_violations=violations)

    SCOPE = {"label": "s", "owner": "root", "owners": ["root"],
             "group": "root", "groups": ["root"], "enforce_group": True,
             "type": "file", "max_mode": "0644",
             "remediation_mode": "u-x,go-wx", "description": "",
             "allow_missing": False, "literals": []}

    def test_only_failing_dimensions_are_repaired(self):
        violation = {"path": "/var/log/syslog", "scope_index": 0,
                     "scope": "s", "source": "literal", "target_index": 0,
                     "dimensions": ["mode"], "reasons": ["mode 0664 is more permissive than 0640"]}
        actions = self.build([violation], [stat_meta("0664")], [self.SCOPE])
        self.assertEqual(1, len(actions))
        action = actions[0]
        self.assertEqual("OMIT", action["owner"])
        self.assertEqual("OMIT", action["group"])
        self.assertEqual("u-x,go-wx", action["mode"])

    def test_group_dimension_repairs_group_only_for_wrong_group(self):
        violation = {"path": "/etc/passwd", "scope_index": 0,
                     "scope": "s", "source": "literal", "target_index": 0,
                     "dimensions": ["group"], "reasons": ["group staff not in root"]}
        actions = self.build([violation], [stat_meta(group="staff")], [self.SCOPE])
        self.assertEqual("root", actions[0]["group"])
        self.assertEqual("OMIT", actions[0]["owner"])
        self.assertEqual("OMIT", actions[0]["mode"])

    def test_existing_compliant_files_produce_no_action(self):
        self.assertEqual([], self.build([], [stat_meta()], [self.SCOPE]))

    def test_check_mode_never_announces_creating_a_missing_file(self):
        violation = {"path": "/etc/motd", "scope_index": 0,
                     "scope": "s", "source": "literal", "target_index": 0,
                     "dimensions": ["exists"], "reasons": ["missing or unreadable"]}
        meta = {"stat": {"exists": False}}
        self.assertEqual([], self.build([violation], [meta], [self.SCOPE],
                                        check_mode=True))
        actions = self.build([violation], [meta], [self.SCOPE], check_mode=False)
        self.assertEqual(1, len(actions))
        created = actions[0]
        self.assertEqual("root", created["owner"])
        self.assertEqual("root", created["group"])
        self.assertEqual("u-x,go-wx", created["mode"])

    def test_directory_scope_is_checked_even_when_missing(self):
        violation = {"path": "/var/log/audit", "scope_index": 0,
                     "scope": "s", "source": "literal", "target_index": 0,
                     "dimensions": ["exists"], "reasons": ["missing or unreadable"]}
        scope = dict(self.SCOPE, type="directory", max_mode="0750")
        actions = self.build([violation], [{"stat": {"exists": False}}],
                             [scope], check_mode=True)
        self.assertEqual("directory", actions[0]["state"])

    def test_vanished_searched_files_are_not_recreated(self):
        violation = {"path": "/var/log/gone.log", "scope_index": 0,
                     "scope": "s", "source": "search", "target_index": 0,
                     "dimensions": ["exists"], "reasons": ["missing or unreadable"]}
        self.assertEqual([], self.build([violation], [{"stat": {"exists": False}}],
                                        [self.SCOPE]))


class AdapterContractTest(unittest.TestCase):
    ROLES = Path(__file__).resolve().parents[1] / "roles"

    def read(self, platform, *parts):
        path = self.ROLES / platform / "tasks/sections" / Path(*parts)
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def adapter_vars(self, platform, *parts):
        doc = self.read(platform, *parts)
        collected = []

        def walk(node):
            if isinstance(node, dict):
                if isinstance(node.get("vars"), dict):
                    collected.append(node["vars"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(doc)
        merged = {}
        for entry in collected:
            merged.update(entry)
        return merged

    def assert_max(self, platform, parts, cap):
        contract = self.adapter_vars(platform, *parts)
        self.assertEqual(cap, contract["cis_linux_common_fixed_file_max_mode"])
        for scope_key in ("allowed_owner_digits", "allowed_group_digits",
                          "allowed_other_digits"):
            self.assertNotIn(f"cis_linux_common_fixed_file_{scope_key}", contract)

    def test_banner_files_cap_at_0644_and_motd_may_be_absent(self):
        for control, parts in (
                ("1.6.4", ("section_01_initial_setup", "1_6_4_motd_permissions")),
                ("1.6.5", ("section_01_initial_setup", "1_6_5_issue_permissions")),
                ("1.6.6", ("section_01_initial_setup", "1_6_6_issue_net_permissions"))):
            for platform in ("cis_debian_12", "cis_ubuntu_2404"):
                for phase in ("audit", "remediation", "verification"):
                    with self.subTest(control=control, platform=platform, phase=phase):
                        contract = self.adapter_vars(platform, *parts, f"{phase}.yml")
                        self.assertEqual("0644",
                                         contract["cis_linux_common_fixed_file_max_mode"])
                        if control == "1.6.4":
                            self.assertTrue(
                                contract["cis_linux_common_fixed_file_allow_missing"])

    def test_sshd_config_covers_the_include_drop_in(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            for phase in ("audit", "remediation", "verification"):
                with self.subTest(platform=platform, phase=phase):
                    contract = self.adapter_vars(
                        platform, "section_05_access_control",
                        "5_1_1_sshd_config_permissions", f"{phase}.yml")
                    self.assertEqual("/etc/ssh/sshd_config",
                                     contract["cis_linux_common_fixed_file_path"])
                    search = contract["cis_linux_common_fixed_file_search"]
                    self.assertEqual("/etc/ssh/sshd_config.d", search["paths"])
                    self.assertEqual(["*.conf"], search["patterns"])
                    self.assertTrue(search["recurse"])
                    self.assertEqual("0600",
                                     contract["cis_linux_common_fixed_file_max_mode"])

    def test_audit_config_controls_cover_conf_and_rules_sets(self):
        controls = ("6_2_4_5_audit_config_file_mode",
                    "6_2_4_6_audit_config_file_owner",
                    "6_2_4_7_audit_config_file_group")
        for control in controls:
            for platform in ("cis_debian_12", "cis_ubuntu_2404"):
                for phase in ("audit", "remediation", "verification"):
                    with self.subTest(control=control, platform=platform):
                        contract = self.adapter_vars(
                            platform, "section_06_logging", control, f"{phase}.yml")
                        search = contract["cis_linux_common_fixed_file_search"]
                        self.assertEqual("/etc/audit", search["paths"])
                        self.assertEqual({"*.conf", "*.rules"},
                                         set(search["patterns"]))
                        self.assertTrue(search["recurse"])
                        self.assertEqual("0640",
                                         contract["cis_linux_common_fixed_file_max_mode"])

    def test_audit_tool_controls_cover_all_six_tools(self):
        tools = {"/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch",
                 "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules"}
        for control in ("6_2_4_8_audit_tool_mode", "6_2_4_9_audit_tool_owner",
                        "6_2_4_10_audit_tool_group"):
            for platform in ("cis_debian_12", "cis_ubuntu_2404"):
                for phase in ("audit", "remediation", "verification"):
                    with self.subTest(control=control, platform=platform):
                        contract = self.adapter_vars(
                            platform, "section_06_logging", control, f"{phase}.yml")
                        self.assertEqual(tools,
                                         set(contract["cis_linux_common_fixed_file_path"]))
                        self.assertEqual("0755",
                                         contract["cis_linux_common_fixed_file_max_mode"])

    def test_audit_log_controls_cover_every_audit_log_directory_file(self):
        for control in ("6_2_4_1_audit_log_file_mode",
                        "6_2_4_2_audit_log_file_owner",
                        "6_2_4_3_audit_log_file_group"):
            for platform in ("cis_debian_12", "cis_ubuntu_2404"):
                for phase in ("audit", "remediation", "verification"):
                    with self.subTest(control=control, platform=platform):
                        contract = self.adapter_vars(
                            platform, "section_06_logging", control, f"{phase}.yml")
                        self.assertNotIn("cis_linux_common_fixed_file_path", contract)
                        search = contract["cis_linux_common_fixed_file_search"]
                        self.assertEqual("/var/log/audit", search["paths"])
                        self.assertEqual("0640",
                                         contract["cis_linux_common_fixed_file_max_mode"])

    def test_logfile_control_covers_every_var_log_file_by_class(self):
        expected_labels = ["utmp-accounting", "cloud-init", "apt-logs",
                           "sensitive-logs", "sssd-logs", "gdm-logs",
                           "journal-logs", "default-logfiles"]
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            for phase in ("audit", "remediation", "verification"):
                with self.subTest(platform=platform, phase=phase):
                    contract = self.adapter_vars(
                        platform, "section_06_logging",
                        "6_1_4_1_logfile_permissions", f"{phase}.yml")
                    scopes = contract["cis_linux_common_fixed_file_scopes"]
                    self.assertEqual(expected_labels,
                                     [scope["label"] for scope in scopes])
                    last = scopes[-1]
                    self.assertEqual("/var/log", last["search"]["paths"])
                    self.assertTrue(last["search"]["recurse"])
                    self.assertTrue(last["search"]["hidden"])
                    for scope in scopes:
                        self.assertRegex(scope["max_mode"], r"^[0-7]{3,4}$")

    def test_crontab_and_cron_directories_cap_at_the_benchmark_modes(self):
        caps = {
            ("section_02_services", "2_4_1_2_crontab_permissions"): "0600",
            ("section_02_services", "2_4_1_3_cron_hourly"): "0700",
            ("section_02_services", "2_4_1_4_cron_daily"): "0700",
            ("section_02_services", "2_4_1_5_cron_weekly"): "0700",
            ("section_02_services", "2_4_1_6_cron_monthly"): "0700",
            ("section_02_services", "2_4_1_7_cron_d"): "0700",
        }
        for parts, cap in caps.items():
            for platform in ("cis_debian_12", "cis_ubuntu_2404"):
                for phase in ("audit", "remediation", "verification"):
                    with self.subTest(parts=parts, platform=platform):
                        self.assert_max(platform, (*parts, f"{phase}.yml"), cap)

    def test_ubuntu_7_1_3_targets_group_not_group_backup(self):
        contract = self.adapter_vars("cis_ubuntu_2404", "section_07_maintenance",
                                     "7_1_3_group_backup_permissions", "audit.yml")
        self.assertEqual("/etc/group", contract["cis_linux_common_fixed_file_path"])

    def test_every_adapter_octal_remediation_is_within_its_cap(self):
        def subsets(cap_digit):
            cap = int(cap_digit, 8)
            return {d for d in range(8) if not d & ~cap}

        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            base = self.ROLES / platform / "tasks/sections"
            for path in sorted(base.glob("**/verification.yml")):
                contract = self.adapter_vars(platform, *path.relative_to(base).parts)
                cap = contract.get("cis_linux_common_fixed_file_max_mode")
                if cap is None:
                    continue
                mode = str(contract.get(
                    "cis_linux_common_fixed_file_remediation_mode", ""))
                if not mode.isdigit():
                    continue
                padded_mode = ("0000" + mode)[-4:]
                padded_cap = ("0000" + cap)[-4:]
                for index, scope in enumerate(("special", "owner", "group",
                                               "other")):
                    with self.subTest(platform=platform, control=path.parent.name,
                                      scope=scope):
                        self.assertIn(int(padded_mode[index], 8),
                                      subsets(padded_cap[index]))


if __name__ == "__main__":
    unittest.main()
