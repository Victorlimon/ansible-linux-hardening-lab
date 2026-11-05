"""CIS audit-log mode must not impose an audit-log group policy."""

from pathlib import Path
import json
import unittest

from jinja2 import Environment
import yaml


ROOT = Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks"
MECHANISM = ROOT / "mechanisms/fixed_file_permissions"
SECTIONS = ROOT / "sections/section_06_logging"


def tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def violations_template():
    for task in tasks(MECHANISM / "evaluate.yml"):
        fact = task.get("ansible.builtin.set_fact") or {}
        if "cis_linux_common_fixed_file_violations_json" in fact:
            return fact["cis_linux_common_fixed_file_violations_json"]
    raise AssertionError("no violations template")


def actions_template():
    for task in tasks(MECHANISM / "remediation.yml"):
        fact = task.get("ansible.builtin.set_fact") or {}
        if "cis_linux_common_fixed_file_actions_json" in fact:
            return fact["cis_linux_common_fixed_file_actions_json"]
    raise AssertionError("no actions template")


class AuditLogGroupPolicyTest(unittest.TestCase):
    def test_mode_and_owner_controls_do_not_enforce_group(self):
        for control in ("6_2_4_1_audit_log_file_mode",
                        "6_2_4_2_audit_log_file_owner",
                        "6_2_4_4_audit_log_directory_mode"):
            for mode in ("audit", "remediation", "verification"):
                with self.subTest(control=control, mode=mode):
                    wrapper = tasks(SECTIONS / f"{control}/{mode}.yml")
                    self.assertIs(False, wrapper[0]["vars"][
                        "cis_linux_common_fixed_file_enforce_group"])

    def test_group_control_accepts_root_and_adm_in_any_mode(self):
        for mode in ("audit", "remediation", "verification"):
            with self.subTest(mode=mode):
                wrapper = tasks(SECTIONS / f"6_2_4_3_audit_log_file_group/{mode}.yml")
                self.assertEqual(["root", "adm"], wrapper[0]["vars"][
                    "cis_linux_common_fixed_file_allowed_groups"])

    def test_evaluation_honours_enforce_group_and_allowed_groups(self):
        env = Environment()
        env.filters["to_json"] = json.dumps
        template = violations_template()
        for enforce, allowed, group, expected in (
                (False, ["root"], "adm", []),
                (True, ["root", "adm"], "adm", []),
                (True, ["root", "adm"], "root", []),
                (True, ["root", "adm"], "staff", ["group"]),
                (True, ["root"], "adm", ["group"])):
            with self.subTest(enforce=enforce, allowed=allowed, group=group):
                scope = {"label": "s", "owner": "root", "owners": ["root"],
                         "group": "root", "groups": allowed,
                         "enforce_group": enforce, "type": "file",
                         "max_mode": "0640", "remediation_mode": "u-x,g-wx,o-rwx",
                         "description": "", "allow_missing": False,
                         "literals": []}
                meta = {"stat": {"exists": True, "isreg": True, "pw_name": "root",
                                 "gr_name": group, "mode": "0640"}}
                violations = json.loads(env.from_string(template).render(
                    cis_linux_common_fixed_file_plan={
                        "scopes": [scope], "search_specs": []},
                    cis_linux_common_fixed_file_targets=[
                        {"path": "/var/log/audit/audit.log", "scope_index": 0,
                         "source": "literal"}],
                    cis_linux_common_fixed_file_target_stats={
                        "results": [meta]}))
                self.assertEqual(sorted(expected),
                                 sorted(violations[0]["dimensions"])
                                 if violations else [])

    def test_remediation_repairs_group_only_when_the_group_is_not_allowed(self):
        env = Environment()
        env.filters["to_json"] = json.dumps
        template = actions_template()
        # Mirror evaluate's output: a group dimension exists only when the
        # group is outside the allowed set (and enforcement is on).
        for enforce, allowed, current, expected_group in (
                (False, ["root"], "adm", "OMIT"),
                (True, ["root", "adm"], "adm", "OMIT"),
                (True, ["root", "adm"], "root", "OMIT"),
                (True, ["root", "adm"], "staff", "root"),
                (True, ["root"], "adm", "root")):
            with self.subTest(enforce=enforce, allowed=allowed, current=current):
                scope = {"label": "s", "owner": "root", "owners": ["root"],
                         "group": "root", "groups": allowed,
                         "enforce_group": enforce, "type": "file",
                         "max_mode": "0640", "remediation_mode": "u-x,g-wx,o-rwx",
                         "description": "", "allow_missing": False,
                         "literals": []}
                group_bad = enforce and current not in allowed
                violation = {
                    "path": "/var/log/audit/audit.log", "scope_index": 0,
                    "scope": "s", "source": "literal", "target_index": 0,
                    "dimensions": ["group"] if group_bad else [],
                    "reasons": ["group mismatch"] if group_bad else []}
                meta = {"stat": {"exists": True, "isreg": True, "pw_name": "root",
                                 "gr_name": current, "mode": "0640"}}
                actions = json.loads(env.from_string(template).render(
                    ansible_check_mode=False,
                    cis_linux_common_fixed_file_plan={
                        "scopes": [scope], "search_specs": []},
                    cis_linux_common_fixed_file_target_stats={
                        "results": [meta]},
                    cis_linux_common_fixed_file_violations=([violation]
                                                            if group_bad else [])))
                if group_bad:
                    self.assertEqual(1, len(actions))
                    self.assertEqual(expected_group, actions[0]["group"])
                else:
                    self.assertEqual([], actions)


if __name__ == "__main__":
    unittest.main()
