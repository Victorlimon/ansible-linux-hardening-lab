"""Selection contract for the sealed Debian and Ubuntu CIS adapters."""

import importlib.util
import json
from pathlib import Path
import re
import sys
import types
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[3]
MODULE = ROOT / "integration" / "wazuh" / "managed_job.py"
if sys.platform == "win32":
    sys.modules.setdefault("pwd", types.SimpleNamespace())
SPEC = importlib.util.spec_from_file_location("selective_managed_job", MODULE)
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)


class SelectiveSectionsTests(unittest.TestCase):
    def test_section_names_are_bounded(self):
        valid = {"kind": "sections", "names": ["4", "5.1"]}
        for names in (["0"], ["8"], ["5.0"], ["5.1.1"], ["4;rm"], ["4", "4"]):
            with self.subTest(names=names), self.assertRaises(job.Reject):
                self._parse({"kind": "sections", "names": names})
        self.assertEqual(self._parse(valid).selection_names, ("4", "5.1"))

    def test_all_seven_sections_cover_each_installed_adapter_mode(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            tasks_root = ROOT / "ansible" / "roles" / platform / "tasks"
            tasks = yaml.safe_load((tasks_root / "main.yml").read_text(encoding="utf-8"))
            text = (tasks_root / "main.yml").read_text(encoding="utf-8")
            with patch.object(job, "trusted_file", side_effect=lambda path: Path(path).read_bytes()):
                for mode in ("audit", "remediation", "verification"):
                    for section in "1234567":
                        with self.subTest(platform=platform, mode=mode, section=section):
                            selected = set(job._section_tags(text, tasks_root, (section,), mode))
                            imports = [task for task in tasks
                                       if re.search(r"section_0" + section + r"_[^/]+/.+/" + mode + r"\.yml$",
                                                    task.get("ansible.builtin.import_tasks", ""))]
                            self.assertTrue(imports)
                            self.assertTrue(selected)
                            self.assertTrue(all(tag.startswith("cis_" + section + "_") for tag in selected))
                            for task in imports:
                                tags = set(task.get("tags", []))
                                if not tags:
                                    nested = yaml.safe_load((tasks_root / task["ansible.builtin.import_tasks"])
                                                            .read_text(encoding="utf-8"))
                                    self.assertTrue(nested)
                                    for child in nested:
                                        self.assertTrue(selected.intersection(child.get("tags", [])))
                                else:
                                    self.assertTrue(selected.intersection(tags), task["ansible.builtin.import_tasks"])

    def test_ssh_subsection_and_individual_controls_stay_scoped(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            root = ROOT / "ansible" / "roles" / platform / "tasks"
            text = (root / "main.yml").read_text(encoding="utf-8")
            with patch.object(job, "trusted_file", side_effect=lambda path: Path(path).read_bytes()):
                ssh = job._section_tags(text, root, ("5.1",), "remediation")
                # Controls 5.1.1 through 5.1.22 each have one remediation directory.
                self.assertEqual(len(ssh), 22)
                self.assertTrue(all(tag.startswith("cis_5_1_") for tag in ssh))
                self.assertTrue(job._control_tag_present(text, root, "cis_5_1_2", "remediation"))
                # 5.1.4 (AllowUsers) became remediable; a non-existent control stays unselectable.
                self.assertTrue(job._control_tag_present(text, root, "cis_5_1_4", "remediation"))
                self.assertFalse(job._control_tag_present(text, root, "cis_5_1_99", "remediation"))
            if platform == "cis_ubuntu_2404":
                self.assertIn("cis_4_2_6", job._section_tags(text, root, ("4",), "remediation"))

    def test_managed_plan_preserves_full_and_selects_sections_or_controls(self):
        catalog = {"releases": {"r1": {"inventory_profiles": {
            "ubuntu_lab": {"platform": "ubuntu24", "aliases": ["web01"]},
            "debian_lab": {"platform": "debian12", "aliases": ["db01"]}}}}}
        policy = {"release_id": "r1", "ansible_root": str(ROOT / "ansible"),
                  "targets": {"web01": {"host": "web01", "os": "ubuntu24"},
                              "db01": {"host": "db01", "os": "debian12"}}}
        inventory = {"ubuntu": {"hosts": ["web01"]},
                     "debian_12": {"hosts": ["db01"]}}
        with patch.object(job, "trusted_file", side_effect=lambda path: Path(path).read_bytes()), \
             patch.object(job, "load_managed_catalog", return_value=catalog):
            for platform, playbook, host, profile, role in (
                    ("ubuntu24", "ubuntu_hardening", "web01", "ubuntu_lab", "cis_ubuntu_2404"),
                    ("debian12", "debian_hardening", "db01", "debian_lab", "cis_debian_12")):
                options = {"playbook_id": playbook, "inventory_profile_id": profile,
                           "targets": [host]}
                with self.subTest(platform=platform):
                    full = self._parse({"kind": "full", "names": []}, **options)
                    _, full_plan = job._v2_plan(policy, "a" * 64, full, inventory)
                    self.assertEqual(full_plan["tags"], [role + "_remediation"])
                    section = self._parse({"kind": "sections", "names": ["5.1"]}, **options)
                    _, section_plan = job._v2_plan(policy, "a" * 64, section, inventory)
                    self.assertEqual(len(section_plan["tags"]), 22)
                    control = self._parse({"kind": "tags", "names": ["cis_5_1_2"]}, **options)
                    _, control_plan = job._v2_plan(policy, "a" * 64, control, inventory)
                    self.assertEqual(control_plan["tags"], ["cis_5_1_2"])
            firewall = self._parse({"kind": "sections", "names": ["4"]},
                                   extra_vars={"cis_ufw_allowed_in_rules": [
                                       {"from_ip": "10.20.30.0/24", "port": 443, "proto": "tcp"}]})
            _, plan = job._v2_plan(policy, "a" * 64, firewall, inventory)
            self.assertIn("cis_4_2_6", plan["tags"])
            inert = self._parse({"kind": "sections", "names": ["5.1"]},
                                 extra_vars={"cis_ufw_ssh_port": 2222})
            with self.assertRaisesRegex(job.Reject, "no selected firewall consumer"):
                job._v2_plan(policy, "a" * 64, inert, inventory)

    def test_dynamic_includes_propagate_tags_to_child_tasks(self):
        for role in ("cis_debian_12", "cis_ubuntu_2404", "cis_linux_common"):
            root = ROOT / "ansible" / "roles" / role / "tasks"
            for path in root.rglob("*.yml"):
                tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
                if not isinstance(tasks, list):
                    continue
                for task in tasks:
                    if not isinstance(task, dict):
                        continue
                    for key in ("ansible.builtin.include_role", "ansible.builtin.include_tasks"):
                        if key in task:
                            include = task[key]
                            self.assertIsInstance(include, dict, path)
                            self.assertIn("tags", include.get("apply", {}), path)

    @staticmethod
    def _parse(selection, **updates):
        order = {"mode": "check", "request_id": "1fca84c0-b7ef-4a9a-a1c2-76955ff426fd",
                 "change_id": "CHG123", "release_id": "r1", "playbook_id": "ubuntu_hardening",
                 "inventory_profile_id": "ubuntu_lab", "targets": ["web01"],
                 "selection": selection, "extra_vars": {}}
        order.update(updates)
        return job.parse_managed_v2(json.dumps(order, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
