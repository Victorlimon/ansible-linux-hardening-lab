"""Guard sudoers permissions and syntax checks in the shared line mechanism."""

from pathlib import Path
import unittest

from jinja2 import Environment
import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"
MECHANISM = ROLES / "cis_linux_common/tasks/mechanisms/config_line/remediation.yml"
SUDO_REMEDIATION = (ROLES / "cis_linux_common/tasks/sections/section_05_access_control/"
                    "5_2_2_sudo_use_pty/remediation.yml")
PLATFORMS = ("cis_debian_12", "cis_ubuntu_2404")


class SudoersConfigLineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tasks = yaml.safe_load(MECHANISM.read_text(encoding="utf-8"))
        cls.lineinfile = next(task["ansible.builtin.lineinfile"] for task in tasks
                              if "ansible.builtin.lineinfile" in task)
        cls.environment = Environment()

    @classmethod
    def render(cls, field, path, exists=True):
        template = cls.lineinfile.get(field)
        if template is None:
            return None
        return cls.environment.from_string(template).render(
            cis_linux_common_config_line_path=path,
            cis_linux_common_config_line_stat={"stat": {"exists": exists}},
            omit="__omit__")

    def test_both_platforms_route_sudoers_through_shared_mechanism(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform):
                adapter = (ROLES / platform / "tasks/sections/section_05_access_control/"
                           "5_2_2_sudo_use_pty/remediation.yml")
                task = yaml.safe_load(adapter.read_text(encoding="utf-8"))[0]
                self.assertEqual("/etc/sudoers.d/cis_use_pty",
                                 task["vars"]["cis_linux_common_config_line_path"])
                self.assertEqual("cis_linux_common", task["ansible.builtin.import_role"]["name"])

    def test_sudoers_files_are_private_and_validated(self):
        for path in ("/etc/sudoers", "/etc/sudoers.d/cis_use_pty"):
            with self.subTest(path=path):
                self.assertEqual("0440", self.render("mode", path))
                self.assertEqual("/usr/sbin/visudo -cf %s", self.render("validate", path))

    def test_existing_unrelated_files_preserve_mode_and_no_validator(self):
        for path in ("/etc/ssh/sshd_config", "/etc/audit/auditd.conf",
                     "/etc/sudoers.different", "/tmp/etc/sudoers"):
            with self.subTest(path=path):
                self.assertEqual("__omit__", self.render("mode", path))
                self.assertIn(self.render("validate", path), (None, "__omit__"))

    def test_new_unrelated_files_have_explicit_safe_mode(self):
        self.assertEqual("0644", self.render("mode", "/tmp/new.conf", exists=False))

    def test_existing_file_probe_precedes_line_edit(self):
        tasks = yaml.safe_load(MECHANISM.read_text(encoding="utf-8"))
        probe = next(task for task in tasks if "ansible.builtin.stat" in task)
        edit = next(task for task in tasks if "ansible.builtin.lineinfile" in task)
        self.assertLess(tasks.index(probe), tasks.index(edit))
        self.assertEqual("{{ cis_linux_common_config_line_path }}",
                         probe["ansible.builtin.stat"]["path"])
        self.assertEqual("cis_linux_common_config_line_stat", probe["register"])

    def test_existing_sudoers_modes_are_normalized_before_policy_validation(self):
        tasks = yaml.safe_load(SUDO_REMEDIATION.read_text(encoding="utf-8"))
        names = [task["name"] for task in tasks]
        validation = names.index("CIS 5.2.2 | Remediation | Validate sudo policy before change")
        main = next(task for task in tasks if task["name"] ==
                    "CIS 5.2.2 | Remediation | Normalize main sudoers mode")
        included = next(task for task in tasks if task["name"] ==
                        "CIS 5.2.2 | Remediation | Normalize sudoers include modes")
        self.assertLess(names.index(main["name"]), validation)
        self.assertLess(names.index(included["name"]), validation)
        self.assertEqual("0440", main["ansible.builtin.file"]["mode"])
        self.assertEqual("0440", included["ansible.builtin.file"]["mode"])
        self.assertEqual("file", main["ansible.builtin.file"]["state"])
        self.assertEqual("file", included["ansible.builtin.file"]["state"])
        self.assertFalse(main["ansible.builtin.file"]["follow"])
        self.assertFalse(included["ansible.builtin.file"]["follow"])
        self.assertIn("cis_linux_common_sudo_main_stat.stat.isreg | default(false)",
                      main["when"])
        self.assertEqual("item.mode != '0440'", included["when"])

    def test_include_discovery_excludes_symlinks_and_nested_files(self):
        tasks = yaml.safe_load(SUDO_REMEDIATION.read_text(encoding="utf-8"))
        discovery = next(task["ansible.builtin.find"] for task in tasks
                         if "ansible.builtin.find" in task)
        self.assertEqual("/etc/sudoers.d", discovery["paths"])
        self.assertEqual("file", discovery["file_type"])
        self.assertFalse(discovery["follow"])
        self.assertFalse(discovery["recurse"])
        self.assertFalse(discovery["hidden"])
        self.assertTrue(discovery["use_regex"])
        self.assertEqual("^[^.~]+$", discovery["patterns"])

    def test_check_mode_defers_visudo_only_for_predicted_mode_corrections(self):
        tasks = yaml.safe_load(SUDO_REMEDIATION.read_text(encoding="utf-8"))
        prediction = next(task["ansible.builtin.set_fact"] for task in tasks
                          if "ansible.builtin.set_fact" in task)
        template = self.environment.from_string(
            prediction["cis_linux_common_sudo_mode_correction_needed"])
        for existing_mode, expected in (("0644", "True"), ("0440", "False")):
            with self.subTest(existing_mode=existing_mode):
                result = template.render(
                    cis_linux_common_sudo_main_stat={"stat": {"isreg": True,
                                                              "mode": "0440"}},
                    cis_linux_common_sudo_include_files={
                        "files": [{"path": "/etc/sudoers.d/vagrant",
                                   "mode": existing_mode}]})
                self.assertEqual(expected, result.strip())
        validations = [task for task in tasks if task.get("ansible.builtin.command") ==
                       "/usr/sbin/visudo -c"]
        self.assertEqual(2, len(validations))
        for task in validations:
            self.assertFalse(task["check_mode"])
            self.assertIn("not ansible_check_mode or not "
                          "cis_linux_common_sudo_mode_correction_needed", task["when"])


if __name__ == "__main__":
    unittest.main()
