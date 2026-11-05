"""CIS 1.1.1.6 must denylist the kernel module "overlay", not "overlayfs".

Both benchmark scripts set l_mod_name="overlayfs" and then map
l_mod_chk_name="${l_mod_name::-2}" to "overlay", so audit, remediation and
verification must act on the module "overlay" while the dedicated file and the
control name may remain overlayfs. Remediation must also retire only the exact
managed lines previously written under the wrong module name.
"""

from pathlib import Path
import re
import unittest

import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"
CONTROL_REL = "sections/section_01_initial_setup/1_1_1_6_overlayfs"
COMMON_CONTROL = ROLES / "cis_linux_common/tasks" / CONTROL_REL
PLATFORMS = ("cis_debian_12", "cis_ubuntu_2404")
PHASES = ("audit", "remediation", "verification")

MODULE_TEMPLATE = "{{ cis_linux_common_kernel_module }}"
MECHANISM = ROLES / "cis_linux_common/tasks/mechanisms/kernel_module_disabled"
REQUIRED = {
    "install": {"line": "install overlay /bin/true",
                "regexp": "^install overlay /bin/true$"},
    "blacklist": {"line": "blacklist overlay",
                  "regexp": "^blacklist overlay$"},
}
OBSOLETE_REGEXPS = ("^install overlayfs /bin/true$", "^blacklist overlayfs$")


def load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def render_module(template):
    """Substitute the corrected module name the way Ansible renders it."""
    assert MODULE_TEMPLATE in template, template
    return template.replace(MODULE_TEMPLATE, "overlay")


class OverlayfsModuleMappingTest(unittest.TestCase):
    def wrapper_vars(self, platform, phase):
        tasks = load(ROLES / platform / "tasks" / CONTROL_REL / f"{phase}.yml")
        self.assertEqual(1, len(tasks))
        return tasks[0]["vars"]

    def test_wrappers_denylist_the_overlay_module_not_overlayfs(self):
        for platform in PLATFORMS:
            for phase in PHASES:
                with self.subTest(platform=platform, phase=phase):
                    wrapper = self.wrapper_vars(platform, phase)
                    self.assertEqual("overlay",
                                     wrapper["cis_linux_common_kernel_module"])
                    # Control identity and dedicated file keep the overlayfs name.
                    self.assertEqual("1.1.1.6", wrapper["cis_linux_common_control_id"])
                    self.assertEqual("/etc/modprobe.d/overlayfs.conf",
                                     wrapper["cis_linux_common_config_line_path"])

    def test_common_phases_delegate_to_the_kernel_module_mechanism(self):
        # The dedicated mechanism owns the write; the control file only
        # routes to it. The overlay spelling reaches it through the wrapper
        # var cis_linux_common_kernel_module=overlay (tested above), so the
        # managed lines rendered for this control are the overlay ones.
        for phase in PHASES:
            with self.subTest(phase=phase):
                tasks = load(COMMON_CONTROL / f"{phase}.yml")
                imports = [task["ansible.builtin.import_tasks"]
                           for task in tasks
                           if "ansible.builtin.import_tasks" in task]
                self.assertEqual(
                    [f"mechanisms/kernel_module_disabled/{phase}.yml"], imports)
        writes = {}
        for task in load(MECHANISM / "remediation.yml"):
            lineinfile = task.get("ansible.builtin.lineinfile")
            if lineinfile and lineinfile.get("state") != "absent":
                line = render_module(lineinfile["line"])
                writes[line.split()[0]] = line
        self.assertEqual(REQUIRED["install"]["line"], writes["install"])
        self.assertEqual(REQUIRED["blacklist"]["line"], writes["blacklist"])

    def test_obsolete_overlayfs_lines_no_longer_satisfy_the_check(self):
        """The false PASS is gone: old managed lines do not match the overlay regexps."""
        obsolete_content = "install overlayfs /bin/true\nblacklist overlayfs\n"
        for kind in REQUIRED:
            with self.subTest(kind=kind):
                self.assertIsNone(re.search(
                    REQUIRED[kind]["regexp"], obsolete_content, re.MULTILINE))

    def removal_tasks(self):
        tasks = load(COMMON_CONTROL / "remediation.yml")
        removals = [task for task in tasks
                    if "ansible.builtin.lineinfile" in task
                    and task["ansible.builtin.lineinfile"].get("state") == "absent"]
        return tasks, removals

    def test_remediation_removes_only_the_exact_obsolete_managed_lines(self):
        tasks, removals = self.removal_tasks()
        self.assertEqual(2, len(removals))
        patterns = sorted(task["ansible.builtin.lineinfile"]["regexp"]
                          for task in removals)
        self.assertEqual(sorted(OBSOLETE_REGEXPS), patterns)
        for task in removals:
            lineinfile = task["ansible.builtin.lineinfile"]
            # Only ever inside the dedicated overlayfs file.
            self.assertEqual("{{ cis_linux_common_config_line_path }}",
                             lineinfile["path"])
            # Full-line anchored match: never a broad prefix or wildcard sweep.
            self.assertTrue(lineinfile["regexp"].startswith("^"))
            self.assertTrue(lineinfile["regexp"].endswith("$"))
            self.assertNotIn("line", lineinfile)
            # Scoped to hosts where the shared mechanism manages the file.
            self.assertIn(
                "cis_linux_common_config_line_package in ansible_facts.packages",
                task["when"])

    def test_removal_runs_after_the_mechanism_gathers_package_facts(self):
        tasks, removals = self.removal_tasks()
        imports = [task for task in tasks if "ansible.builtin.import_tasks" in task]
        self.assertEqual(1, len(imports))
        for removal in removals:
            self.assertLess(tasks.index(imports[-1]), tasks.index(removal))

    def test_simulated_removal_preserves_administrator_configuration(self):
        content = "\n".join([
            "# site policy",
            "blacklist usb-storage",
            "install overlay /bin/true",
            "blacklist overlay",
            "install overlayfs /bin/true",
            "blacklist overlayfs",
            "options overlay xattr=0",
            "",
        ])
        kept = [line for line in content.splitlines()
                if not any(re.match(pattern, line) for pattern in OBSOLETE_REGEXPS)]
        self.assertEqual([
            "# site policy",
            "blacklist usb-storage",
            "install overlay /bin/true",
            "blacklist overlay",
            "options overlay xattr=0",
        ], kept)

    def test_remediation_has_no_file_deletion_tasks(self):
        tasks, _ = self.removal_tasks()
        for task in tasks:
            module_args = task.get("ansible.builtin.file")
            self.assertTrue(module_args is None
                            or module_args.get("state") != "absent")


if __name__ == "__main__":
    unittest.main()
