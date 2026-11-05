"""Keep journal upload disabled until an explicit secure destination exists."""

from pathlib import Path
import re
import unittest
from urllib.parse import urlsplit

from jinja2 import Environment
import yaml


ROOT = Path(__file__).resolve().parents[1] / "roles"
CONTROL = "sections/section_06_logging/6_1_2_1_3_journal_upload_enabled"


def read_tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class JournalUploadDestinationTest(unittest.TestCase):
    def test_platform_defaults_do_not_assume_a_remote_collector(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            with self.subTest(platform=platform):
                defaults = yaml.safe_load(
                    (ROOT / platform / "defaults/main.yml").read_text(encoding="utf-8")
                )
                self.assertEqual("", defaults[f"{platform}_journal_upload_url"])

    def test_every_platform_mode_passes_its_own_destination(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            for mode in ("audit", "remediation", "verification"):
                with self.subTest(platform=platform, mode=mode):
                    wrapper = read_tasks(ROOT / platform / "tasks" / CONTROL / f"{mode}.yml")
                    self.assertEqual(
                        f"{{{{ {platform}_journal_upload_url }}}}",
                        wrapper[0]["vars"]["cis_linux_common_journal_upload_url"],
                    )

    def test_remediation_requires_destination_before_enable(self):
        tasks = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / "remediation.yml")
        validation = next(task for task in tasks if "ansible.builtin.assert" in task)
        config = next(task for task in tasks if "ansible.builtin.lineinfile" in task)
        enabled = next(task for task in tasks if "service_enabled/remediation.yml" in str(task))
        disabled = next(task for task in tasks if "service_disabled/remediation.yml" in str(task))
        self.assertLess(tasks.index(validation), tasks.index(config))
        self.assertLess(tasks.index(config), tasks.index(enabled))
        self.assertIn("urlsplit('scheme')", str(validation))
        self.assertIn("urlsplit('hostname')", str(validation))
        self.assertIn("cis_linux_common_journal_upload_url", str(validation))
        self.assertIn("journal-upload.conf", config["ansible.builtin.lineinfile"]["path"])
        self.assertIn("URL={{ cis_linux_common_journal_upload_url }}", config["ansible.builtin.lineinfile"]["line"])
        self.assertIn("cis_linux_common_journal_upload_url", str(enabled["when"]))
        self.assertIn("cis_linux_common_journal_upload_url", str(disabled["when"]))

    def test_audit_and_verification_have_unconfigured_path(self):
        audit = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / "audit.yml")
        self.assertTrue(any("service_enabled/audit.yml" in str(task) for task in audit))
        self.assertTrue(any("NOT_APPLICABLE" in str(task) for task in audit))
        verification = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / "verification.yml")
        self.assertTrue(any("service_enabled/verification.yml" in str(task) for task in verification))
        self.assertTrue(any("service_disabled/verification.yml" in str(task) for task in verification))

    def test_failed_unit_is_reset_only_outside_check_mode(self):
        tasks = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / "remediation.yml")
        disabled = next(task for task in tasks if "service_disabled/remediation.yml" in str(task))
        probe = next(task for task in tasks if "is-failed" in str(task.get("ansible.builtin.command", "")))
        reset = next(task for task in tasks if "reset-failed" in str(task.get("ansible.builtin.command", "")))
        self.assertLess(tasks.index(disabled), tasks.index(probe))
        self.assertLess(tasks.index(probe), tasks.index(reset))
        self.assertEqual(False, probe["check_mode"])
        self.assertEqual(False, probe["changed_when"])
        self.assertEqual(False, probe["failed_when"])
        self.assertIn("not ansible_check_mode", reset["when"])
        self.assertIn("cis_linux_common_journal_upload_failed.rc == 0", reset["when"])

    def test_failed_unit_cannot_pass_audit_or_verification(self):
        for mode in ("audit", "verification"):
            with self.subTest(mode=mode):
                tasks = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / f"{mode}.yml")
                probe = next(task for task in tasks if "is-failed" in str(task.get("ansible.builtin.command", "")))
                self.assertEqual(False, probe["check_mode"])
                self.assertEqual(False, probe["changed_when"])
                self.assertEqual(False, probe["failed_when"])
                if mode == "audit":
                    report = next(task for task in tasks if "NOT_APPLICABLE" in str(task))
                    self.assertIn("cis_linux_common_journal_upload_failed.rc | default(1)", str(report))
                else:
                    assertion = next(task for task in tasks if "ansible.builtin.assert" in task)
                    self.assertIn("cis_linux_common_journal_upload_failed.rc != 0",
                                  assertion["ansible.builtin.assert"]["that"])

    def test_destination_gate_accepts_https_host_and_rejects_unsafe_values(self):
        tasks = read_tasks(ROOT / "cis_linux_common/tasks" / CONTROL / "remediation.yml")
        conditions = next(task["ansible.builtin.assert"]["that"] for task in tasks
                          if "ansible.builtin.assert" in task)
        environment = Environment()
        environment.filters["urlsplit"] = lambda value, part: getattr(urlsplit(value), part)
        environment.tests["search"] = lambda value, pattern: re.search(pattern, value) is not None
        for url, expected in (
            ("https://logs.example.org:19532/upload", True),
            ("http://logs.example.org/upload", False),
            ("https:///upload", False),
            ("https://admin:secret@logs.example.org/upload", False),
            ("https://logs.example.org/upload\nURL=https://attacker", False),
            ("https://logs.example.org/upload#fragment", False),
        ):
            with self.subTest(url=url):
                self.assertEqual(expected, all(environment.compile_expression(expression)(
                    cis_linux_common_journal_upload_url=url) for expression in conditions))


if __name__ == "__main__":
    unittest.main()
