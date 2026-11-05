"""Regression tests for the CIS 2.3 single time-daemon profile."""

from pathlib import Path
import unittest

from jinja2 import Environment
import yaml


ROLES = Path(__file__).resolve().parents[1] / "roles"


def tasks(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class TimeSyncSelectionTest(unittest.TestCase):
    def test_default_profile_selects_timesyncd_subsection_only(self):
        for platform in ("cis_debian_12", "cis_ubuntu_2404"):
            with self.subTest(platform=platform):
                defaults = tasks(ROLES / platform / "defaults/main.yml")
                self.assertTrue(defaults[f"{platform}_2_3_1_1_single_daemon"])
                self.assertTrue(defaults[f"{platform}_2_3_2_1_timesyncd_config"])
                self.assertTrue(defaults[f"{platform}_2_3_2_2_timesyncd_enabled"])
                for control in ("2_3_3_1_chrony_config", "2_3_3_2_chrony_user",
                                "2_3_3_3_chrony_enabled"):
                    self.assertFalse(defaults[f"{platform}_{control}"])

    def test_single_daemon_rejects_zero_and_multiple(self):
        mechanism = ROLES / "cis_linux_common/tasks/mechanisms/single_daemon"
        audit = tasks(mechanism / "audit.yml")
        classification = audit[-1]["ansible.builtin.debug"]["msg"]["classification"]
        verify = tasks(mechanism / "verification.yml")
        condition = verify[-1]["ansible.builtin.assert"]["that"][0]
        environment = Environment()
        for active, expected in (([], False), (["systemd-timesyncd.service"], True),
                                 (["chrony.service"], True),
                                 (["systemd-timesyncd.service", "chrony.service"], False)):
            with self.subTest(active=active):
                services = {name: {"state": "running"} for name in active}
                context = {"ansible_facts": {"services": services}}
                self.assertEqual(
                    "PASS" if expected else "FAIL",
                    environment.from_string(classification).render(
                        cis_linux_common_time_daemon_count=len(active)
                    ).strip(),
                )
                self.assertEqual(
                    expected,
                    environment.compile_expression(condition)(**context),
                )


if __name__ == "__main__":
    unittest.main()
