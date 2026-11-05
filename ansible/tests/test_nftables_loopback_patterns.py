"""Regression tests for CIS 4.3.6 nftables loopback patterns."""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1] / "roles"
CONTROL = "tasks/sections/section_04_firewall/4_3_6_nftables_loopback_traffic"


class NftablesLoopbackPatternsTest(unittest.TestCase):
    def test_both_platforms_accept_live_and_permanent_rules(self):
        live = (
            'iif "lo" accept\n'
            'ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop\n'
            'ip6 saddr ::1 counter packets 0 bytes 0 drop\n'
        )
        permanent = (
            'iif "lo" accept\n'
            'ip saddr 127.0.0.0/8 counter drop\n'
            'ip6 saddr ::1 counter drop\n'
        )
        for role, modes in (
            ("cis_debian_12", ("audit", "remediation", "verification")),
            ("cis_ubuntu_2404", ("audit", "verification")),
        ):
            for mode in modes:
                with self.subTest(role=role, mode=mode):
                    tasks = yaml.safe_load((ROOT / role / CONTROL / f"{mode}.yml")
                                           .read_text(encoding="utf-8"))
                    patterns = tasks[0]["vars"]["cis_linux_common_nftables_expected_patterns"]
                    self.assertEqual(3, len(patterns))
                    for ruleset in (live, permanent):
                        self.assertTrue(all(re.search(pattern, ruleset) for pattern in patterns))
                    for missing in (
                        live.replace('iif "lo" accept', 'iif "lo" drop'),
                        live.replace('ip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop',
                                     'ip saddr 127.0.0.0/8 counter packets 0 bytes 0 accept'),
                        live.replace('ip6 saddr ::1 counter packets 0 bytes 0 drop',
                                     'ip6 saddr ::1 counter packets 0 bytes 0 accept'),
                    ):
                        self.assertFalse(all(re.search(pattern, missing) for pattern in patterns))


if __name__ == "__main__":
    unittest.main()
