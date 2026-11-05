"""Regression tests for nftables ruleset pattern matching."""

from pathlib import Path
import re
import unittest

from jinja2 import Environment
import yaml


MECHANISM = (Path(__file__).resolve().parents[1] / "roles/cis_linux_common/tasks/"
             "mechanisms/nftables_config")


class NftablesPatternMatchingTest(unittest.TestCase):
    def test_audit_and_verify_search_ruleset_for_each_pattern(self):
        environment = Environment()
        environment.tests["search"] = lambda value, pattern: re.search(pattern, value) is not None
        ruleset = "table inet filter {\n chain input { type filter hook input priority 0; policy drop; }\n}"
        for mode in ("audit", "verification"):
            with self.subTest(mode=mode):
                tasks = yaml.safe_load((MECHANISM / f"{mode}.yml").read_text(encoding="utf-8"))
                expression = tasks[-1]["vars"]["cis_linux_common_nftables_patterns_present"]
                for patterns, expected in ((["table inet filter", "hook input", "policy drop"], True),
                                           (["table inet filter", "hook forward"], False),
                                           ([], True)):
                    with self.subTest(patterns=patterns):
                        result = environment.from_string(expression).render(
                            cis_linux_common_nftables_expected_patterns=patterns,
                            cis_linux_common_nftables_ruleset={"stdout": ruleset},
                        )
                        self.assertEqual(expected, result.strip() == "True")


if __name__ == "__main__":
    unittest.main()
