"""CIS 5.3.2.1 jump-alignment regressions (pam_unix enabled under faillock).

The [success=N] jump rendered for pam_unix in /etc/pam.d/common-auth is not a
benchmark constant: stock Debian 12 / Ubuntu 24.04 render N=1, but the same
benchmark's CIS 5.3.2.2 faillock profiles (applied through pam-auth-update)
add a preauth line that shifts the rendering to N=2. The control must accept
both renderings and must never rewrite the live line to a hardcoded value.
"""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTROL = (
    ROOT
    / "roles/cis_linux_common/tasks/sections/section_05_access_control"
    / "5_3_2_1_pam_unix_enabled"
)

STACK_SAMPLE_STOCK = (
    "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"
    "auth\trequisite\t\t\t\tpam_deny.so\n"
)
STACK_SAMPLE_FAILLOCK = (
    "auth\trequisite pam_faillock.so preauth\n"
    "auth\t[success=2 default=ignore]\tpam_unix.so nullok try_first_pass\n"
    "auth\t[default=die] pam_faillock.so authfail\n"
)


def read_yaml(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


class PamUnixEnabledJumpTest(unittest.TestCase):
    def _delegated_vars(self, filename):
        tasks = read_yaml(CONTROL / filename)
        delegate = next(
            task for task in tasks if "mechanisms/config_line/" in str(task)
        )
        return delegate["vars"]

    def test_audit_and_verification_accept_both_jump_renderings(self):
        for filename in ("audit.yml", "verification.yml"):
            with self.subTest(filename=filename):
                regexp = self._delegated_vars(filename)[
                    "cis_linux_common_config_line_regexp"
                ]
                for sample, expected in (
                    (STACK_SAMPLE_STOCK, True),
                    (STACK_SAMPLE_FAILLOCK, True),
                    ("auth\t[success=3 default=ignore]\tpam_unix.so nullok\n", False),
                    ("account\t[success=1 default=ignore]\tpam_unix.so\n", False),
                    ("auth\trequisite pam_deny.so\n", False),
                ):
                    matched = any(
                        re.match(regexp, line) for line in sample.splitlines()
                    )
                    self.assertIs(matched, expected, (filename, sample))

    def test_remediation_reads_stack_before_touching_config_line(self):
        tasks = read_yaml(CONTROL / "remediation.yml")
        names = [task["name"] for task in tasks]
        inspect_index = next(
            i for i, task in enumerate(tasks)
            if "pam_faillock_stack/inspect.yml" in str(task)
        )
        delegate_index = next(
            i for i, task in enumerate(tasks)
            if "mechanisms/config_line/remediation.yml" in str(task)
        )
        self.assertLess(inspect_index, delegate_index, names)

    def test_remediation_preserves_existing_line_with_stock_fallback(self):
        vars_block = self._delegated_vars("remediation.yml")
        line = vars_block["cis_linux_common_config_line"]
        self.assertIn("cis_linux_common_pam_unix_enabled_current_line", line)
        self.assertIn("auth [success=1 default=ignore] pam_unix.so nullok", line)
        self.assertIn(
            "^auth\\s+\\[success=[12] default=ignore\\]\\s+pam_unix\\.so",
            vars_block["cis_linux_common_config_line_regexp"],
        )


if __name__ == "__main__":
    unittest.main()
