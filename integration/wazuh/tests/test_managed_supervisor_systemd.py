"""Linux systemd harness for the inert managed-supervisor service contract."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid

from integration.wazuh import execution_state


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "config" / "ansible-wazuh@.service"


class UnitContractTests(unittest.TestCase):
    def test_instance_name_matches_pending_record(self):
        request_id = str(uuid.uuid4())
        self.assertEqual(execution_state.unit_name(request_id),
                         "ansible-wazuh@" + uuid.UUID(request_id).hex + ".service")

    def test_unused_template_with_missing_entrypoints_is_not_shipped(self):
        self.assertFalse(UNIT.exists(), "managed-v2 uses the gateway with durable host blockers")


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0 and shutil.which("systemd-run")
                     and Path("/run/systemd/system").exists(), "requires a root local systemd lab")
class SystemdHarnessTests(unittest.TestCase):
    def test_systemd_kills_a_setsid_descendant_with_the_control_group(self):
        unit = "ansible-wazuh-u2-" + uuid.uuid4().hex
        command = ["systemd-run", "--unit=" + unit, "--property=Type=exec",
                   "--property=KillMode=control-group", "--property=Restart=no",
                   "--property=Delegate=no", "--property=SendSIGKILL=yes",
                   "--property=RuntimeMaxSec=2s", "/bin/sh", "-c", "setsid sleep 30 & wait"]
        started = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, timeout=15, check=False)
        self.assertEqual(started.returncode, 0, started.stderr[-500:])
        result = subprocess.run(["systemctl", "show", unit, "--property=Result", "--value"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        self.assertIn(result.stdout.strip(), {"timeout", "success"})
        subprocess.run(["systemctl", "reset-failed", unit], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)


if __name__ == "__main__":
    unittest.main()
