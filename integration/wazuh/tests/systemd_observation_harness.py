"""Opt-in synthetic probe, NEVER imported by the gateway or run by discovery.

Run only after separate authorization on a disposable Linux/systemd host:
python3 -m integration.wazuh.tests.systemd_observation_harness --run-synthetic
It creates one transient UUID unit and stops only that unit. No Ansible, SSH,
Wazuh, API, approval, release, pending reservation, or application operation.
"""

import argparse
import json
import subprocess
import time
import uuid

from integration.wazuh import execution_observation as observation
from integration.wazuh import execution_state as state


def _command(binary, arguments):
    with observation._trusted_file(binary) as executable:
        result = subprocess.run([f"/proc/self/fd/{executable}", *arguments],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=observation.ENVIRONMENT,
                                cwd="/", close_fds=True, pass_fds=(executable,), timeout=4)
    if result.returncode:
        raise state.Blocked("synthetic harness command failed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-synthetic", action="store_true",
                        help="explicitly create one short-lived unprivileged synthetic unit")
    args = parser.parse_args(argv)
    if not args.run_synthetic:
        parser.error("--run-synthetic and separate host authorization are required")
    observation._require_root()
    boot = observation._boot(time.monotonic() + 2)
    request = str(uuid.uuid4())
    record = state.pending_record(request, boot, "synthetic", "observation", "0" * 64)
    unit = record["unit"]
    samples = []
    # Keep the program fixed and verify its root-owned path before asking PID 1.
    with observation._trusted_file("/usr/bin/sleep"):
        pass
    try:
        _command("/usr/bin/systemd-run", ["--system", "--quiet", "--collect", "--unit=" + unit,
                 "--property=Type=exec", "--property=DynamicUser=yes", "--property=Restart=no",
                 "--property=KillMode=control-group", "--property=RuntimeMaxSec=5s",
                 "--property=TimeoutStopSec=2s", "--property=NoNewPrivileges=yes",
                 "--property=PrivateNetwork=yes", "--property=ProtectSystem=strict",
                 "--property=ProtectHome=yes", "--property=PrivateTmp=yes",
                 "--property=CapabilityBoundingSet=", "--property=RestrictSUIDSGID=yes",
                 "--", "/usr/bin/sleep", "3"])
        for phase in ("running", "after-exit"):
            try:
                result = observation.collect(record)
                samples.append({"phase": phase, "observation": result,
                                "terminal_and_empty": state.terminal_and_empty(
                                    record, result["properties"], result["cgroup_path"],
                                    result["cgroup_events"], result["boot_id"])})
            except state.Blocked as exc:
                samples.append({"phase": phase, "blocked": str(exc)})
            if phase == "running":
                time.sleep(4)
    finally:
        # A failed/timed-out start may still have created our unique unit.
        # Already collected/not-found is expected; RuntimeMaxSec is the backstop.
        try:
            _command(observation.SYSTEMCTL, ["--system", "--no-pager", "stop", "--", unit])
        except (state.Blocked, OSError, subprocess.SubprocessError):
            samples.append({"cleanup": "stop unconfirmed; unit has RuntimeMaxSec=5s"})
        print(json.dumps({"synthetic_only": True, "unit": unit, "samples": samples}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
