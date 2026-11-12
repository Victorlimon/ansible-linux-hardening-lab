#!/usr/bin/python3 -B
"""Read-only selection reachability matrix for the active lab release."""

import json
from pathlib import Path
import re
import sys
import uuid

SOURCE = Path("/home/vagrant/ansible/integration/wazuh")
sys.path.insert(0, str(SOURCE))
import managed_job as gateway  # noqa: E402

policy, fingerprint = gateway.policy_and_hash()
if policy["release_id"] != "lab_v21":
    raise SystemExit("unexpected active release")
inventory = gateway.inventory_groups(policy, str(uuid.uuid4()))
for playbook, profile, host in (
    ("debian_hardening", "debian_lab", "debian12"),
    ("ubuntu_hardening", "ubuntu_lab", "ubuntu24"),
):
    for section in ("1", "2", "3", "4", "5", "6", "7", "5.1"):
        order = {
            "mode": "check",
            "request_id": str(uuid.uuid4()),
            "change_id": "LAB_PREPROD_SELECTION",
            "release_id": "lab_v21",
            "playbook_id": playbook,
            "inventory_profile_id": profile,
            "targets": [host],
            "selection": {"kind": "sections", "names": [section]},
            "extra_vars": {},
        }
        request = gateway.parse_managed_v2(json.dumps(order, sort_keys=True, separators=(",", ":")))
        selected, plan = gateway._v2_plan(policy, fingerprint, request, inventory)
        if selected != (host,):
            raise SystemExit("unexpected target expansion")
        tasks_digest = gateway._v2_selected_tasks(policy, request, host, plan, None)
        if not re.fullmatch(r"[0-9a-f]{64}", tasks_digest):
            raise SystemExit("invalid task digest")
        print(f"{host} section={section} control_tags={len(plan['tags'])} selected_tasks_digest={tasks_digest[:12]}", flush=True)
