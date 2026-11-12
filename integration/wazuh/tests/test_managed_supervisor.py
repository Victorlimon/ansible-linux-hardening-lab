"""Threat-matrix and authority tests for the managed supervisor boundary."""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integration.wazuh import managed_supervisor as supervisor
from integration.wazuh import execution_state as state


APPROVAL = "01234567-89ab-4cde-8123-456789abcdef"
REQUEST = "fedcba98-7654-4321-8abc-def012345678"
BOOT = "12345678-1234-4abc-8123-123456789abc"
DIGEST = "a" * 64


def approval(**changes):
    values = {"approval_id": APPROVAL, "release_digest": DIGEST,
              "request_id": REQUEST, "release_id": "lab_v10",
              "profile_digest": "d" * 64, "target_alias": "ubuntu_lab",
              "section": "cron_hourly", "issued_at": int(time.time()),
              "inventory_profile_id": "inventory_lab", "host_profile_id": "ubuntu_lab",
              "section_profile_id": "section_01", "change_id": "change_001",
              "diff_digest": "b" * 64, "issuer": "reviewer", "reason": "reviewed diff",
              "expires_at": int(time.time()) + 300}
    values.update(changes)
    return supervisor.create_approval(**values)


def reservation(**changes):
    return supervisor.Reservation(
        request_id=REQUEST, boot_id=BOOT, job_id="ubuntu_hardening", target="ubuntu_lab",
        control="section_01", release_digest=DIGEST, approval_id=APPROVAL,
        change_id="change_001", **changes)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.sync = patch.object(supervisor, "_sync_directory")
        self.sync.start()
        self.addCleanup(self.sync.stop)
        self.root_guard = patch.object(supervisor, "_private_root_directory")
        self.root_guard.start()
        self.addCleanup(self.root_guard.stop)

    def issue(self, value=None):
        value = approval() if value is None else value
        supervisor.issue(value, approval_directory=self.directory)
        return value

    def consume(self, **changes):
        value = approval()
        self.issue(value)
        return supervisor.consume(approval_id=value.approval_id, release_digest=value.release_digest,
            request_id=value.request_id, release_id=value.release_id,
            profile_digest=value.profile_digest, target_alias=value.target_alias,
            section=value.section,
            inventory_profile_id=value.inventory_profile_id, host_profile_id=value.host_profile_id,
            section_profile_id=value.section_profile_id, change_id=value.change_id,
            diff_digest=value.diff_digest, approval_directory=self.directory, **changes)

    def test_incomplete_approval_never_creates_authority(self):
        for field, value in (("release_digest", "bad"), ("reason", ""),
                             ("expires_at", int(time.time())), ("host_profile_id", "../host")):
            with self.subTest(field=field), self.assertRaises(supervisor.SupervisorRejected):
                approval(**{field: value})
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_matching_approval_is_consumed_once(self):
        self.assertEqual(self.consume().approval_id, APPROVAL)
        self.assertFalse((self.directory / (APPROVAL + ".json")).exists())
        self.assertTrue((self.directory / (APPROVAL + ".consumed")).exists())
        with self.assertRaises(supervisor.SupervisorRejected):
            self.consume()

    def test_expired_or_mismatched_identity_fails_closed(self):
        value = approval()
        self.issue(value)
        for changes in ({"now": value.expires_at}, {"host_profile_id": "other_host"},
                        {"diff_digest": "c" * 64}):
            with self.subTest(changes=changes), self.assertRaises(supervisor.SupervisorRejected):
                supplied = {"host_profile_id": "ubuntu_lab", "diff_digest": "b" * 64}
                supplied.update(changes)
                now = supplied.pop("now", None)
                supervisor.consume(approval_id=APPROVAL, release_digest=DIGEST,
                    request_id=REQUEST, release_id="lab_v10", profile_digest="d" * 64,
                    target_alias="ubuntu_lab", section="cron_hourly",
                    inventory_profile_id="inventory_lab", section_profile_id="section_01",
                    change_id="change_001", approval_directory=self.directory, **supplied,
                    **({"now": now} if now is not None else {}))

    def test_payload_input_never_becomes_an_approval_or_command(self):
        # Threat-matrix RED cases are rejected before any worker/command API exists.
        for path in ("requirements.txt", "CMakeLists.txt", "README.md", "README.mdx", "README.sh",
                     "--extra-vars=x", "$(id)", "A;id", "ANSIBLE_CONFIG=/tmp/x"):
            with self.subTest(path=path), self.assertRaises(supervisor.SupervisorRejected):
                supervisor.validate_sealed_worker_manifest({"path": path})
        self.assertEqual(supervisor.validate_sealed_worker_manifest({
            "kind": "sealed-ansible-worker", "launcher": "/usr/local/lib/ansible-wazuh/managed-worker",
            "digest": "c" * 64}), "c" * 64)
        self.assertFalse(any(hasattr(supervisor, name) for name in ("spawn", "run", "popen", "shell")))


class ReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.leases, self.pending, self.claims = root / "leases", root / "pending", root / "claims"
        for directory in (self.leases, self.pending, self.claims):
            directory.mkdir(mode=0o700)
        self.sync = patch.object(supervisor, "_sync_directory")
        self.sync.start()
        self.addCleanup(self.sync.stop)
        self.root_guard = patch.object(supervisor, "_private_root_directory")
        self.root_guard.start()
        self.addCleanup(self.root_guard.stop)

    def test_same_change_is_replay_and_different_change_is_retained(self):
        with patch.object(state, "reserve") as reserve:
            self.assertEqual(supervisor.reserve_or_replay(reservation(), pending_directory=self.pending,
                             lease_directory=self.leases), "reserved")
            self.assertEqual(supervisor.reserve_or_replay(reservation(), pending_directory=self.pending,
                             lease_directory=self.leases), "replay")
            with self.assertRaises(supervisor.SupervisorRejected):
                supervisor.reserve_or_replay(replace(reservation(), request_id=BOOT,
                    approval_id=REQUEST), pending_directory=self.pending,
                    lease_directory=self.leases)
            with self.assertRaises(supervisor.SupervisorRejected):
                supervisor.reserve_or_replay(replace(reservation(), change_id="change_002"),
                    pending_directory=self.pending, lease_directory=self.leases)
        reserve.assert_called_once()

    def test_claim_delegates_to_atomic_existing_primitive(self):
        binding = {"identity": state.pending_record(REQUEST, BOOT, "ubuntu_lab", "section_01", DIGEST,
                   job_id="ubuntu_hardening", approval_id=APPROVAL), "invocation_id": "c" * 32,
                   "runtime_max_seconds": 60, "timeout_stop_seconds": 2}
        with patch("integration.wazuh.managed_supervisor.launch_claim.claim") as claim:
            supervisor.claim_before_worker(reservation(), binding, pending_directory=self.pending,
                                           claim_directory=self.claims)
        claim.assert_called_once_with(REQUEST, binding, pending_directory=self.pending,
                                      claim_directory=self.claims)

    def test_prestart_rejects_replaced_unit_or_invocation_before_worker(self):
        identity = state.pending_record(REQUEST, BOOT, "ubuntu_lab", "section_01", DIGEST,
            job_id="ubuntu_hardening", approval_id=APPROVAL)
        binding = {"identity": identity, "invocation_id": "c" * 32,
                   "runtime_max_seconds": 60, "timeout_stop_seconds": 2}
        with patch.object(state, "read_pending", return_value=identity), \
             patch("integration.wazuh.managed_supervisor.launch_claim.read_claim", return_value=binding):
            supervisor.validate_prestart(request_id=REQUEST, invocation_id="c" * 32,
                unit=identity["unit"], show_invocation_id="c" * 32,
                pending_directory=self.pending, claim_directory=self.claims)
            for changed in ({"unit": "other.service"}, {"show_invocation_id": "d" * 32}):
                with self.subTest(changed=changed), self.assertRaises(supervisor.SupervisorRejected):
                    arguments = {"unit": identity["unit"], "show_invocation_id": "c" * 32}
                    arguments.update(changed)
                    supervisor.validate_prestart(request_id=REQUEST, invocation_id="c" * 32,
                        pending_directory=self.pending, claim_directory=self.claims, **arguments)

    def test_ambiguous_or_live_descendant_never_reconciles_to_terminal(self):
        with patch.object(state, "read_pending", return_value={"identity": "unused"}), \
             patch("integration.wazuh.managed_supervisor.launch_claim.read_claim", return_value={}):
            self.assertEqual(supervisor.reconcile(request_id=REQUEST, properties={}, cgroup_events="populated 1\n",
                             boot_id=BOOT, pending_directory=self.pending, claim_directory=self.claims), "ambiguous")


if __name__ == "__main__":
    unittest.main()
