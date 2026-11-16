"""The safety file must satisfy the gateway's _v2_safety_digest contract exactly."""

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
WAZUH = ROOT / "integration" / "wazuh"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, WAZUH / filename)
    module = importlib.util.module_from_spec(spec)
    # managed_job imports the Linux-only pwd module. Stub it only while loading so
    # the stub never leaks into other test modules (patch.dict restores sys.modules).
    stub = {"pwd": types.SimpleNamespace()} if sys.platform == "win32" else {}
    with mock.patch.dict(sys.modules, stub):
        spec.loader.exec_module(module)
    return module


safety_tool = load("prepare_safety_under_test", "prepare_safety.py")
gateway = load("managed_job_for_safety_test", "managed_job.py")

REQUEST = "1fca84c0-b7ef-4a9a-a1c2-76955ff426fd"
HOST = "ubuntu-app01"
SCOPE = "a" * 64


def check_record(**plan_changes):
    plan = {"request_id": REQUEST, "change_id": "CHG_1", "release_id": "rel_1",
            "release_digest": "b" * 64, "playbook_id": "ubuntu_hardening",
            "inventory_profile_id": "ubuntu_staging", "hosts": [HOST],
            "selection": {"kind": "full", "names": []}, "tags": ["cis_ubuntu_2404_remediation"],
            "extra_vars": {}, "scope_digest": SCOPE}
    plan.update(plan_changes)
    return {"version": 1, "host": HOST, "plan": plan, "task_digest": "c" * 64,
            "diff_digest": "d" * 64}


class SafetyCase(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.state, True)
        self.write_check(check_record())

    def write_check(self, record):
        path = safety_tool.v2_path(self.state, REQUEST, HOST, "check.json")
        path.write_text(json.dumps(record), encoding="ascii")

    def prepare(self, **changes):
        values = dict(request_id=REQUEST, host=HOST, backup_ref="SNAP_2026_11_15",
                      oob_ref="CONSOLE_OK", ttl=3600)
        values.update(changes)
        return safety_tool.prepare(self.state, values["request_id"], values["host"],
                                   values["backup_ref"], values["oob_ref"], values["ttl"])


class ContractTests(SafetyCase):
    def test_file_name_and_keys_match_the_gateway(self):
        path, safety = self.prepare()
        self.assertEqual(path.name, f"{REQUEST}.{HOST}.v2.safety.json")
        with mock.patch.object(gateway, "STATE_DIR", self.state):
            self.assertEqual(path, gateway._v2_path(REQUEST, HOST, "safety.json"))
        stored = json.loads(path.read_text())
        self.assertEqual(set(stored), {"version", "request_id", "change_id", "host", "scope_digest",
                                       "backup_ref", "oob_ref", "expires_at"})
        self.assertEqual((stored["version"], stored["scope_digest"], stored["change_id"]),
                         (1, SCOPE, "CHG_1"))
        self.assertGreater(stored["expires_at"], int(time.time()))

    def test_gateway_accepts_the_file_and_binds_it_to_exact_references(self):
        path, _ = self.prepare()
        check = check_record()
        with mock.patch.object(gateway, "STATE_DIR", self.state), \
                mock.patch.object(gateway, "trusted_file", side_effect=lambda p: Path(p).read_bytes()):
            digest = gateway._v2_safety_digest(REQUEST, HOST, check, "SNAP_2026_11_15",
                                               "CONSOLE_OK", "CHG_1")
            self.assertEqual(len(digest), 64)
            for refs in (("OTHER", "CONSOLE_OK", "CHG_1"), ("SNAP_2026_11_15", "OTHER", "CHG_1"),
                         ("SNAP_2026_11_15", "CONSOLE_OK", "CHG_2")):
                with self.subTest(refs=refs), self.assertRaises(gateway.Reject):
                    gateway._v2_safety_digest(REQUEST, HOST, check, *refs)
            moved = check_record(scope_digest="e" * 64)
            with self.assertRaises(gateway.Reject):
                gateway._v2_safety_digest(REQUEST, HOST, moved, "SNAP_2026_11_15", "CONSOLE_OK", "CHG_1")
        self.assertTrue(path.exists())

    @unittest.skipIf(sys.platform == "win32", "POSIX permission bits")
    def test_file_is_private(self):
        path, _ = self.prepare()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_expired_files_are_rejected_by_the_gateway(self):
        path, safety = self.prepare()
        safety["expires_at"] = int(time.time()) - 1
        path.write_text(json.dumps(safety))
        with mock.patch.object(gateway, "STATE_DIR", self.state), \
                mock.patch.object(gateway, "trusted_file", side_effect=lambda p: Path(p).read_bytes()), \
                self.assertRaises(gateway.Reject):
            gateway._v2_safety_digest(REQUEST, HOST, check_record(), "SNAP_2026_11_15",
                                      "CONSOLE_OK", "CHG_1")


class RefusalTests(SafetyCase):
    def test_never_replaces_an_existing_file(self):
        self.prepare()
        with self.assertRaises(safety_tool.SafetyError):
            self.prepare(backup_ref="SNAP_OTHER")

    def test_references_follow_the_gateway_identifier_grammar(self):
        for bad in ("", "has space", "9start", "a" * 64, "x" * 65, "snap;rm", "../x"):
            for field in ("backup_ref", "oob_ref"):
                with self.subTest(field=field, value=bad), self.assertRaises(safety_tool.SafetyError):
                    self.prepare(**{field: bad})

    def test_ttl_is_bounded(self):
        for ttl in (0, 59, 86401, -5):
            with self.subTest(ttl=ttl), self.assertRaises(safety_tool.SafetyError):
                self.prepare(ttl=ttl)

    def test_requires_matching_hardening_check_evidence(self):
        with self.assertRaises(safety_tool.SafetyError):
            self.prepare(host="another-host")
        self.write_check(check_record(playbook_id="ubuntu_audit"))
        with self.assertRaises(safety_tool.SafetyError):
            self.prepare()
        self.write_check(check_record(scope_digest="not-a-digest"))
        with self.assertRaises(safety_tool.SafetyError):
            self.prepare()
        safety_tool.v2_path(self.state, REQUEST, HOST, "check.json").write_text("{not json")
        with self.assertRaises(safety_tool.SafetyError):
            self.prepare()

    def test_request_id_must_be_canonical(self):
        for bad in ("nope", REQUEST.upper(), "../" + REQUEST):
            with self.subTest(bad=bad), self.assertRaises(safety_tool.SafetyError):
                self.prepare(request_id=bad)

    def test_main_reports_errors_without_traceback(self):
        argv = ["--request-id", REQUEST, "--host", HOST, "--backup-ref", "bad ref",
                "--oob-ref", "CONSOLE_OK", "--state-dir", str(self.state)]
        with mock.patch("sys.stderr"):
            self.assertEqual(safety_tool.main(argv), 2)
        argv[argv.index("bad ref")] = "SNAP_1"
        with mock.patch("sys.stdout"):
            self.assertEqual(safety_tool.main(argv), 0)
        self.assertTrue(os.path.exists(safety_tool.v2_path(self.state, REQUEST, HOST, "safety.json")))


if __name__ == "__main__":
    unittest.main()
