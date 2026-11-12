import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "execution_state", Path(__file__).resolve().parents[1] / "execution_state.py")
state = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(state)
REQUEST = "01234567-89ab-4cde-8123-456789abcdef"
BOOT = "abcdef01-2345-4678-9abc-def012345678"


def record():
    return state.pending_record(REQUEST, BOOT, "web01", "cron_hourly", "a" * 64)


def properties():
    return {"Id": state.unit_name(REQUEST), "LoadState": "loaded", "Type": "exec",
            "KillMode": "control-group", "Restart": "no", "MainPID": "0", "ControlPID": "0",
            "ControlGroup": "/system.slice/" + state.unit_name(REQUEST),
            "ActiveState": "inactive", "SubState": "dead", "InvocationID": "b" * 32,
            "ExecMainExitTimestampMonotonic": "1234"}


class EvidenceTests(unittest.TestCase):
    def evaluate(self, props=None, events="populated 0\nfrozen 0\n", boot=BOOT, path=None):
        props = properties() if props is None else props
        return state.terminal_and_empty(record(), props,
            properties()["ControlGroup"] if path is None else path, events, boot)

    def test_unit_identity_is_deterministic_and_validated(self):
        self.assertEqual(state.unit_name(REQUEST), "ansible-wazuh@" + REQUEST.replace("-", "") + ".service")
        for invalid in (REQUEST.upper(), "../x", "0" * 32, None, "00000000-0000-0000-0000-000000000000"):
            with self.subTest(invalid=invalid), self.assertRaises(state.Blocked):
                state.unit_name(invalid)

    def test_record_rejects_unknown_and_malformed_fields(self):
        for changes in ({"version": True}, {"unit": "other.service"}, {"extra": 1},
                        {"release_digest": "z" * 64}, {"target": "../root"}):
            with self.subTest(changes=changes), self.assertRaises(state.Blocked):
                state.validate_record({**record(), **changes})

    def test_terminal_success_or_failure_is_not_application_success(self):
        self.assertTrue(self.evaluate())
        self.assertTrue(self.evaluate({**properties(), "ActiveState": "failed", "SubState": "failed"}))

    def test_every_required_property_is_fail_closed(self):
        for key in properties():
            for value in (None, "", "unknown"):
                with self.subTest(key=key, value=value):
                    self.assertFalse(self.evaluate({**properties(), key: value}))

    def test_running_restart_wrong_unit_or_never_started_stays_blocked(self):
        for key, value in (("ActiveState", "active"), ("SubState", "auto-restart"),
                           ("Restart", "always"), ("KillMode", "process"),
                           ("LoadState", "not-found"), ("MainPID", "1"),
                           ("ControlPID", "2"), ("InvocationID", "0" * 32),
                           ("ExecMainExitTimestampMonotonic", "0")):
            with self.subTest(key=key):
                self.assertFalse(self.evaluate({**properties(), key: value}))

    def test_missing_populated_descendants_and_malformed_evidence_block(self):
        for events in (None, "", "frozen 0\n", "populated 1\n", "populated 0\npopulated 0\n",
                       "populated 0 extra\n", "populated false\n"):
            with self.subTest(events=events):
                self.assertFalse(self.evaluate(events=events))
        self.assertFalse(self.evaluate(boot=REQUEST))
        self.assertFalse(self.evaluate(path="/other"))

    def test_no_process_or_retirement_api(self):
        self.assertFalse(any(hasattr(state, name) for name in ("main", "launch", "remove", "unlink")))


@unittest.skipUnless(os.name == "posix" and getattr(os, "geteuid", lambda: -1)() == 0,
                     "requires POSIX root for real ownership/openat/fsync tests")
class MarkerFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="wazuh-state-test-", dir="/root")
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        self.marker = self.directory / (REQUEST + ".json")

    def test_durable_exclusive_round_trip(self):
        self.assertFalse(state.has_pending(self.directory))
        with patch.object(state.os, "fsync", wraps=os.fsync) as sync:
            state.reserve(record(), self.directory)
            self.assertEqual(sync.call_count, 3)
        self.assertTrue(state.has_pending(self.directory))
        self.assertEqual(state.read_pending(REQUEST, self.directory), record())
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            state.reserve(record(), self.directory)

    def test_interrupted_write_and_fsync_keep_blocker(self):
        for operation in ("write", "fsync"):
            with self.subTest(operation=operation):
                with patch.object(state.os, operation, side_effect=OSError("injected failure")):
                    with self.assertRaises(OSError):
                        state.reserve(record(), self.directory)
                self.assertTrue(state.has_pending(self.directory))
                with self.assertRaises(state.Blocked):
                    state.read_pending(REQUEST, self.directory)
                self.marker.unlink()  # Test fixture cleanup, never production recovery.

    def test_partial_writes_are_completed(self):
        original_write = os.write
        with patch.object(state.os, "write", side_effect=lambda fd, data: original_write(fd, data[:7])):
            state.reserve(record(), self.directory)
        self.assertEqual(state.read_pending(REQUEST, self.directory), record())

    def test_unknown_entries_and_bad_permissions_remain_blocked(self):
        (self.directory / "unknown").touch()
        self.assertTrue(state.has_pending(self.directory))
        state.reserve(record(), self.directory)
        for mode in (0o644, 0o660):
            self.marker.chmod(mode)
            with self.assertRaises(state.Blocked):
                state.read_pending(REQUEST, self.directory)
        self.directory.chmod(0o755)
        with self.assertRaises(state.Blocked):
            state.has_pending(self.directory)

    def test_symlinks_hardlinks_fifo_and_writable_ancestor_rejected(self):
        self.marker.symlink_to("/etc/passwd")
        with self.assertRaises(OSError):
            state.read_pending(REQUEST, self.directory)
        self.marker.unlink()
        state.reserve(record(), self.directory)
        os.link(self.marker, self.directory / "second-link")
        with self.assertRaises(state.Blocked):
            state.read_pending(REQUEST, self.directory)
        self.marker.unlink()
        os.mkfifo(self.marker, 0o600)
        with self.assertRaises(state.Blocked):
            state.read_pending(REQUEST, self.directory)
        nested = self.directory / "nested"
        nested.mkdir(mode=0o700)
        self.directory.chmod(0o777)
        with self.assertRaises(state.Blocked):
            state.has_pending(nested)

    def test_duplicate_json_and_nonroot_marker_are_rejected(self):
        state.reserve(record(), self.directory)
        self.marker.write_text('{"version":1,"version":1}\n')
        with self.assertRaises(state.Blocked):
            state.read_pending(REQUEST, self.directory)
        os.chown(self.marker, 65534, -1)
        with self.assertRaises(state.Blocked):
            state.read_pending(REQUEST, self.directory)


if __name__ == "__main__":
    unittest.main()
