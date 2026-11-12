"""Mocked source-only contract; no Linux runtime or launch/retirement proof."""

import subprocess
import unittest
from unittest.mock import patch

from integration.wazuh import execution_observation as transport
from integration.wazuh import execution_state as state
from integration.wazuh import retained_observation as retained


REQUEST = "01234567-89ab-4cde-8123-456789abcdef"
BOOT = "abcdef01-2345-4678-9abc-def012345678"
APPROVAL = "fedcba98-7654-4321-8abc-def012345678"


def identity():
    return {**state.pending_record(REQUEST, BOOT, "synthetic", "completion", "a" * 64),
            "job_id": "synthetic_job", "approval_id": APPROVAL}


def binding():
    return {"identity": identity(), "invocation_id": "b" * 32,
            "runtime_max_seconds": 65, "timeout_stop_seconds": 2}


def properties(**changes):
    return {**retained.FIXED, "Id": state.unit_name(REQUEST), "InvocationID": "b" * 32,
            "ActiveState": "active", "SubState": "exited", "Result": "success",
            "ExecMainExitTimestampMonotonic": "1234", "RuntimeMaxUSec": "1min 5s",
            "TimeoutStopUSec": "2s", **changes}


def encoded(props=None):
    return "".join(f"{key}={value}\n" for key, value in
                   (properties() if props is None else props).items()).encode("ascii")


class PredicateTests(unittest.TestCase):
    def test_success_and_failure_are_distinct_not_retirement(self):
        self.assertEqual(retained.classify(identity(), binding(), properties(), BOOT), "retained_success")
        for result in retained.FAILURES:
            with self.subTest(result=result):
                props = properties(ActiveState="failed", SubState="failed", Result=result)
                self.assertEqual(retained.classify(identity(), binding(), props, BOOT), "retained_failure")
        self.assertFalse(state.terminal_and_empty(
            {key: identity()[key] for key in retained.RECORD_KEYS}, properties(), "", "", BOOT))

    def test_every_identity_dimension_is_bound(self):
        for key in retained.IDENTITY_KEYS:
            changed = {**identity(), key: "different"}
            with self.subTest(key=key), self.assertRaises(state.Blocked):
                retained.classify(identity(), {**binding(), "identity": changed}, properties(), BOOT)

    def test_invalid_expected_and_launch_schema_block(self):
        bad = (None, {}, {**identity(), "version": True}, {**identity(), "approval_id": "none"},
               {**identity(), "job_id": "../../command"}, {**identity(), "extra": "x"})
        for value in bad:
            with self.subTest(value=value), self.assertRaises(state.Blocked):
                retained.classify(value, binding(), properties(), BOOT)
        bad = (None, {}, {**binding(), "extra": "x"},
               {**binding(), "identity": {**identity(), "version": True}})
        for value in bad:
            with self.subTest(value=value), self.assertRaises(state.Blocked):
                retained.classify(identity(), value, properties(), BOOT)

    def test_bounded_durations_and_nonzero_invocation(self):
        cases = (("runtime_max_seconds", 0), ("runtime_max_seconds", 3601),
                 ("timeout_stop_seconds", 61), ("timeout_stop_seconds", True),
                 ("timeout_stop_seconds", 1.5), ("invocation_id", "0" * 32),
                 ("invocation_id", "B" * 32), ("invocation_id", None))
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(state.Blocked):
                retained.classify(identity(), {**binding(), key: value}, properties(), BOOT)
        for seconds, rendered in ((1, "1s"), (60, "1min"), (65, "1min 5s"), (3600, "1h")):
            self.assertEqual(retained._timespan(seconds), rendered)

    def test_all_supervision_fields_are_required_and_exact(self):
        for key in retained.PROPERTIES:
            for props in ({k: v for k, v in properties().items() if k != key}, properties(**{key: "wrong"})):
                with self.subTest(key=key), self.assertRaises(state.Blocked):
                    retained.classify(identity(), binding(), props, BOOT)

    def test_restart_reboot_queue_missing_unit_and_wrong_terminal_states(self):
        cases = ({"InvocationID": "c" * 32}, {"NRestarts": "1"}, {"Job": "123"},
                 {"Job": "0"}, {"LoadState": "not-found"}, {"MainPID": "123"},
                 {"ControlPID": "12"}, {"ActiveState": "inactive", "SubState": "dead"},
                 {"SubState": "running"}, {"ActiveState": "failed", "SubState": "failed"},
                 {"Result": "exit-code"}, {"RuntimeMaxUSec": "infinity"},
                 {"TimeoutStopUSec": "2.0s"}, {"ExecMainExitTimestampMonotonic": "0"})
        for change in cases:
            with self.subTest(change=change), self.assertRaises(state.Blocked):
                retained.classify(identity(), binding(), properties(**change), BOOT)
        with self.assertRaises(state.Blocked):
            retained.classify(identity(), binding(), properties(), REQUEST)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("_require_root", None), ("_boot", BOOT), ("_run_show", encoded())):
            context = patch.object(transport, name, return_value=value)
            setattr(self, name, context.start())
            self.addCleanup(context.stop)

    def test_bracketed_success_never_reads_or_interprets_absent_cgroup(self):
        with patch.object(transport, "_read_kernel_file", side_effect=AssertionError("cgroup access")):
            result = retained.collect(identity(), binding())
        self.assertEqual(result["outcome"], "retained_success")
        self.assertNotIn("cgroup_events", result)
        self.assertNotIn("approved", result)
        self.assertEqual(self._boot.call_count, 2)
        self.assertEqual(self._run_show.call_count, 2)
        for call in self._run_show.call_args_list:
            self.assertEqual(call.args[0], state.unit_name(REQUEST))
            self.assertEqual(call.args[2], retained.PROPERTIES)

    def test_collect_preserves_failure_outcome(self):
        self._run_show.return_value = encoded(properties(ActiveState="failed", SubState="failed", Result="timeout"))
        self.assertEqual(retained.collect(identity(), binding())["outcome"], "retained_failure")

    def test_malformed_properties_fail_closed(self):
        cases = (b"", encoded()[:-1], encoded() + b"Job=\n", encoded() + b"Extra=x\n",
                 b"x" * 4097, b"\xff\n", b"Id\n", encoded().replace(b"Job=\n", b""),
                 encoded().replace(b"Type=exec", b"Type=ex\x00ec"))
        for data in cases:
            self._run_show.return_value = data
            with self.subTest(data=data[:30]), self.assertRaises(state.Blocked):
                retained.collect(identity(), binding())

    def test_binding_and_wrong_boot_rejected_before_show(self):
        with self.assertRaises(state.Blocked):
            retained.collect(identity(), {})
        self._boot.assert_not_called()
        self._boot.return_value = REQUEST
        with self.assertRaises(state.Blocked):
            retained.collect(identity(), binding())
        self._run_show.assert_not_called()

    def test_changed_invocation_restart_or_boot_blocks(self):
        for change in ({"InvocationID": "c" * 32}, {"NRestarts": "1"}, {"Job": "99"}):
            self._run_show.side_effect = [encoded(), encoded(properties(**change))]
            with self.subTest(change=change), self.assertRaises(state.Blocked):
                retained.collect(identity(), binding())
        self._run_show.side_effect = None
        self._boot.side_effect = [BOOT, REQUEST]
        with self.assertRaises(state.Blocked):
            retained.collect(identity(), binding())

    def test_identical_snapshots_of_recreated_unit_do_not_match_launch(self):
        # Same unit name and same terminal state (ABA), but a new invocation.
        self._run_show.return_value = encoded(properties(InvocationID="c" * 32))
        with self.assertRaises(state.Blocked):
            retained.collect(identity(), binding())

    def test_unavailable_and_timeout_do_not_return_partial_evidence(self):
        for error in (FileNotFoundError(), PermissionError(), subprocess.TimeoutExpired("systemctl", 2)):
            self._run_show.side_effect = error
            with self.subTest(error=error), self.assertRaises(state.Blocked):
                retained.collect(identity(), binding())
        self._run_show.side_effect = None
        with patch.object(retained.time, "monotonic", side_effect=[1, 7]):
            with self.assertRaises(state.Blocked):
                retained.collect(identity(), binding())


if __name__ == "__main__":
    unittest.main()
