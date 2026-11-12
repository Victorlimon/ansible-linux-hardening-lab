"""Pure tests: no system manager, filesystem mutation, or remote operations."""

from contextlib import nullcontext
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from integration.wazuh import execution_observation as observation
from integration.wazuh import execution_state as state


REQUEST = "01234567-89ab-4cde-8123-456789abcdef"
BOOT = "abcdef01-2345-4678-9abc-def012345678"


def record():
    return state.pending_record(REQUEST, BOOT, "synthetic", "observation", "a" * 64)


def properties():
    return {"Id": state.unit_name(REQUEST), "LoadState": "loaded", "Type": "exec",
            "KillMode": "control-group", "Restart": "no", "MainPID": "0",
            "ControlPID": "0", "ControlGroup": "/system.slice/" + state.unit_name(REQUEST),
            "ActiveState": "inactive", "SubState": "dead", "InvocationID": "b" * 32,
            "ExecMainExitTimestampMonotonic": "1234"}


def encoded(props=None):
    return "".join(f"{key}={value}\n" for key, value in
                   (properties() if props is None else props).items()).encode("ascii")


class CollectorTests(unittest.TestCase):
    def setUp(self):
        for name, value in (("_require_root", None), ("_boot", BOOT),
                            ("_run_show", encoded()),
                            ("_read_kernel_file", ("populated 0\nfrozen 0\n", (1, 2)))):
            context = patch.object(observation, name, return_value=value)
            setattr(self, name, context.start())
            self.addCleanup(context.stop)

    def test_complete_evidence_is_not_retirement_or_application_success(self):
        result = observation.collect(record())
        self.assertTrue(state.terminal_and_empty(record(), result["properties"],
                        result["cgroup_path"], result["cgroup_events"], result["boot_id"]))
        self.assertLessEqual(result["started_monotonic"], result["finished_monotonic"])
        self.assertNotIn("approved", result)
        self.assertEqual(self._run_show.call_count, 2)

    def test_running_observation_is_not_terminal(self):
        self._run_show.return_value = encoded({**properties(), "ActiveState": "active",
                                               "SubState": "running", "MainPID": "123"})
        result = observation.collect(record())
        self.assertFalse(state.terminal_and_empty(record(), result["properties"],
                         result["cgroup_path"], result["cgroup_events"], BOOT))

    def test_record_is_validated_before_any_io(self):
        for change in ({"unit": "sshd.service"}, {"request_id": "../../etc"}, {"version": True}):
            with self.subTest(change=change), self.assertRaises(state.Blocked):
                observation.collect({**record(), **change})
        self._run_show.assert_not_called()
        self._boot.assert_not_called()

    def test_wrong_boot_blocks_before_systemctl(self):
        self._boot.return_value = REQUEST
        with self.assertRaises(state.Blocked):
            observation.collect(record())
        self._run_show.assert_not_called()

    def test_unavailable_input_never_becomes_empty_evidence(self):
        for name in ("_boot", "_run_show", "_read_kernel_file"):
            for error in (FileNotFoundError(), PermissionError(),
                          subprocess.TimeoutExpired("systemctl", 2), OSError()):
                mock = getattr(self, name)
                mock.side_effect = error
                with self.subTest(name=name, error=type(error)), self.assertRaises(state.Blocked):
                    observation.collect(record())
                mock.side_effect = None

    def test_property_boot_event_and_inode_drift_block(self):
        changes = (("_run_show", [encoded(), encoded({**properties(), "InvocationID": "c" * 32})]),
                   ("_boot", [BOOT, REQUEST]),
                   ("_read_kernel_file", [("populated 0\n", (1, 2)), ("populated 1\n", (1, 2))]),
                   ("_read_kernel_file", [("populated 0\n", (1, 2)), ("populated 0\n", (1, 3))]))
        for name, values in changes:
            mock = getattr(self, name)
            mock.side_effect = values
            with self.subTest(name=name), self.assertRaises(state.Blocked):
                observation.collect(record())
            mock.side_effect = None

    def test_collection_deadline_blocks(self):
        with patch.object(observation.time, "monotonic", side_effect=[1, 7]):
            with self.assertRaisesRegex(state.Blocked, "timeout"):
                observation.collect(record())


class ParsingTests(unittest.TestCase):
    def test_property_shape_rejects_malformed_duplicate_extra_missing_or_huge(self):
        for data in (b"", encoded()[:-1], encoded() + b"Id=x\n", encoded() + b"Extra=x\n",
                     b"Id\n", b"\xff\n", b"x" * 4097 + b"\n",
                     encoded().replace(b"Type=exec\n", b""),
                     encoded().replace(b"ActiveState=inactive", b"ActiveState=inact\x00ive")):
            with self.subTest(data=data[:50]), self.assertRaises(state.Blocked):
                observation._parse_properties(data, record())

    def test_property_contract_identity_and_path_validation(self):
        changes = (("Id", "other.service"), ("LoadState", "not-found"),
                   ("Type", "simple"), ("KillMode", "process"), ("Restart", "always"),
                   ("ControlGroup", "/system.slice/../other"), ("ControlGroup", ""),
                   ("MainPID", "-1"), ("ControlPID", "01"), ("MainPID", "9" * 21),
                   ("InvocationID", "0" * 32), ("InvocationID", "B" * 32),
                   ("ExecMainExitTimestampMonotonic", "-1"), ("SubState", "unknown state"))
        for key, value in changes:
            with self.subTest(key=key, value=value), self.assertRaises(state.Blocked):
                observation._parse_properties(encoded({**properties(), key: value}), record())

    def test_events_reject_missing_duplicate_unknown_and_bad_values(self):
        for value in ("", "frozen 0\n", "populated 2\n", "populated 0\npopulated 0\n",
                      "populated 0 extra\n", "future 1\npopulated 0\n"):
            with self.subTest(value=value), self.assertRaises(state.Blocked):
                observation._events(value)
        observation._events("populated 1\nfrozen 0\n")


class TrustBoundaryTests(unittest.TestCase):
    def test_unsupported_platform_or_nonroot_rejected(self):
        for platform, uid, euid in (("win32", 0, 0), ("linux", 1, 0), ("linux", 0, 1)):
            with patch.object(observation.sys, "platform", platform), \
                    patch.object(observation.os, "getuid", return_value=uid, create=True), \
                    patch.object(observation.os, "geteuid", return_value=euid, create=True):
                with self.assertRaises(state.Blocked):
                    observation._require_root()

    def test_unsafe_paths_rejected_before_open(self):
        with patch.object(observation.os, "open") as opened:
            for path in ("relative", "/a/../b", "/a//b", "/a/./b"):
                with self.subTest(path=path), self.assertRaises(state.Blocked):
                    with observation._trusted_file(path):
                        pass
            opened.assert_not_called()

    def test_nonroot_writable_special_and_setid_files_rejected(self):
        for mode, uid in ((stat.S_IFREG | 0o644, 1), (stat.S_IFREG | 0o666, 0),
                          (stat.S_IFLNK | 0o777, 0), (stat.S_IFIFO | 0o600, 0),
                          (stat.S_IFREG | 0o4755, 0)):
            with patch.object(observation.os, "fstat", return_value=SimpleNamespace(st_uid=uid, st_mode=mode)):
                with self.subTest(mode=mode), self.assertRaises(state.Blocked):
                    observation._metadata(5)

    def test_descriptor_walk_checks_each_component_and_closes_on_symlink_failure(self):
        # Model Linux flags on Windows without touching a real filesystem.
        with patch.multiple(observation.os, O_NOFOLLOW=0x10000, O_CLOEXEC=0x20000,
                            O_NONBLOCK=0x40000, O_DIRECTORY=0x80000, create=True), \
                patch.object(observation.os, "open", side_effect=[10, 11, OSError("symlink")]) as opened, \
                patch.object(observation.os, "close") as closed, \
                patch.object(observation, "_metadata") as metadata:
            with self.assertRaises(OSError):
                with observation._trusted_file("/safe/link"):
                    pass
            self.assertEqual(metadata.call_count, 2)
            self.assertEqual(opened.call_args_list[1].kwargs, {"dir_fd": 10})
            self.assertEqual(opened.call_args_list[2].kwargs, {"dir_fd": 11})
            self.assertTrue(all(call.args[1] & observation.os.O_NOFOLLOW for call in opened.call_args_list))
            self.assertEqual([call.args[0] for call in closed.call_args_list], [10, 11])

    def test_wrong_kernel_filesystem_rejected(self):
        libc = Mock()
        libc.fstatfs.return_value = -1
        with patch.object(observation.ctypes, "CDLL", return_value=libc):
            with self.assertRaises(state.Blocked):
                observation._filesystem(5, 0x63677270)
        libc.fstatfs.return_value = 0  # Unset f_type is still not cgroup2.
        with patch.object(observation.ctypes, "CDLL", return_value=libc):
            with self.assertRaises(state.Blocked):
                observation._filesystem(5, 0x63677270)

    def test_kernel_read_limits_encoding_and_completion(self):
        info = SimpleNamespace(st_dev=1, st_ino=2)
        with patch.object(observation, "_trusted_file", return_value=nullcontext(5)), \
                patch.object(observation, "_filesystem"), \
                patch.object(observation.os, "fstat", return_value=info):
            for data in (b"x" * 4097, b"\xff\n", b"populated 0", b"populated\x00 0\n"):
                with patch.object(observation.os, "read", return_value=data), self.assertRaises(state.Blocked):
                    observation._read_kernel_file("/fixed", 1, float("inf"))

    def test_systemctl_is_fixed_bounded_and_sanitized(self):
        process = Mock()
        process.stdout.fileno.return_value = 10
        process.wait.return_value = 0
        process.poll.return_value = 0
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=None)
        selector.select.return_value = [(1, 1)]
        with patch.object(observation, "_trusted_file", return_value=nullcontext(5)), \
                patch.object(observation.os, "fstat", return_value=SimpleNamespace(st_mode=0o755)), \
                patch.object(observation.subprocess, "Popen", return_value=process) as popen, \
                patch.object(observation.selectors, "DefaultSelector", return_value=selector), \
                patch.object(observation.os, "read", side_effect=[encoded(), b""]):
            self.assertEqual(observation._run_show(record()["unit"], float("inf")), encoded())
        args, kwargs = popen.call_args
        self.assertEqual(args[0][-2:], ["--", record()["unit"]])
        self.assertEqual(args[0][1:4], ["--system", "--no-pager", "show"])
        self.assertIn("--all", args[0])  # Preserve explicit empty properties such as Job.
        self.assertIn("--property=" + ",".join(observation.PROPERTIES), args[0])
        self.assertEqual(kwargs["env"], observation.ENVIRONMENT)
        self.assertEqual(kwargs["pass_fds"], (5,))
        self.assertNotIn("shell", kwargs)
        self.assertLessEqual(process.wait.call_args.kwargs["timeout"], 2)

    def test_systemctl_timeout_overflow_and_error_never_return_partial_output(self):
        for scenario in ("timeout", "overflow", "nonzero"):
            process = Mock()
            process.stdout.fileno.return_value = 10
            process.wait.return_value = 1 if scenario == "nonzero" else 0
            process.poll.return_value = None
            selector = Mock()
            selector.__enter__ = Mock(return_value=selector)
            selector.__exit__ = Mock(return_value=None)
            selector.select.return_value = [] if scenario == "timeout" else [(1, 1)]
            data = [b"x" * 4097] if scenario == "overflow" else [b""]
            with self.subTest(scenario=scenario), \
                    patch.object(observation, "_trusted_file", return_value=nullcontext(5)), \
                    patch.object(observation.os, "fstat", return_value=SimpleNamespace(st_mode=0o755)), \
                    patch.object(observation.subprocess, "Popen", return_value=process), \
                    patch.object(observation.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(observation.os, "read", side_effect=data):
                with self.assertRaises(state.Blocked):
                    observation._run_show(record()["unit"], float("inf"))
            process.kill.assert_called_once()
            process.stdout.close.assert_called_once()

    def test_harness_import_has_no_process_side_effect(self):
        path = Path(__file__).with_name("systemd_observation_harness.py")
        spec = importlib.util.spec_from_file_location("observation_harness", path)
        module = importlib.util.module_from_spec(spec)
        with patch.object(subprocess, "Popen", side_effect=AssertionError("import launched a process")):
            spec.loader.exec_module(module)


if __name__ == "__main__":
    unittest.main()
